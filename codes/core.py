# Rahgozar
import socket
import threading
import select
import time
import sqlite3
import logging
from requests import get

ip = get('https://api.ipify.org').text
DB_NAME = "forwarder.db"
POLL_INTERVAL = 2
IDLE_TIMEOUT = 3600
SAVE_INTERVAL = 5

logging.basicConfig(level=logging.INFO, format='[RahGozar CORE] %(asctime)s - %(message)s')

class ForwarderCore:
    def __init__(self):
        self.listeners = {}
        self.rule_signatures = {}
        self.active_conns = {}
        self.conn_lock = threading.Lock()
        self.running = True
        
        self.stats_cache = {}
        self.stats_lock = threading.Lock()
        
        self.saver_thread = threading.Thread(target=self.background_saver)
        self.saver_thread.daemon = True
        self.saver_thread.start()

    def get_db_rules(self):
        try:
            with sqlite3.connect(DB_NAME) as conn:
                conn.row_factory = sqlite3.Row
                cur = conn.execute("SELECT id, username, listen_port, target_ip, target_port, limit_bytes, bytes_used, active, expiry_date FROM rules")
                return {row['id']: dict(row) for row in cur.fetchall()}
        except Exception as e:
            logging.error(f"DB Read Error: {e}")
            return {}

    def background_saver(self):
        while self.running:
            time.sleep(SAVE_INTERVAL)
            to_update = {}
            with self.stats_lock:
                if self.stats_cache:
                    to_update = self.stats_cache.copy()
                    self.stats_cache.clear()
            
            if to_update:
                try:
                    with sqlite3.connect(DB_NAME) as conn:
                        for r_id, bytes_val in to_update.items():
                            conn.execute("UPDATE rules SET bytes_used = bytes_used + ? WHERE id = ?", (bytes_val, r_id))
                        conn.commit()
                except Exception as e:
                    logging.error(f"DB Save Error: {e}")

    def cache_usage(self, rule_id, bytes_count):
        with self.stats_lock:
            self.stats_cache[rule_id] = self.stats_cache.get(rule_id, 0) + bytes_count

    def register_conn(self, rule_id, s1, s2):
        with self.conn_lock:
            if rule_id not in self.active_conns:
                self.active_conns[rule_id] = []
            self.active_conns[rule_id].append((s1, s2))

    def unregister_conn(self, rule_id, s1, s2):
        with self.conn_lock:
            if rule_id in self.active_conns:
                try:
                    self.active_conns[rule_id].remove((s1, s2))
                except ValueError:
                    pass 

    def kill_all_connections(self, rule_id):
        with self.conn_lock:
            if rule_id in self.active_conns:
                count = len(self.active_conns[rule_id])
                for s1, s2 in self.active_conns[rule_id]:
                    try: s1.close()
                    except: pass
                    try: s2.close()
                    except: pass
                self.active_conns[rule_id] = [] 
                logging.info(f"Killed {count} connections for Rule {rule_id}")
    def configure_socket(self, s):
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except: pass

    def bridge(self, client, rule):
        r_id = rule['id']
        target = None
        try:
            self.configure_socket(client)
            target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.configure_socket(target)
            target.settimeout(10)
            target.connect((rule['target_ip'], rule['target_port']))
        except Exception:
            if client: client.close()
            if target: target.close()
            return

        self.register_conn(r_id, client, target)

        sockets = [client, target]
        last_activity = time.time()
        
        try:
            while self.running:
                readable, _, _ = select.select(sockets, [], [], 1.0)
                if readable:
                    for s in readable:
                        data = s.recv(131072)
                        if not data:
                            raise Exception("Closed")
                        
                        last_activity = time.time()
                        self.cache_usage(r_id, len(data))

                        if s is client: target.sendall(data)
                        else: client.sendall(data)
                else:
                    if r_id not in self.listeners: 
                        raise Exception("Rule Deleted")
                    if time.time() - last_activity > IDLE_TIMEOUT:
                        raise Exception("Timeout")
        except Exception:
            pass
        finally:
            try: client.close()
            except: pass
            try: target.close()
            except: pass
            self.unregister_conn(r_id, client, target)

    def start_listener(self, rule):
        r_id = rule['id']
        srv = None
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(('0.0.0.0', rule['listen_port']))
            srv.listen(100)
            
            self.listeners[r_id] = srv
            self.rule_signatures[r_id] = (rule['listen_port'], rule['target_ip'], rule['target_port'])
            
            logging.info(f"Started {ip}:{rule['listen_port']} -> {rule['target_ip']}:{rule['target_port']}")

            while self.running and r_id in self.listeners:
                try:
                    srv.settimeout(1.0)
                    try:
                        client, _ = srv.accept()
                    except socket.timeout:
                        continue
                    except Exception:
                        break

                    t = threading.Thread(target=self.bridge, args=(client, rule))
                    t.daemon = True
                    t.start()
                except Exception:
                    break
        except Exception as e:
            logging.error(f"Bind error {rule['listen_port']}: {e}")
        finally:
            if srv: 
                try: srv.close()
                except: pass
            if r_id in self.listeners and self.listeners[r_id] == srv:
                self.listeners.pop(r_id, None)
            self.rule_signatures.pop(r_id, None)

    def loop(self):
        logging.info(f"RahGozar Core Started.")
        while self.running:
            rules = self.get_db_rules()
            
            for r_id, r in rules.items():
                expiry = r['expiry_date'] if r['expiry_date'] is not None else 0
                is_expired = (expiry > 0 and time.time() > expiry)
                is_valid = (r['active'] and r['bytes_used'] < r['limit_bytes'] and not is_expired)

                if is_valid:
                    current_sig = (r['listen_port'], r['target_ip'], r['target_port'])
                    
                    if r_id in self.listeners:
                        if self.rule_signatures.get(r_id) != current_sig:
                            logging.info(f"Config changed for Rule {r_id}. Restarting...")
                            self.stop_rule(r_id)
                            
                    if r_id not in self.listeners:
                        t = threading.Thread(target=self.start_listener, args=(r,))
                        t.daemon = True
                        t.start()
            
            active_ids = list(self.listeners.keys())
            for r_id in active_ids:
                r = rules.get(r_id)
                should_stop = False
                
                if not r: should_stop = True
                else:
                    expiry = r['expiry_date'] if r['expiry_date'] is not None else 0
                    if not r['active']: should_stop = True
                    elif r['bytes_used'] >= r['limit_bytes']: should_stop = True
                    elif expiry > 0 and time.time() > expiry: should_stop = True

                if should_stop:
                    self.stop_rule(r_id)
                    logging.info(f"Stopped Rule {r_id}")

            time.sleep(POLL_INTERVAL)

    def stop_rule(self, r_id):
        sock = self.listeners.pop(r_id, None)
        self.rule_signatures.pop(r_id, None)
        if sock:
            try: sock.close()
            except: pass
        self.kill_all_connections(r_id)

if __name__ == "__main__":
    core = ForwarderCore()
    try:
        core.loop()
    except KeyboardInterrupt:
        core.running = False
        print("Stopping...")
