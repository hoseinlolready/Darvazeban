#!/usr/bin/env python3

import sqlite3
import json
import hashlib
import secrets
import sys
import time
import os
import subprocess

the_path = "/opt/Rahgozar/"
DB_NAME = os.path.join(the_path, "forwarder.db")


def runner():
    Panel_runner = subprocess.Popen(["python3", f"{the_path}panel.py"])
    Core_runner = subprocess.Popen(["python3", f"{the_path}core.py"])
    try:
        Panel_runner.wait()
        Core_runner.wait()
    except:
        Panel_runner.kill()
        Core_runner.kill()


def init_db():
    with get_db() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT, salt TEXT)""")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                listen_port INTEGER UNIQUE,
                target_ip TEXT,
                target_port INTEGER,
                limit_bytes INTEGER,
                bytes_used INTEGER DEFAULT 0,
                expiry_date INTEGER,
                note TEXT,
                active BOOLEAN DEFAULT 1,
                created_at INTEGER
            )
        """)
        conn.execute("""CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT, created_at INTEGER)""")

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    salt = secrets.token_hex(8)
    hash_obj = hashlib.sha256((password + salt).encode())
    return hash_obj.hexdigest(), salt

def verify_password(stored_hash, salt, provided_password):
    hash_obj = hashlib.sha256((provided_password + salt).encode())
    return hash_obj.hexdigest() == stored_hash

def cli_manager():
    if len(sys.argv) < 2: return
    cmd = sys.argv[1]
    
    if cmd == "add" and len(sys.argv) == 4:
        user, pwd = sys.argv[2], sys.argv[3]
        ph, salt = hash_password(pwd)
        try:
            with get_db() as conn:
                conn.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)", (user, ph, salt))
            print(f"User '{user}' added.")
        except: print("User exists.")
        sys.exit(0)
        
    if cmd == "del" and len(sys.argv) == 3:
        user = sys.argv[2]
        with get_db() as conn:
            conn.execute("DELETE FROM users WHERE username = ?", (user,))
        print(f"User '{user}' deleted (if existed).")
        sys.exit(0)

    if cmd == "run" and len(sys.argv) == 2:
        runner()


def cli_manager():
    while True:
        print("=== Rahgozar Manager ===")
        print("1) Add User")
        print("2) Delete User")
        print("3) Run Panel + Core")
        print("4) Exit")
        
        choice = input("Select option: ").strip()

        if choice == "1":
            user = input("Enter username: ").strip()
            pwd = input("Enter password: ").strip()
            ph, salt = hash_password(pwd)

            try:
                with get_db() as conn:
                    conn.execute("INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
                                 (user, ph, salt))
                print(f"[OK] User '{user}' added.")
            except:
                print("[ERR] This user already exists.")

        elif choice == "2":
            user = input("Enter username to delete: ").strip()
            with get_db() as conn:
                conn.execute("DELETE FROM users WHERE username = ?", (user,))
            print(f"[OK] User '{user}' deleted (if existed).")

        elif choice == "3":
            print("Starting Panel + Core...")
            runner()
            print("Stopped.")

        elif choice == "4":
            print("Goodbye!")
            sys.exit(0)

        else:
            print("Invalid option.")





if __name__ == "__main__":
    init_db()
    cli_manager() 
