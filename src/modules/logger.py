import sqlite3
import time
from cryptography.fernet import Fernet
import os
from typing import Any, Tuple

class Logger:
    def __init__(self, db_path: str, encryption_key: bytes):
        """Initialize the logger with database connection and encryption"""
        self.db_path = db_path
        self.cipher_suite = Fernet(encryption_key)
        self.setup_database()

    def setup_database(self):
        """Set up the database and create necessary tables"""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                src_ip TEXT,
                src_mac TEXT,
                dst_ip TEXT,
                dst_mac TEXT,
                protocol TEXT,
                packet_size INTEGER,
                message TEXT
            )
        ''')
        self.conn.commit()

    def log_event(self, message: str, src_ip: str, src_mac: str, 
                 dst_ip: str, dst_mac: str, protocol: str, packet_size: int):
        """Log an event with encryption"""
        encrypted_message = self.cipher_suite.encrypt(message.encode())
        self.cursor.execute('''
            INSERT INTO logs (timestamp, src_ip, src_mac, dst_ip, dst_mac, 
                            protocol, packet_size, message)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
              src_ip, src_mac, dst_ip, dst_mac, protocol, 
              packet_size, encrypted_message))
        self.conn.commit()

    def read_logs(self) -> list[Tuple[Any, ...]]:
        """Read and decrypt logs from the database"""
        self.cursor.execute("SELECT * FROM logs")
        rows = self.cursor.fetchall()
        decrypted_rows = []
        for row in rows:
            decrypted_message = self.cipher_suite.decrypt(row[-1]).decode()
            decrypted_rows.append(row[:-1] + (decrypted_message,))
        return decrypted_rows

    def __del__(self):
        """Cleanup database connection"""
        if hasattr(self, 'conn'):
            self.conn.close() 