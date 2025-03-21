import sqlite3
from cryptography.fernet import Fernet
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get encryption key
key = os.getenv('ENCRYPTION_KEY')
cipher_suite = Fernet(key)

def read_logs():
    # Connect to the database
    conn = sqlite3.connect('firewall_logs.db')
    cursor = conn.cursor()
    
    try:
        # Get all logs
        cursor.execute("SELECT * FROM logs")
        rows = cursor.fetchall()
        
        if not rows:
            print("No logs found in the database.")
            return
            
        for row in rows:
            try:
                # Decrypt the message
                decrypted_message = cipher_suite.decrypt(row[8]).decode()  # message is the 9th column
                
                # Format based on message type
                if "ALERT" in decrypted_message or "attack" in decrypted_message.lower():
                    print(f"\n!!! ATTACK DETECTED !!!")
                    print(f"Time: {row[1]}")
                    print(f"Source IP: {row[2]}")
                    print(f"Protocol: {row[6]}")
                    print(f"Details: {decrypted_message}")
                    print("!" * 50)
                else:
                    # Print regular log entry
                    print(f"{row[1]} | {row[2]} | {row[6]} | {decrypted_message}")
            except Exception as e:
                print(f"Error decrypting log entry: {e}")
                continue
            
    except Exception as e:
        print(f"Error reading logs: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    read_logs() 