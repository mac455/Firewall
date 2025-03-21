# Secure Network Firewall

A Python-based network firewall built for monitoring and protecting networks from various cyber threats using signature detection, rate limiting, protocol filtering, and IP management.

## Features

- **Signature-Based Attack Detection**: Detects various attack patterns including SQL injection, XSS, Log4j exploits, and others.
- **Rate Limiting**: Prevents DoS attacks by limiting traffic from individual IP addresses.
- **Protocol Filtering**: Blocks unwanted protocols (e.g., UDP).
- **IP Whitelisting and Blacklisting**: Manages trusted and blocked IP addresses.
- **Nimda Worm Detection**: Specifically detects and blocks the Nimda worm attack pattern.
- **Secure Logging**: All logs are encrypted and stored in a SQLite database.
- **Attack Simulation**: Includes tools to simulate various attacks for testing.

## Architecture

The firewall consists of several modules:

- **PacketAnalyzer**: Examines packet contents for malicious patterns and signatures.
- **IPManager**: Handles IP address whitelisting, blacklisting, and blocking.
- **RateLimiter**: Monitors and limits traffic rates from specific sources.
- **Logger**: Securely stores encrypted logs of all detected events.

## Requirements

- Python 3.6+
- scapy
- cryptography
- python-dotenv
- sqlite3 (included in Python standard library)




### Encrypted Logging
All log messages are encrypted using Fernet symmetric encryption before being stored in the database, ensuring that sensitive information about network traffic and detected attacks remains secure.

### Signature Detection
The firewall maintains a comprehensive database of attack signatures for various threat types, including:
- SQL injection patterns
- XSS attack vectors
- Log4j exploitation attempts
- Directory traversal attacks
- Remote code execution patterns
- Malware communication signatures
