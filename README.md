# Secure Relay-Based Chat System

**Course:** CS 6349 – Network Security (FALL 2025)  
**Project Members:**
- Spoorti Katti 
- Shreya Basavaraj Devagiri

---

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Security Properties](#security-properties)
- [Installation](#installation)
- [Usage](#usage)
- [Protocol Demonstration](#protocol-demonstration)
- [Testing Security Features](#testing-security-features)
- [Technology Stack](#technology-stack)
- [File Structure](#file-structure)

---

## Overview

This project implements a **secure relay-based chat system** that enables end-to-end encrypted communication between clients through an untrusted relay server. The system provides complete confidentiality, integrity protection, authentication, replay resistance, and forward secrecy using a combination of RSA signatures, Diffie-Hellman key exchange, and HMAC-based symmetric encryption.

### Key Highlights
- **End-to-End Encryption**: Messages encrypted using session keys derived from ephemeral Diffie-Hellman exchange
- **Untrusted Relay**: Relay server cannot decrypt message contents
- **Forward Secrecy**: Compromise of long-term keys doesn't expose past session keys
- **Replay Protection**: Timestamps, nonces, and sequence numbers prevent replay attacks
- **Message Integrity**: Multi-layer HMAC protection detects any tampering

---

## Features

### Core Security Features
1. **Mutual Authentication**
   - Client-to-Relay authentication using RSA digital signatures
   - Client-to-Client authentication via signed DH public values
   - Relay-to-Client authentication on forwarded messages

2. **End-to-End Confidentiality**
   - Inner encryption layer using session keys from DH exchange
   - Relay cannot decrypt message contents
   - Keyed-Hash stream cipher based on HMAC-SHA256

3. **Message Integrity**
   - Inner MAC protects message content (end-to-end)
   - Outer MAC ensures relay receives authentic messages
   - Any tampering detected through MAC verification

4. **Replay Protection**
   - Timestamp freshness checks (5-minute window)
   - Cryptographically secure nonces
   - Strictly increasing sequence numbers per session
   - Session binding via unique session IDs

5. **Forward Secrecy**
   - Ephemeral Diffie-Hellman key pairs per session
   - DH private keys deleted after key derivation
   - Independent session keys for each conversation

### Additional Features
- **Session Management**: Multiple concurrent secure sessions
- **Message History**: In-memory storage for testing replay attacks
- **Attack Simulation**: Built-in commands to test security mechanisms
- **Client Discovery**: List all connected clients on relay

---

## System Architecture

### Components

#### 1. Clients (Alice, Bob, etc.)
- Maintain long-term RSA key pairs for authentication
- Generate ephemeral DH key pairs for each session
- Perform end-to-end message encryption/decryption
- Verify all signatures and MACs

#### 2. Relay Server
- Registers clients and stores public keys
- Routes encrypted messages between clients
- Verifies message authenticity before forwarding
- **Cannot decrypt message contents**
- Provides central message forwarding service

### Trust Model

**Trusted:**
- Client-to-client authentication (via signed public keys)
- Relay's message routing functionality

**Untrusted:**
- Relay cannot be trusted to read message contents
- Network channels subject to eavesdropping, replay, tampering

**Pre-shared Information:**
- Relay knows all clients' RSA public keys
- Clients know relay's RSA public key
- Clients can verify other clients' public keys

---

## Security Properties

### 1. Authentication
- **Client-to-Relay**: Digital signatures using RSA private keys
- **Client-to-Client**: DH values signed with long-term keys
- **Relay-to-Client**: Relay signs all forwarded messages

### 2. Confidentiality
- **End-to-End Encryption**: Inner layer uses DH-derived session keys
- **Semantic Security**: Random IVs prevent ciphertext patterns
- **Key Separation**: Different keys for each session and direction

### 3. Integrity
- **Multi-Layer Protection**: Inner and outer MAC layers
- **Binding**: MACs include session_id, sequence numbers, timestamps
- **Tamper Detection**: Any modification causes MAC verification failure

### 4. Replay Protection
- **Timestamps**: Messages outside 5-minute window rejected
- **Nonces**: Fresh random values in session establishment
- **Sequence Numbers**: Strictly increasing, duplicates rejected
- **Session IDs**: Bind messages to specific sessions

### 5. Forward Secrecy
- **Ephemeral Keys**: Fresh DH key pairs per session
- **Key Deletion**: DH private values deleted after use
- **Independence**: Each session key cryptographically independent

---

## Installation

### Prerequisites
- Python 3.9 or higher
- `cryptography` library

### Setup

1. **Clone or download the project files:**
```bash
# Ensure you have these files:
# - secure_relay_server.py
# - secure_client.py
```

2. **Install dependencies:**
```bash
pip install cryptography
```

3. **Verify installation:**
```bash
python3 --version
python3 -c "import cryptography; print('cryptography installed')"
```

---

## Usage

### Step 1: Start the Relay Server

Open a terminal and run:
```bash
python3 secure_relay_server.py
```

**Expected Output:**
```
======================================================================
SECURE RELAY-BASED CHAT SYSTEM
Secure Relay Server - Full Protocol Implementation
======================================================================

[RELAY_SERVER] Secure Relay Server Initialized
[RELAY_SERVER] Listening on 0.0.0.0:5050
[RELAY_SERVER] Replay protection window: 0:05:00
[RELAY_SERVER] Generating RSA key pair...
[RELAY_SERVER] RSA keys generated
[RELAY_SERVER]  Server started successfully!
[RELAY_SERVER] Waiting for client connections...
```

### Step 2: Start Client Alice

Open a new terminal:
```bash
python3 secure_client.py alice
```

**Expected Output:**
```
======================================================================
 SECURE RELAY-BASED CHAT SYSTEM
======================================================================

[alice] Secure Client initialized
[alice] Target relay: localhost:5050
[alice] Generating RSA key pair...
[alice] RSA keys generated
[alice]  Connected to relay server
[alice]  Registration successful!
[alice] Mutual authentication complete

======================================================================
 SECURE CHAT CLIENT: alice
======================================================================
Commands:
  session <peer_id>              - Establish secure session
  send <peer_id> <message>       - Send encrypted message
  history [peer_id]              - View message history
  replay <peer_id> <index>       - Replay message (Test Replay Attack)
  tamper <peer_id> <index>       - Tamper with ciphertext
  corrupt <peer_id> <index>      - Corrupt MAC
  sessions                       - List active sessions
  lists                          - List all clients
  quit                           - Exit
======================================================================

alice>
```

### Step 3: Start Client Bob

Open another terminal:
```bash
python3 secure_client.py bob
```

You should see similar output with successful registration.

### Step 4: Establish Secure Session

In **Alice's terminal**:
```bash
alice> session bob
```

**Expected Output:**
```
[alice]  Initiating secure session with 'bob'...
[alice]  Deriving session keys...
[alice]  Session keys derived
[alice]   - Forward secrecy enabled
[alice]  Session with 'bob' ESTABLISHED
[alice]  Ready for secure communication
[alice] You can now send messages to 'bob'
```

In **Bob's terminal**, you'll automatically see:
```
[bob]  Session request from 'alice'
[bob]  Peer signature validated by relay
[bob]  Sending session response...
[bob]  Session keys derived
[bob]   - Forward secrecy enabled
[bob]  Session with 'alice' ESTABLISHED
[bob] You can now send messages to 'alice'
```

### Step 5: Send Encrypted Messages

In **Alice's terminal**:
```bash
alice> send bob Hello Bob! This is a secure message.
```

**Expected Output (Alice):**
```
[alice]  Encrypting message for 'bob'...
[alice]   - Sequence: 0
[alice]   - Plaintext: 'Hello Bob! This is a secure message.'
[alice]  Encryption details:
[alice]   - Replay protection: timestamp + sequence
[alice]   - Message saved to history
```

**Expected Output (Bob):**
```
[bob]  Encrypted message received from 'alice'
[bob]   - Sequence: 0
[bob]  MAC verified - message integrity confirmed

======================================================================
 DECRYPTED MESSAGE
======================================================================
From:       alice
Sequence:   0
Message:    Hello Bob! This is a secure message.
Security:    Encrypted  Authenticated  Replay-Protected
======================================================================
```

---

## Protocol Demonstration

### 1. Successful Client-Relay Connection

When a client connects to the relay, you'll see:

**Relay Terminal:**
```
[RELAY_SERVER] New connection from ('127.0.0.1', 54321)
```

**Client Terminal:**
```
[alice]  Connected to relay server
[alice]   Address: localhost:5050
```

### 2. Registration and Authentication

**Client sends registration:**
```
[alice]  Sending secure registration request...
[alice]   Registration details:
[alice]   - Timestamp: 2024-12-08T10:30:45.123456
```

**Relay processes and authenticates:**
```
[RELAY_SERVER]  Received: REGISTER
[RELAY_SERVER] Processing registration from 'alice'
[RELAY_SERVER] Signature verified
[RELAY_SERVER] Client 'alice' registered successfully
[RELAY_SERVER] Mutual authentication complete
[RELAY_SERVER] Total clients: 1
```

**Client receives confirmation:**
```
[alice]  Registration response received
[alice]  Registration successful!
[alice]  Nonce echo verified
[alice]  Mutual authentication complete
```

### 3. Session Key Establishment

**Alice initiates session:**
```
[alice]  Initiating secure session with 'bob'...
```

**Relay forwards session request:**
```
[RELAY_SERVER]  Session Init: 'alice' → 'bob'
[RELAY_SERVER] Sender signature verified
[RELAY_SERVER] Session request forwarded to 'bob'
```

**Bob responds:**
```
[bob]  Session request from 'alice'
[bob]  Peer signature validated by relay
[bob]  Sending session response...
[bob]  Deriving session keys...
[bob]  Session with 'alice' ESTABLISHED
```

**Alice completes handshake:**
```
[alice]  Session established with 'bob'
[alice]  Nonce echo verified
[alice]  Deriving session keys...
[alice]  Session with 'bob' ESTABLISHED
```

### 4. Encrypted Message Exchange

**Alice sends encrypted message:**
```
[alice]  Encrypting message for 'bob'...
[alice]   - Sequence: 0
[alice]   - Plaintext: 'Hello Bob!'
[alice]  Encryption details:
[alice]   - Replay protection: timestamp + sequence
```

**Relay forwards (cannot decrypt):**
```
[RELAY_SERVER]  Encrypted Data: 'alice' → 'bob'
[RELAY_SERVER] Session ID: 3a7f2b1c...
[RELAY_SERVER] Sequence: 0
[RELAY_SERVER] Timestamp verified (fresh)
[RELAY_SERVER] Forwarding encrypted payload (cannot decrypt)
[RELAY_SERVER] End-to-end confidentiality maintained
```

**Bob receives and decrypts:**
```
[bob]  Encrypted message received from 'alice'
[bob]   - Sequence: 0
[bob]  Decrypting message...
[bob]  MAC verified - message integrity confirmed

======================================================================
 DECRYPTED MESSAGE
======================================================================
From:       alice
Sequence:   0
Message:    Hello Bob!
Security:    Encrypted  Authenticated  Replay-Protected
======================================================================
```

---

## Testing Security Features

### 1. Replay Protection Testing

**Send a legitimate message first:**
```bash
alice> send bob Test message for replay
```

**View message history:**
```bash
alice> history bob
```

**Output:**
```
[alice] Message History with 'bob':
======================================================================
[0] Seq: 0 | Test message for replay
======================================================================
Usage: replay bob <index>
```

**Attempt replay attack:**
```bash
alice> replay bob 0
```

**Expected Output (Alice):**
```
[alice]  SIMULATING REPLAY ATTACK
[alice]  Replaying from message history
[alice]   - Target: bob
[alice]   - Message Index: 0
[alice]   - Original Sequence: 0
[alice]   - Original Text: 'Test message for replay'
[alice]   - Sending SAME encrypted message twice...
[alice]  Replayed message sent to relay
```

**Expected Output (Bob - ATTACK DETECTED):**
```
[bob]  Encrypted message received from 'alice'
[bob]   - Received seq: 0
[bob]   - Expected > 0

[bob]  REPLAY ATTACK DETECTED!
[bob]   - Received seq: 0
[bob]   - Expected > 0
[bob]   - Message REJECTED
```

### 2. Integrity Protection Testing (Ciphertext Tampering)

**Tamper with message ciphertext:**
```bash
alice> tamper bob 0
```

**Expected Output (Alice):**
```
[alice]  SIMULATING TAMPERING ATTACK
[alice]  Tampering with message
[alice]   - Attack: Modifying ciphertext to change plaintext...
[alice]  Ciphertext tampered (bit-flip attack)
[alice]   - MAC unchanged (attacker doesn't know key!)
[alice]  Sending tampered message...
```

**Expected Output (Bob - INTEGRITY VIOLATION):**
```
[bob]  Encrypted message received from 'alice'
[bob]  Decrypting message...

[bob]  INTEGRITY VIOLATION!
[bob]   - MAC verification failed
[bob]   - Message REJECTED (possible tampering)
```

### 3. MAC Corruption Testing

**Corrupt the message MAC:**
```bash
alice> corrupt bob 0
```

**Expected Output (Alice):**
```
[alice]  SIMULATING MAC TAMPERING
[alice]  Corrupting message authentication code
[alice]   - Attack: Flipping bits in MAC...
[alice]  MAC corrupted
[alice]   - Ciphertext: unchanged
[alice]   - MAC: corrupted (invalid authentication)
```

**Expected Output (Bob - INTEGRITY VIOLATION):**
```
[bob]  Encrypted message received from 'alice'

[bob]  INTEGRITY VIOLATION!
[bob]   - MAC verification failed
[bob]   - Message REJECTED (possible tampering)
```

### 4. List Active Sessions

```bash
alice> sessions
```

**Output:**
```
[alice] Active Sessions:
  - bob: ESTABLISHED (seq: 3)
```

### 5. List Connected Clients

```bash
alice> lists
```

**Output:**
```
[alice] Requesting client list from relay...

======================================================================
CLIENTS CONNECTED TO RELAY SERVER
======================================================================
Total clients: 2

  1. alice (SELF)
  2. bob (ONLINE)
======================================================================
```

---

## Technology Stack

### Language
- **Python 3.9+**

### Libraries
- **socket**: Network communication (TCP)
- **cryptography**: RSA operations, HMAC, SHA-256, key serialization
- **secrets**: Cryptographically secure random number generation
- **json**: Message serialization and parsing
- **threading**: Concurrent client connection handling
- **datetime**: Timestamp management for replay protection

### Cryptographic Primitives
- **RSA-2048**: Long-term authentication keys
- **Diffie-Hellman**: Ephemeral key exchange (2048-bit safe prime)
- **HMAC-SHA256**: Message authentication and key derivation
- **Keyed-Hash Stream Cipher**: HMAC-based encryption

---

## File Structure

```
secure-chat-system/
│
├── secure_relay_server.py          # Relay server implementation
├── secure_client.py                # Client implementation
├── README.md                       # This file
├── FINAL_REPORT.md                 # Detailed project report
└── DAL879368_Project_Design_Report.pdf  # Design specifications
```

---

## Security Analysis Summary

### Attack Scenarios Tested

| Attack Type | Detection Method | Result |
|------------|------------------|---------|
| Eavesdropping | End-to-end encryption |  Protected |
| Replay Attack | Sequence numbers + timestamps |  Detected & Blocked |
| Message Tampering | HMAC verification |  Detected & Blocked |
| MAC Corruption | HMAC verification |  Detected & Blocked |
| MITM Attack | Digital signatures on DH values |  Prevented |
| Impersonation | Challenge-response + signatures |  Prevented |
| Session Hijacking | Session binding via session_id |  Prevented |

### Relay Server Capabilities & Limitations

**What Relay CAN do:**
- Route messages between registered clients
- Verify message authenticity (signatures)
- Detect stale timestamps
- Prevent replay attacks at relay level

**What Relay CANNOT do:**
- Decrypt message contents (no session keys)
- Forge client signatures (no private keys)
- Modify messages without detection (HMAC protection)
- Read message plaintext (end-to-end encryption)

---

## Common Commands Reference

### Session Commands
```bash
session <peer_id>              # Establish secure session with peer
sessions                       # List all active sessions
lists                          # Show all connected clients
```

### Messaging Commands
```bash
send <peer_id> <message>       # Send encrypted message
history [peer_id]              # View message history
```

### Security Testing Commands
```bash
replay <peer_id> <index>       # Test replay protection
tamper <peer_id> <index>       # Test integrity protection
corrupt <peer_id> <index>      # Test MAC verification
```

### Other Commands
```bash
help                           # Show command list
quit                           # Exit client
```

---

## Troubleshooting

### Connection Refused
**Problem:** Client cannot connect to relay
**Solution:** 
- Ensure relay server is running first
- Check firewall settings
- Verify port 5050 is not in use

### Registration Failed
**Problem:** Client registration rejected
**Solution:**
- Check if client_id is already registered
- Restart relay server to clear registrations
- Verify system time is synchronized

### Session Establishment Failed
**Problem:** Cannot establish session with peer
**Solution:**
- Ensure both clients are registered
- Check that peer_id is spelled correctly
- Use `lists` command to verify peer is connected

### Message Not Received
**Problem:** Peer doesn't receive message
**Solution:**
- Verify session is established (`sessions` command)
- Check relay server terminal for errors
- Ensure recipient client is running

---
