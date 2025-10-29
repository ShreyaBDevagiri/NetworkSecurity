# 🚀 Quick Start Guide

## 🧑‍💻 Team Information
- **Spoorti Katti** 
- **Shreya Basavaraj Devagiri** 
- **Course:** CS 6349.001 – Network Security (Fall 2025)


## ⚙️ Prerequisites
- **Python version:** 3.9 or higher  
- **Operating system:** Windows, Linux, or macOS  
- **Network:** Localhost/LAN access (no external dependencies)

### Check Python version
```bash
python --version
# or
python3 --version
```

### Quick Start (3 Steps)

## Step 1: Start the Relay Server
Open Terminal 1 and run:
``` bash
python relay_server.py
```
```
Expected Output:
============================================================
SECURE RELAY-BASED CHAT SYSTEM - DELIVERABLE 1
Relay Server
============================================================

[RELAY_SERVER] Relay Server Initialized
[RELAY_SERVER] Listening on 0.0.0.0:5000
[RELAY_SERVER] Server started successfully!
[RELAY_SERVER] Waiting for client connections...
✅ Server is now running and ready to accept clients.
```

### Step 2: Start the First Client (Alice)
Open Terminal 2 and run:

```bash
python client.py alice
```
```
Expected Output:
[alice] ✓ Connected to relay server
[alice] ✓ Registration successful!

alice> _
Alice is connected and registered.
```

##Step 3: Start the Second Client (Bob)
Open Terminal 3 and run:

```bash
python client.py bob
```
```Expected Output:
[bob] ✓ Connected to relay server
[bob] ✓ Registration successful!

bob> _
Bob is connected and registered.
```
```
Sending Messages
In Alice’s terminal:
alice> send bob Hello Bob! This is Alice.
In Bob’s terminal:
============================================================
📨 NEW MESSAGE
============================================================
From:      alice
Time:      2025-10-28 10:32:45
Message:   Hello Bob! This is Alice.
============================================================
Bob can reply:
bob> send alice Hi Alice! Nice to meet you!
You’ve successfully exchanged messages via the relay server!
```
```
Available Commands
Command	Description
send <recipient_id> <message>	Send a message to another client
list	Display all registered clients
help	Show available commands
quit	Disconnect and exit
```
```
Example Usage
alice> list
alice> send bob Want to grab lunch?
alice> quit
```
### 🧱 Architecture Overview
```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│    Alice     │◄───────►│    Relay     │◄───────►│     Bob      │
│   (Client)   │   TCP   │   (Server)   │   TCP   │   (Client)   │
└──────────────┘         └──────────────┘         └──────────────┘
```
