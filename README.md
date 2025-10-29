
---

## Prerequisites
- **Python:** Version 3.9 or higher  
- **Operating System:** Windows, Linux, or macOS  
- **Network:** Localhost/LAN access (no external dependencies)

### Check Python Version
```bash
python --version
# or
python3 --version
```

### Start (3 Steps)
**Step 1: Start Relay Server**
Open Terminal 1 and run:
```bash
python relay_server.py
```

**Expected Output:**

SECURE RELAY-BASED CHAT SYSTEM - DELIVERABLE 1
Relay Server
[RELAY_SERVER] Relay Server Initialized
[RELAY_SERVER] Listening on 0.0.0.0:5000
[RELAY_SERVER] Server started successfully!
[RELAY_SERVER] Waiting for client connections...


✅ Success: Server is running and waiting for connections

**Step 2: Start First Client (Alice)**
Open Terminal 2:
```bash
python client.py alice
```

**Expected Output:**

[alice] ✓ Connected to relay server
[alice] ✓ Registration successful!

alice> _

✅ Alice connected successfully

**Step 3: Start Second Client (Bob)**
Open Terminal 3:
```bash
python client.py bob
```

**Expected Output:**
[bob] ✓ Connected to relay server
[bob] ✓ Registration successful!

bob> _
✅ Bob connected successfully


💬 Send Your First Message
In Alice's Terminal:
alice> send bob Hello Bob! This is Alice.

Bob Will See:

📨 NEW MESSAGE

From:      alice
Time:      2025-10-28 10:32:45
Message:   Hello Bob! This is Alice.


Bob Replies:
bob> send alice Hi Alice! Nice to meet you!


```bash
🧠 Available Commands
Command	Description
send <recipient_id> <message>	Send message to another client
list	Show all registered clients
help	Display available commands
quit	Disconnect and exit
Example:
alice> list
alice> send bob Want to grab lunch?
alice> quit
```


