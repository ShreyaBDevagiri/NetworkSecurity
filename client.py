"""
Chat Client
Handles TCP connection, registration, and message sending/receiving
"""

import socket
import threading
import json
import sys
import time
from datetime import datetime
from typing import Optional


class Client:
    def __init__(self, client_id: str, relay_host: str = 'localhost', relay_port: int = 5000):
        self.client_id = client_id
        self.relay_host = relay_host
        self.relay_port = relay_port
        
        self.socket: Optional[socket.socket] = None
        self.running = False
        self.registered = False
        
        print(f"[{self.client_id}] Client initialized")
        print(f"[{self.client_id}] Target relay: {relay_host}:{relay_port}\n")
    
    def connect(self) -> bool:
        """Connect to relay server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.relay_host, self.relay_port))
            
            print(f"[{self.client_id}] ✓ Connected to relay server")
            print(f"[{self.client_id}]   Address: {self.relay_host}:{self.relay_port}\n")
            
            # Start receiving thread
            self.running = True
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()
            
            return True
        
        except ConnectionRefusedError:
            print(f"[{self.client_id}] X Connection refused - Is relay server running?")
            return False
        except Exception as e:
            print(f"[{self.client_id}] X Connection failed: {e}")
            return False
    
    def register(self) -> bool:
        """Register with the relay server"""
        if not self.socket:
            print(f"[{self.client_id}] X Not connected to relay")
            return False
        
        print(f"[{self.client_id}] Sending registration request...")
        
        # Create registration message
        message = {
            "msg_type": "REGISTER",
            "client_id": self.client_id,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Send registration
        self.send_message(json.dumps(message).encode())
        
        # Wait for response
        time.sleep(0.5)
        
        return self.registered
    
    def send_chat_message(self, recipient_id: str, message_text: str) -> bool:
        """Send a chat message to another client through relay"""
        if not self.registered:
            print(f"[{self.client_id}] X Not registered with relay")
            return False
        
        print(f"[{self.client_id}] Sending message to '{recipient_id}'...")
        
        message = {
            "msg_type": "MESSAGE",
            "to": recipient_id,
            "message": message_text,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.send_message(json.dumps(message).encode())
        return True
    
    def list_clients(self):
        """Request list of registered clients from relay"""
        if not self.socket:
            print(f"[{self.client_id}] X Not connected to relay")
            return
        
        message = {
            "msg_type": "LIST_CLIENTS",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.send_message(json.dumps(message).encode())
    
    def receive_messages(self):
        """Receive and process messages from relay"""
        while self.running:
            try:
                data = self.recv_message()
                if not data:
                    break
                
                # Parse message
                message = json.loads(data.decode('utf-8'))
                msg_type = message.get('msg_type')
                
                # Handle different message types
                if msg_type == "REGISTER_RESPONSE":
                    self.handle_register_response(message)
                
                elif msg_type == "MESSAGE":
                    self.handle_incoming_message(message)
                
                elif msg_type == "MESSAGE_ACK":
                    self.handle_message_ack(message)
                
                elif msg_type == "CLIENT_LIST":
                    self.handle_client_list(message)
                
                elif msg_type == "ERROR":
                    self.handle_error(message)
                
                else:
                    print(f"[{self.client_id}] Unknown message type: {msg_type}")
            
            except json.JSONDecodeError as e:
                print(f"[{self.client_id}] JSON decode error: {e}")
            except Exception as e:
                if self.running:
                    print(f"[{self.client_id}] Receive error: {e}")
                break
        
        print(f"[{self.client_id}] Receiver thread stopped")
    
    def handle_register_response(self, message: dict):
        """Handle registration response from relay"""
        status = message.get('status')
        msg = message.get('message')
        timestamp = message.get('timestamp')
        
        if status == "SUCCESS":
            self.registered = True
            print(f"[{self.client_id}] ✓ Registration successful!")
            print(f"[{self.client_id}]   {msg}")
            print(f"[{self.client_id}]   Time: {timestamp}\n")
        else:
            self.registered = False
            print(f"[{self.client_id}] X Registration failed!")
            print(f"[{self.client_id}]   {msg}\n")
    
    def handle_incoming_message(self, message: dict):
        """Handle incoming chat message"""
        sender_id = message.get('from')
        message_text = message.get('message')
        timestamp = message.get('timestamp')
        
        print(f"\n{'='*60}")
        print(f"📨 NEW MESSAGE")
        print(f"{'='*60}")
        print(f"From:      {sender_id}")
        print(f"Time:      {timestamp}")
        print(f"Message:   {message_text}")
        print(f"{'='*60}\n")
    
    def handle_message_ack(self, message: dict):
        """Handle message delivery acknowledgment"""
        msg = message.get('message')
        timestamp = message.get('timestamp')
        
        print(f"[{self.client_id}] ✓ {msg}")
        print(f"[{self.client_id}]   Time: {timestamp}\n")
    
    def handle_client_list(self, message: dict):
        """Handle list of registered clients"""
        clients = message.get('clients', [])
        count = message.get('count', 0)
        
        print(f"\n{'='*60}")
        print(f"REGISTERED CLIENTS ({count})")
        print(f"{'='*60}")
        
        if clients:
            for i, client in enumerate(clients, 1):
                marker = " (you)" if client == self.client_id else ""
                print(f"{i}. {client}{marker}")
        else:
            print("No clients registered")
        
        print(f"{'='*60}\n")
    
    def handle_error(self, message: dict):
        """Handle error message from relay"""
        error_msg = message.get('message')
        timestamp = message.get('timestamp')
        
        print(f"[{self.client_id}] X ERROR: {error_msg}")
        print(f"[{self.client_id}]   Time: {timestamp}\n")
    
    def send_message(self, data: bytes):
        """Send message with 4-byte length prefix"""
        try:
            length = len(data)
            self.socket.sendall(length.to_bytes(4, 'big') + data)
        except Exception as e:
            print(f"[{self.client_id}] Send error: {e}")
    
    def recv_message(self) -> Optional[bytes]:
        """Receive message with 4-byte length prefix"""
        try:
            # Read 4-byte length prefix
            length_bytes = self.socket.recv(4)
            if not length_bytes or len(length_bytes) < 4:
                return None
            
            length = int.from_bytes(length_bytes, 'big')
            
            # Read the actual message
            data = b''
            while len(data) < length:
                chunk = self.socket.recv(min(length - len(data), 4096))
                if not chunk:
                    return None
                data += chunk
            
            return data
        
        except Exception as e:
            if self.running:
                print(f"[{self.client_id}] Receive error: {e}")
            return None
    
    def disconnect(self):
        """Disconnect from relay server"""
        self.running = False
        if self.socket:
            self.socket.close()
        print(f"[{self.client_id}] Disconnected from relay\n")
    
    def interactive_mode(self):
        """Run client in interactive mode"""
        print(f"{'='*60}")
        print(f"CHAT CLIENT: {self.client_id}")
        print(f"{'='*60}")
        print("Commands:")
        print("  send <recipient_id> <message>  - Send a message")
        print("  list                           - List registered clients")
        print("  help                           - Show this help")
        print("  quit                           - Exit the client")
        print(f"{'='*60}\n")
        
        try:
            while True:
                try:
                    command = input(f"{self.client_id}> ").strip()
                    
                    if not command:
                        continue
                    
                    parts = command.split(maxsplit=2)
                    cmd = parts[0].lower()
                    
                    if cmd == "quit" or cmd == "exit":
                        print(f"[{self.client_id}] Exiting...\n")
                        break
                    
                    elif cmd == "send":
                        if len(parts) < 3:
                            print(f"[{self.client_id}] Usage: send <recipient_id> <message>\n")
                        else:
                            recipient = parts[1]
                            message = parts[2]
                            self.send_chat_message(recipient, message)
                    
                    elif cmd == "list":
                        self.list_clients()
                    
                    elif cmd == "help":
                        print("\nCommands:")
                        print("  send <recipient_id> <message>  - Send a message")
                        print("  list                           - List registered clients")
                        print("  help                           - Show this help")
                        print("  quit                           - Exit the client\n")
                    
                    else:
                        print(f"[{self.client_id}] Unknown command: {cmd}")
                        print(f"[{self.client_id}] Type 'help' for available commands\n")
                
                except EOFError:
                    break
        
        except KeyboardInterrupt:
            print(f"\n[{self.client_id}] Interrupted by user\n")
        
        finally:
            self.disconnect()


def main():
    """Main entry point for the client"""
    print("="*60)
    print("SECURE RELAY-BASED CHAT SYSTEM ")
    print("Chat Client")
    print("="*60)
    print()
    
    # Parse command line arguments
    if len(sys.argv) < 2:
        print("Usage: python client.py <client_id> [relay_host] [relay_port]")
        print("Example: python client.py alice")
        print("Example: python client.py bob localhost 5000")
        sys.exit(1)
    
    client_id = sys.argv[1]
    relay_host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'
    relay_port = int(sys.argv[3]) if len(sys.argv) > 3 else 5000
    
    # Create client
    client = Client(client_id, relay_host, relay_port)
    
    # Connect to relay
    if not client.connect():
        print("Failed to connect to relay server")
        sys.exit(1)
    
    # Register with relay
    time.sleep(0.5)  # Give connection time to establish
    if not client.register():
        print("Failed to register with relay server")
        sys.exit(1)
    
    # Wait for registration to complete
    time.sleep(1)
    
    # Start interactive mode
    client.interactive_mode()


if __name__ == "__main__":
    main()