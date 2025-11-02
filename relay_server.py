"""
Relay Server
Handles TCP connections, registration, and message forwarding
"""

import socket
import threading
import json
from datetime import datetime
from typing import Dict, Optional


class RelayServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 5000):
        self.host = host
        self.port = port
        self.relay_id = "RELAY_SERVER"
        
        # Store registered clients: client_id -> socket
        self.clients: Dict[str, socket.socket] = {}
        
        # Store reverse mapping: socket -> client_id
        self.socket_to_client: Dict[socket.socket, str] = {}
        
        # Lock for thread-safe operations
        self.lock = threading.Lock()
        
        print(f"[{self.relay_id}] Relay Server Initialized")
        print(f"[{self.relay_id}] Listening on {self.host}:{self.port}")
    
    def start(self):
        """Start the relay server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            
            print(f"[{self.relay_id}] Server started successfully!")
            print(f"[{self.relay_id}] Waiting for client connections...\n")
            
            while True:
                client_socket, address = server_socket.accept()
                print(f"[{self.relay_id}] New connection from {address}")
                
                # Handle each client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address),
                    daemon=True
                )
                client_thread.start()
                
        except KeyboardInterrupt:
            print(f"\n[{self.relay_id}] Shutting down server...")
        except Exception as e:
            print(f"[{self.relay_id}] Server error: {e}")
        finally:
            server_socket.close()
            print(f"[{self.relay_id}] Server stopped")
    
    def handle_client(self, client_socket: socket.socket, address):
        """Handle messages from a connected client"""
        client_id = None
        
        try:
            while True:
                # Receive message with length prefix
                data = self.recv_message(client_socket)
                if not data:
                    break
                
                # Parse JSON message
                try:
                    message = json.loads(data.decode('utf-8'))
                    msg_type = message.get('msg_type')
                    
                    # Route message based on type
                    if msg_type == "REGISTER":
                        client_id = self.handle_registration(client_socket, message)
                    
                    elif msg_type == "MESSAGE":
                        self.handle_message(client_socket, message)
                    
                    elif msg_type == "LIST_CLIENTS":
                        self.handle_list_clients(client_socket)
                    
                    else:
                        print(f"[{self.relay_id}] Unknown message type: {msg_type}")
                
                except json.JSONDecodeError as e:
                    print(f"[{self.relay_id}] JSON decode error: {e}")
                except Exception as e:
                    print(f"[{self.relay_id}] Error processing message: {e}")
        
        except Exception as e:
            print(f"[{self.relay_id}] Connection error with {address}: {e}")
        
        finally:
            # Cleanup on disconnect
            with self.lock:
                if client_socket in self.socket_to_client:
                    client_id = self.socket_to_client[client_socket]
                    del self.socket_to_client[client_socket]
                    if client_id in self.clients:
                        del self.clients[client_id]
                    print(f"[{self.relay_id}] Client '{client_id}' disconnected\n")
            
            client_socket.close()
    
    def handle_registration(self, client_socket: socket.socket, message: dict) -> Optional[str]:
        """Handle client registration request"""
        client_id = message.get('client_id', 'Unknown')
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"[{self.relay_id}] Registration request from '{client_id}'")
        
        # Check if client_id already exists
        with self.lock:
            if client_id in self.clients:
                # Client ID already taken
                response = {
                    "msg_type": "REGISTER_RESPONSE",
                    "status": "FAILURE",
                    "message": f"Client ID '{client_id}' is already registered",
                    "timestamp": timestamp
                }
                self.send_message(client_socket, json.dumps(response).encode())
                print(f"[{self.relay_id}] Registration FAILED - ID already exists")
                return None
            
            # Register the client
            self.clients[client_id] = client_socket
            self.socket_to_client[client_socket] = client_id
        
        # Send success response
        response = {
            "msg_type": "REGISTER_RESPONSE",
            "status": "SUCCESS",
            "message": f"Client '{client_id}' registered successfully",
            "relay_id": self.relay_id,
            "timestamp": timestamp
        }
        
        self.send_message(client_socket, json.dumps(response).encode())
        print(f"[{self.relay_id}] Client '{client_id}' registered successfully")
        print(f"[{self.relay_id}] Total clients: {len(self.clients)}\n")
        
        return client_id
    
    def handle_message(self, sender_socket: socket.socket, message: dict):
        """Handle message forwarding from one client to another"""
        # Get sender info
        with self.lock:
            if sender_socket not in self.socket_to_client:
                print(f"[{self.relay_id}] Message from unregistered client")
                return
            
            sender_id = self.socket_to_client[sender_socket]
        
        recipient_id = message.get('to')
        message_text = message.get('message')
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"[{self.relay_id}] Message: '{sender_id}' -> '{recipient_id}'")
        print(f"[{self.relay_id}] Content: {message_text}")
        
        # Find recipient socket
        with self.lock:
            if recipient_id not in self.clients:
                # Recipient not found
                error_response = {
                    "msg_type": "ERROR",
                    "message": f"Recipient '{recipient_id}' not found or offline",
                    "timestamp": timestamp
                }
                self.send_message(sender_socket, json.dumps(error_response).encode())
                print(f"[{self.relay_id}] Recipient '{recipient_id}' not found\n")
                return
            
            recipient_socket = self.clients[recipient_id]
        
        # Forward message to recipient
        forward_message = {
            "msg_type": "MESSAGE",
            "from": sender_id,
            "message": message_text,
            "timestamp": timestamp
        }
        
        self.send_message(recipient_socket, json.dumps(forward_message).encode())
        print(f"[{self.relay_id}] Message forwarded successfully\n")
        
        # Send acknowledgment to sender
        ack_message = {
            "msg_type": "MESSAGE_ACK",
            "message": "Message delivered successfully",
            "timestamp": timestamp
        }
        self.send_message(sender_socket, json.dumps(ack_message).encode())
    
    def handle_list_clients(self, client_socket: socket.socket):
        """Send list of registered clients"""
        with self.lock:
            client_list = list(self.clients.keys())
        
        response = {
            "msg_type": "CLIENT_LIST",
            "clients": client_list,
            "count": len(client_list),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.send_message(client_socket, json.dumps(response).encode())
        print(f"[{self.relay_id}] Sent client list (count: {len(client_list)})\n")
    
    def send_message(self, sock: socket.socket, data: bytes):
        """Send message with 4-byte length prefix"""
        try:
            length = len(data)
            sock.sendall(length.to_bytes(4, 'big') + data)
        except Exception as e:
            print(f"[{self.relay_id}] Send error: {e}")
    
    def recv_message(self, sock: socket.socket) -> Optional[bytes]:
        """Receive message with 4-byte length prefix"""
        try:
            # Read 4-byte length prefix
            length_bytes = sock.recv(4)
            if not length_bytes or len(length_bytes) < 4:
                return None
            
            length = int.from_bytes(length_bytes, 'big')
            
            # Read the actual message
            data = b''
            while len(data) < length:
                chunk = sock.recv(min(length - len(data), 4096))
                if not chunk:
                    return None
                data += chunk
            
            return data
        
        except Exception as e:
            print(f"[{self.relay_id}] Receive error: {e}")
            return None


if __name__ == "__main__":
    print("="*60)
    print("SECURE RELAY-BASED CHAT SYSTEM")
    print("Relay Server")
    print("="*60)
    print()
    
    relay = RelayServer(host='0.0.0.0', port=5000)
    relay.start()
