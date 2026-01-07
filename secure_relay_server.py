"""
Secure Relay Server
Handles secure registration, session forwarding, and message routing
"""

import socket
import threading
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class SecureRelayServer:
    def __init__(self, host: str = '0.0.0.0', port: int = 5050):
        self.host = host
        self.port = port
        self.relay_id = "RELAY_SERVER"
        
        # RSA keys for relay
        self.private_key = None
        self.public_key = None
        self._generate_rsa_keys()
        
        # Client registry: client_id -> {socket, public_key, timestamp}
        self.clients: Dict[str, Dict] = {}
        
        # Reverse mapping: socket -> client_id
        self.socket_to_client: Dict[socket.socket, str] = {}
        
        # Message tracking for replay detection
        self.processed_messages: Dict[str, set] = {}  # client_id -> set of (nonce, timestamp)
        
        # Lock for thread-safe operations
        self.lock = threading.Lock()
        
        # Timestamp window for replay protection (5 minutes)
        self.timestamp_window = timedelta(minutes=5)
        
        print(f"[{self.relay_id}] Secure Relay Server Initialized")
        print(f"[{self.relay_id}] Listening on {self.host}:{self.port}")
        print(f"[{self.relay_id}] Replay protection window: {self.timestamp_window}\n")
    
    def _generate_rsa_keys(self):
        """Generate RSA key pair for relay authentication"""
        print(f"[{self.relay_id}] Generating RSA key pair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print(f"[{self.relay_id}] RSA keys generated\n")
    
    def _sign_message(self, *data_parts) -> bytes:
        """Sign data using RSA private key"""
        message = "|".join(str(d) for d in data_parts).encode()
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def _verify_signature(self, public_key, signature: bytes, *data_parts) -> bool:
        """Verify RSA signature"""
        try:
            message = "|".join(str(d) for d in data_parts).encode()
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    def _check_timestamp_freshness(self, timestamp_str: str) -> bool:
        """Check if timestamp is within acceptable window"""
        try:
            msg_time = datetime.fromisoformat(timestamp_str)
            current_time = datetime.now()
            time_diff = abs(current_time - msg_time)
            
            is_fresh = time_diff < self.timestamp_window
            
            if not is_fresh:
                print(f"[{self.relay_id}]   Timestamp freshness check failed:")
                print(f"[{self.relay_id}]   Message time: {msg_time}")
                print(f"[{self.relay_id}]   Current time: {current_time}")
                print(f"[{self.relay_id}]   Difference: {time_diff}")
            
            return is_fresh
        except Exception as e:
            print(f"[{self.relay_id}] Timestamp parsing error: {e}")
            return False
    
    def _check_replay(self, client_id: str, nonce: str, timestamp: str) -> bool:
        """Check for replay attacks using nonce and timestamp"""
        message_id = f"{nonce}:{timestamp}"
        
        with self.lock:
            if client_id not in self.processed_messages:
                self.processed_messages[client_id] = set()
            
            if message_id in self.processed_messages[client_id]:
                print(f"[{self.relay_id}]   REPLAY ATTACK DETECTED!")
                print(f"[{self.relay_id}]   Client: {client_id}")
                print(f"[{self.relay_id}]   Nonce: {nonce[:16]}...")
                print(f"[{self.relay_id}]   Message already processed - REJECTED")
                return False
            
            # Add to processed set
            self.processed_messages[client_id].add(message_id)
            
            # Clean old entries (older than timestamp window)
            # In production, implement periodic cleanup
            
            return True
    
    def start(self):
        """Start the relay server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            
            print(f"[{self.relay_id}]  Server started successfully!")
            print(f"[{self.relay_id}] Waiting for client connections...\n")
            
            while True:
                client_socket, address = server_socket.accept()
                print(f"[{self.relay_id}] New connection from {address}")
                
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
                data = self.recv_message(client_socket)
                if not data:
                    break
                
                try:
                    message = json.loads(data.decode('utf-8'))
                    msg_type = message.get('msg_type')
                    
                    print(f"[{self.relay_id}]  Received: {msg_type}")
                    
                    if msg_type == "REGISTER":
                        client_id = self.handle_registration(client_socket, message)
                    
                    elif msg_type == "SESSION_INIT":
                        self.handle_session_init(client_socket, message)
                    
                    elif msg_type == "SESSION_RESPONSE":
                        self.handle_session_response(client_socket, message)
                    
                    elif msg_type == "DATA":
                        self.handle_data_message(client_socket, message)
                    
                    elif msg_type == "REQUEST_CLIENT_LIST":
                        self.handle_client_list_request(client_socket, message)
                    
                    elif msg_type == "RELAY_TAMPER_TEST":
                        self.handle_tamper_trigger(client_socket, message)
                    
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
        """Handle secure client registration"""
        client_id = message.get('client_id', 'Unknown')
        public_key_pem = message.get('public_key')
        timestamp = message.get('timestamp')
        nonce = message.get('nonce')
        signature_hex = message.get('signature')
        
        print(f"\n[{self.relay_id}] Processing registration from '{client_id}'")
        print(f"[{self.relay_id}] Timestamp: {timestamp}")
        print(f"[{self.relay_id}] Nonce: {nonce[:16]}...")
        
        # Load public key
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
                backend=default_backend()
            )
        except Exception as e:
            print(f"[{self.relay_id}] Invalid public key: {e}")
            self._send_error(client_socket, "Invalid public key format")
            return None
        
        # Check timestamp freshness
        if not self._check_timestamp_freshness(timestamp):
            print(f"[{self.relay_id}] Registration rejected - stale timestamp")
            self._send_error(client_socket, "Timestamp outside acceptable window")
            return None
        
        # Check for replay
        if not self._check_replay(client_id, nonce, timestamp):
            self._send_error(client_socket, "Replay attack detected")
            return None
        
        # Verify signature
        signature = bytes.fromhex(signature_hex)
        if not self._verify_signature(
            public_key, signature,
            "REGISTER", client_id, public_key_pem, timestamp, nonce
        ):
            print(f"[{self.relay_id}] Signature verification failed")
            self._send_error(client_socket, "Invalid signature")
            return None
        
        print(f"[{self.relay_id}] Signature verified")
        
        # Check if client_id already exists
        with self.lock:
            if client_id in self.clients:
                print(f"[{self.relay_id}] Client ID already registered")
                self._send_error(client_socket, f"Client ID '{client_id}' already registered")
                return None
            
            # Register the client
            self.clients[client_id] = {
                "socket": client_socket,
                "public_key": public_key,
                "registered_at": datetime.now()
            }
            self.socket_to_client[client_socket] = client_id
        
        # Send success response with relay's public key
        relay_pk_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        response_timestamp = datetime.now().isoformat()
        
        # Sign the response
        response_signature = self._sign_message(
            "REGISTER_ACK", "SUCCESS", client_id, self.relay_id,
            response_timestamp, nonce
        )
        
        response = {
            "msg_type": "REGISTER_ACK",
            "status": "SUCCESS",
            "client_id": client_id,
            "relay_id": self.relay_id,
            "relay_public_key": relay_pk_pem,
            "timestamp": response_timestamp,
            "nonce_echo": nonce,
            "nonce_new": nonce,  # Could generate new nonce
            "signature": response_signature.hex()
        }
        
        self.send_message(client_socket, json.dumps(response).encode())
        
        print(f"[{self.relay_id}] Client '{client_id}' registered successfully")
        print(f"[{self.relay_id}] Mutual authentication complete")
        print(f"[{self.relay_id}] Total clients: {len(self.clients)}\n")
        
        return client_id
    
    def handle_session_init(self, sender_socket: socket.socket, message: dict):
        """Handle and forward session initialization"""
        with self.lock:
            if sender_socket not in self.socket_to_client:
                print(f"[{self.relay_id}] Session init from unregistered client")
                return
            
            sender_id = self.socket_to_client[sender_socket]
            sender_pk = self.clients[sender_id]["public_key"]
        
        recipient_id = message.get('to')
        timestamp = message.get('timestamp')
        signature_hex = message.get('signature')
        
        print(f"\n[{self.relay_id}] Session Init: '{sender_id}' → '{recipient_id}'")
        
        # Verify timestamp
        if not self._check_timestamp_freshness(timestamp):
            self._send_error(sender_socket, "Timestamp outside acceptable window")
            return
        
        # Verify sender's signature (using hex string as signed)
        signature = bytes.fromhex(signature_hex)
        if not self._verify_signature(
            sender_pk, signature,
            "SESSION_INIT", message['from'], message['to'],
            str(message['dh_public']), timestamp, message['nonce']
        ):
            print(f"[{self.relay_id}] Invalid signature from sender")
            print(f"[{self.relay_id}] Debug - Signature data:")
            print(f"[{self.relay_id}]   from: {message['from']}")
            print(f"[{self.relay_id}]   to: {message['to']}")
            print(f"[{self.relay_id}]   dh_public: {message['dh_public'][:32]}...")
            print(f"[{self.relay_id}]   timestamp: {timestamp}")
            print(f"[{self.relay_id}]   nonce: {message['nonce'][:16]}...")
            self._send_error(sender_socket, "Invalid signature")
            return
        
        print(f"[{self.relay_id}] Sender signature verified")
        
        # Find recipient
        with self.lock:
            if recipient_id not in self.clients:
                print(f"[{self.relay_id}] Recipient '{recipient_id}' not found")
                self._send_error(sender_socket, f"Recipient '{recipient_id}' not registered")
                return
            
            recipient_socket = self.clients[recipient_id]["socket"]
        
        # Add relay signature and forward
        relay_timestamp = datetime.now().isoformat()
        relay_signature = self._sign_message(
            "SESSION_REQUEST", sender_id, recipient_id,
            message['dh_public'], relay_timestamp
        )
        
        forward_message = {
            "msg_type": "SESSION_REQUEST",
            "from": sender_id,
            "to": recipient_id,
            "dh_public": message['dh_public'],
            "dh_params": message['dh_params'],
            "timestamp": timestamp,
            "nonce": message['nonce'],
            "signature_sender": signature_hex,
            "relay_signature": relay_signature.hex(),
            "relay_timestamp": relay_timestamp
        }
        
        self.send_message(recipient_socket, json.dumps(forward_message).encode())
        print(f"[{self.relay_id}] Session request forwarded to '{recipient_id}'\n")
    
    def handle_session_response(self, sender_socket: socket.socket, message: dict):
        """Handle and forward session response"""
        with self.lock:
            if sender_socket not in self.socket_to_client:
                print(f"[{self.relay_id}] Session response from unregistered client")
                return
            
            sender_id = self.socket_to_client[sender_socket]
            sender_pk = self.clients[sender_id]["public_key"]
        
        recipient_id = message.get('to')
        timestamp = message.get('timestamp')
        signature_hex = message.get('signature')
        
        print(f"\n[{self.relay_id}] Session Response: '{sender_id}' → '{recipient_id}'")
        
        # Verify timestamp
        if not self._check_timestamp_freshness(timestamp):
            self._send_error(sender_socket, "Timestamp outside acceptable window")
            return
        
        # Verify sender's signature (using hex string as signed)
        signature = bytes.fromhex(signature_hex)
        if not self._verify_signature(
            sender_pk, signature,
            "SESSION_RESPONSE", message['from'], message['to'],
            str(message['dh_public']), timestamp, message['nonce'], message['nonce_echo']
        ):
            print(f"[{self.relay_id}] Invalid signature from sender")
            self._send_error(sender_socket, "Invalid signature")
            return
        
        print(f"[{self.relay_id}] Sender signature verified")
        
        # Find recipient
        with self.lock:
            if recipient_id not in self.clients:
                print(f"[{self.relay_id}] Recipient '{recipient_id}' not found")
                self._send_error(sender_socket, f"Recipient '{recipient_id}' not registered")
                return
            
            recipient_socket = self.clients[recipient_id]["socket"]
        
        # Add relay signature and forward
        relay_timestamp = datetime.now().isoformat()
        relay_signature = self._sign_message(
            "SESSION_ESTABLISHED", sender_id, recipient_id,
            message['dh_public'], relay_timestamp
        )
        
        forward_message = {
            "msg_type": "SESSION_ESTABLISHED",
            "from": sender_id,
            "to": recipient_id,
            "dh_public": message['dh_public'],
            "timestamp": timestamp,
            "nonce": message['nonce'],
            "nonce_echo": message['nonce_echo'],
            "signature_B": signature_hex,
            "relay_signature": relay_signature.hex(),
            "relay_timestamp": relay_timestamp
        }
        
        self.send_message(recipient_socket, json.dumps(forward_message).encode())
        print(f"[{self.relay_id}] Session established confirmation sent to '{recipient_id}'")
        print(f"[{self.relay_id}] Secure session between '{sender_id}' and '{recipient_id}' ready\n")
    
    def handle_data_message(self, sender_socket: socket.socket, message: dict):
        """Handle and forward encrypted data message"""
        with self.lock:
            if sender_socket not in self.socket_to_client:
                print(f"[{self.relay_id}] Data message from unregistered client")
                return
            
            sender_id = self.socket_to_client[sender_socket]
        
        recipient_id = message.get('to')
        session_id = message.get('session_id')
        seq_num = message.get('seq_num')
        timestamp = message.get('timestamp')
        
        print(f"\n[{self.relay_id}] Encrypted Data: '{sender_id}' → '{recipient_id}'")
        print(f"[{self.relay_id}] Session ID: {session_id[:16]}...")
        print(f"[{self.relay_id}] Sequence: {seq_num}")
        print(f"[{self.relay_id}] Timestamp: {timestamp}")
        
        # Verify timestamp
        if not self._check_timestamp_freshness(timestamp):
            print(f"[{self.relay_id}] Stale timestamp - message rejected")
            self._send_error(sender_socket, "Timestamp outside acceptable window")
            return
        
        print(f"[{self.relay_id}] Timestamp verified (fresh)")
        
        # Find recipient
        with self.lock:
            if recipient_id not in self.clients:
                print(f"[{self.relay_id}] Recipient '{recipient_id}' not found")
                self._send_error(sender_socket, f"Recipient '{recipient_id}' not registered")
                return
            
            recipient_socket = self.clients[recipient_id]["socket"]
        
        # Check if relay should tamper (for testing outer MAC protection)
        should_tamper = hasattr(self, 'tamper_next_message') and self.tamper_next_message
        
        if should_tamper:
            print(f"[{self.relay_id}] TAMPERING WITH OUTER MAC (Testing outer MAC detection)")
            if "mac_outer" in message:
                mac_outer_bytes = bytes.fromhex(message["mac_outer"])
                tampered_bytes = bytearray(mac_outer_bytes)
                if len(tampered_bytes) > 0:
                    tampered_bytes[0] = (tampered_bytes[0] + 1) % 256
                    message["mac_outer"] = tampered_bytes.hex()
                print(f"[{self.relay_id}] Outer MAC corrupted - recipient will detect tampering")
            self.tamper_next_message = False
        
        # Forward the encrypted message (relay cannot decrypt)
        print(f"[{self.relay_id}] Forwarding encrypted payload (cannot decrypt)")
        self.send_message(recipient_socket, json.dumps(message).encode())
        
        if should_tamper:
            print(f"[{self.relay_id}] Tampered message forwarded - watch recipient for detection\n")
        else:
            print(f"[{self.relay_id}] Encrypted message forwarded successfully")
            print(f"[{self.relay_id}] End-to-end confidentiality maintained\n")
    
    def handle_client_list_request(self, client_socket: socket.socket, message: dict):
        """Handle request for list of connected clients"""
        with self.lock:
            if client_socket not in self.socket_to_client:
                print(f"[{self.relay_id}] Client list request from unregistered client")
                return
            
            requester_id = self.socket_to_client[client_socket]
            # Get list of all connected clients
            client_list = list(self.clients.keys())
        
        print(f"\n[{self.relay_id}] Client List Request from '{requester_id}'")
        print(f"[{self.relay_id}] Total connected clients: {len(client_list)}")
        
        response = {
            "msg_type": "CLIENT_LIST",
            "clients": client_list,
            "total_count": len(client_list),
            "timestamp": datetime.now().isoformat()
        }
        
        self.send_message(client_socket, json.dumps(response).encode())
        
        print(f"[{self.relay_id}] Client list sent to '{requester_id}'\n")
    
    def handle_tamper_trigger(self, client_socket: socket.socket, message: dict):
        """Handle relay tampering trigger (for testing outer MAC detection)"""
        with self.lock:
            if client_socket not in self.socket_to_client:
                print(f"[{self.relay_id}] Tamper request from unregistered client")
                return
            
            requester_id = self.socket_to_client[client_socket]
        
        target_id = message.get('to')
        
        print(f"\n[{self.relay_id}] RELAY TAMPERING TEST TRIGGERED")
        print(f"[{self.relay_id}] By: '{requester_id}'")
        print(f"[{self.relay_id}] Target: '{target_id}'")
        print(f"[{self.relay_id}] Next message to '{target_id}' will have corrupted outer MAC")
        print(f"[{self.relay_id}] Recipient will detect: RELAY TAMPERING DETECTED!\n")
        
        # Set flag for tampering on next message to this target
        self.tamper_next_message = True
    
    def _send_error(self, client_socket: socket.socket, error_msg: str):
        """Send error message to client"""
        response = {
            "msg_type": "ERROR",
            "message": error_msg,
            "timestamp": datetime.now().isoformat()
        }
        self.send_message(client_socket, json.dumps(response).encode())
    
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
            length_bytes = sock.recv(4)
            if not length_bytes or len(length_bytes) < 4:
                return None
            
            length = int.from_bytes(length_bytes, 'big')
            
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
    print("="*70)
    print("SECURE RELAY-BASED CHAT SYSTEM")
    print("Secure Relay Server - Full Protocol Implementation")
    print("="*70)
    print()
    
    relay = SecureRelayServer(host='0.0.0.0', port=5050)
    relay.start()
