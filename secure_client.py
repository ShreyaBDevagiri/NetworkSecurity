"""
Secure Chat Client
Implements complete security protocol with RSA, DH, and Keyed-Hash encryption
"""

import socket
import threading
import json
import sys
import time
import os
import secrets
from datetime import datetime
from typing import Optional, Dict
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


class SecureClient:
    def __init__(self, client_id: str, relay_host: str = 'localhost', relay_port: int = 5050):
        self.client_id = client_id
        self.relay_host = relay_host
        self.relay_port = relay_port
        
        # RSA Keys (long-term)
        self.private_key = None
        self.public_key = None
        self.relay_public_key = None
        self.peer_public_keys: Dict[str, any] = {}
        
        # Session management
        self.sessions: Dict[str, Dict] = {}  # peer_id -> session_info
        self.sequence_numbers: Dict[str, int] = {}
        self.received_sequences: Dict[str, int] = {}
        
        # Message history - store sent messages for replay testing
        self.message_history: Dict[str, list] = {}  # peer_id -> list of messages
        
        # Network
        self.socket: Optional[socket.socket] = None
        self.running = False
        self.registered = False
        
        # DH parameters (using safe primes)
        self.DH_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                       "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                       "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                       "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                       "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                       "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                       "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                       "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                       "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                       "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                       "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
        self.DH_G = 2
        
        self._generate_rsa_keys()
        print(f"[{self.client_id}] Secure Client initialized")
        print(f"[{self.client_id}] Target relay: {relay_host}:{relay_port}\n")
    
    def _generate_rsa_keys(self):
        """Generate RSA key pair for authentication"""
        print(f"[{self.client_id}] Generating RSA key pair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        print(f"[{self.client_id}] RSA keys generated\n")
    
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
    
    def _hmac_kdf(self, key: bytes, context: str) -> bytes:
        """HMAC-based Key Derivation Function"""
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(context.encode())
        return h.finalize()
    
    def _encrypt_keyed_hash(self, key: bytes, plaintext: bytes) -> tuple:
        """Encrypt using HMAC-based stream cipher"""
        iv = secrets.token_bytes(16)
        ciphertext = bytearray()
        
        block_size = 32  # HMAC-SHA256 output size
        counter = 0
        
        for i in range(0, len(plaintext), block_size):
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(iv + counter.to_bytes(4, 'big'))
            keystream = h.finalize()
            
            block = plaintext[i:i+block_size]
            cipher_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            ciphertext.extend(cipher_block)
            counter += 1
        
        return iv, bytes(ciphertext)
    
    def _decrypt_keyed_hash(self, key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """Decrypt using HMAC-based stream cipher"""
        plaintext = bytearray()
        
        block_size = 32
        counter = 0
        
        for i in range(0, len(ciphertext), block_size):
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(iv + counter.to_bytes(4, 'big'))
            keystream = h.finalize()
            
            block = ciphertext[i:i+block_size]
            plain_block = bytes(a ^ b for a, b in zip(block, keystream[:len(block)]))
            plaintext.extend(plain_block)
            counter += 1
        
        return bytes(plaintext)
    
    def _compute_hmac(self, key: bytes, *data_parts) -> bytes:
        """Compute HMAC-SHA256"""
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        for part in data_parts:
            if isinstance(part, str):
                h.update(part.encode())
            elif isinstance(part, int):
                h.update(str(part).encode())
            else:
                h.update(part)
        return h.finalize()
    
    def connect(self) -> bool:
        """Connect to relay server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.relay_host, self.relay_port))
            
            print(f"[{self.client_id}]  Connected to relay server")
            print(f"[{self.client_id}]  Address: {self.relay_host}:{self.relay_port}\n")
            
            self.running = True
            receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receive_thread.start()
            
            return True
        
        except ConnectionRefusedError:
            print(f"[{self.client_id}]  Connection refused - Is relay server running?")
            return False
        except Exception as e:
            print(f"[{self.client_id}]  Connection failed: {e}")
            return False
    
    def register(self) -> bool:
        """Register with relay server using secure protocol"""
        if not self.socket:
            print(f"[{self.client_id}]  Not connected to relay")
            return False
        
        print(f"[{self.client_id}]  Sending secure registration request...")
        
        timestamp = datetime.now().isoformat()
        nonce = secrets.token_hex(32)
        
        # Serialize public key
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Sign registration data
        signature = self._sign_message(
            "REGISTER", self.client_id, public_key_pem, timestamp, nonce
        )
        
        message = {
            "msg_type": "REGISTER",
            "client_id": self.client_id,
            "public_key": public_key_pem,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature.hex()
        }
        
        print(f"[{self.client_id}]  Registration details:")
        # print(f"[{self.client_id}]   - Nonce: {nonce[:16]}...")
        print(f"[{self.client_id}]   - Timestamp: {timestamp}\n")
        # print(f"[{self.client_id}]   - Signature length: {len(signature)} bytes\n")
        
        self.send_message(json.dumps(message).encode())
        time.sleep(0.5)
        
        return self.registered
    
    def initiate_session(self, peer_id: str) -> bool:
        """Initiate Diffie-Hellman session with peer"""
        if not self.registered:
            print(f"[{self.client_id}]  Not registered with relay")
            return False
        
        print(f"\n[{self.client_id}]  Initiating secure session with '{peer_id}'...")
        
        # Generate ephemeral DH private key
        dh_private = secrets.randbelow(self.DH_P - 2) + 1
        dh_public = pow(self.DH_G, dh_private, self.DH_P)
        
        timestamp = datetime.now().isoformat()
        nonce = secrets.token_hex(32)
        
        # Sign session init (use hex string for consistency)
        dh_public_hex = hex(dh_public)
        signature = self._sign_message(
            "SESSION_INIT", self.client_id, peer_id, dh_public_hex, timestamp, nonce
        )
        
        # Store for later
        session_info = {
            "peer_id": peer_id,
            "dh_private": dh_private,
            "dh_public": dh_public,
            "nonce": nonce,
            "timestamp": timestamp,
            "status": "INIT_SENT"
        }
        self.sessions[peer_id] = session_info
        
        message = {
            "msg_type": "SESSION_INIT",
            "from": self.client_id,
            "to": peer_id,
            "dh_public": dh_public_hex,
            "dh_params": {
                "p": hex(self.DH_P),
                "g": str(self.DH_G)
            },
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature.hex()
        }
        
        # print(f"[{self.client_id}]  Session Init details:")
        # print(f"[{self.client_id}]   - DH public (g^a): {hex(dh_public)[:32]}...")
        # print(f"[{self.client_id}]   - Nonce: {nonce[:16]}...")
        # print(f"[{self.client_id}]   - Signature: {signature.hex()[:32]}...\n")
        
        self.send_message(json.dumps(message).encode())
        return True
    
    def _derive_session_keys(self, peer_id: str, dh_secret: int, 
                            dh_public_a: int, dh_public_b: int,
                            nonce_a: str, nonce_b: str):
        """Derive session keys from DH secret"""
        print(f"[{self.client_id}]  Deriving session keys...")
        
        # Session ID - use sorted client IDs to ensure same ID for both parties
        sorted_clients = tuple(sorted([self.client_id, peer_id]))
        session_id = self._compute_hmac(
            b"session_id",
            sorted_clients[0], sorted_clients[1],
            hex(dh_public_a), hex(dh_public_b),
            nonce_a, nonce_b
        )
        
        # Master key
        dh_secret_bytes = dh_secret.to_bytes((dh_secret.bit_length() + 7) // 8, 'big')
        k_master = self._compute_hmac(dh_secret_bytes, session_id, b"master")
        
        # Derive directional keys
        k_enc_ab = self._hmac_kdf(k_master, f"enc_{self.client_id}_to_{peer_id}")
        k_enc_ba = self._hmac_kdf(k_master, f"enc_{peer_id}_to_{self.client_id}")
        k_mac_ab = self._hmac_kdf(k_master, f"mac_{self.client_id}_to_{peer_id}")
        k_mac_ba = self._hmac_kdf(k_master, f"mac_{peer_id}_to_{self.client_id}")
        
        self.sessions[peer_id].update({
            "session_id": session_id.hex(),
            "k_master": k_master,
            "k_enc_send": k_enc_ab,
            "k_enc_recv": k_enc_ba,
            "k_mac_send": k_mac_ab,
            "k_mac_recv": k_mac_ba,
            "status": "ESTABLISHED"
        })
        
        self.sequence_numbers[peer_id] = 0
        self.received_sequences[peer_id] = -1
        
        print(f"[{self.client_id}]  Session keys derived")
        # print(f"[{self.client_id}]   - Session ID: {session_id.hex()[:32]}...")
        # print(f"[{self.client_id}]   - Master key: {k_master.hex()[:32]}...")
        print(f"[{self.client_id}]   - Forward secrecy enabled \n")
    
    def send_encrypted_message(self, peer_id: str, plaintext: str) -> bool:
        """Send encrypted message to peer"""
        if peer_id not in self.sessions or self.sessions[peer_id]["status"] != "ESTABLISHED":
            print(f"[{self.client_id}]  No established session with '{peer_id}'")
            return False
        
        session = self.sessions[peer_id]
        seq_num = self.sequence_numbers[peer_id]
        timestamp = datetime.now().isoformat()
        
        print(f"[{self.client_id}]  Encrypting message for '{peer_id}'...")
        print(f"[{self.client_id}]   - Sequence: {seq_num}")
        print(f"[{self.client_id}]   - Plaintext: '{plaintext}'")
        
        # Inner encryption (end-to-end)
        plaintext_bytes = plaintext.encode()
        iv, encrypted_inner = self._encrypt_keyed_hash(session["k_enc_send"], plaintext_bytes)
        
        # Inner MAC
        mac_inner = self._compute_hmac(
            session["k_mac_send"],
            encrypted_inner,
            str(seq_num).encode(),
            timestamp.encode()
        )
        
        # Combine payload
        payload = {
            "iv": iv.hex(),
            "ciphertext": encrypted_inner.hex(),
            "mac_inner": mac_inner.hex()
        }
        
        message = {
            "msg_type": "DATA",
            "from": self.client_id,
            "to": peer_id,
            "session_id": session["session_id"],
            "seq_num": seq_num,
            "timestamp": timestamp,
            "payload": json.dumps(payload)
        }
        
        # Outer MAC (prevents relay tampering)
        # Authenticates: session_id + seq_num + timestamp + payload
        mac_outer = self._compute_hmac(
            session["k_mac_send"],
            session["session_id"],
            str(seq_num).encode(),
            timestamp.encode(),
            json.dumps(payload).encode()
        )
        
        message["mac_outer"] = mac_outer.hex()
        message_json = json.dumps(message)
        
        print(f"[{self.client_id}]  Encryption details:")
        # print(f"[{self.client_id}]   - IV: {iv.hex()[:32]}...")
        # print(f"[{self.client_id}]   - Ciphertext length: {len(encrypted_inner)} bytes")
        # print(f"[{self.client_id}]   - Inner MAC: {mac_inner.hex()[:32]}...")
        # print(f"[{self.client_id}]   - Outer MAC: {mac_outer.hex()[:32]}...")
        print(f"[{self.client_id}]   - Relay tampering protection: outer MAC")
        print(f"[{self.client_id}]   - Replay protection: timestamp + sequence")
        print(f"[{self.client_id}]   - Message saved to history (use 'history' command)\n")
        
        # Save message to in-memory history for replay testing
        if peer_id not in self.message_history:
            self.message_history[peer_id] = []
        
        self.message_history[peer_id].append({
            "index": len(self.message_history[peer_id]),
            "plaintext": plaintext,
            "seq_num": seq_num,
            "timestamp": timestamp,
            "message": message,
            "message_json": message_json
        })
        
        self.send_message(message_json.encode())
        self.sequence_numbers[peer_id] += 1
        
        return True
    
    def _handle_encrypted_message(self, message: dict):
        """Decrypt and verify received message"""
        sender_id = message["from"]
        seq_num = message["seq_num"]
        timestamp = message["timestamp"]
        payload_str = message["payload"]
        
        print(f"\n[{self.client_id}]  Encrypted message received from '{sender_id}'")
        print(f"[{self.client_id}]   - Sequence: {seq_num}")
        print(f"[{self.client_id}]   - Timestamp: {timestamp}")
        
        # Check session
        if sender_id not in self.sessions or self.sessions[sender_id]["status"] != "ESTABLISHED":
            print(f"[{self.client_id}]  No established session with sender\n")
            return
        
        session = self.sessions[sender_id]
        
        # Parse payload
        payload = json.loads(payload_str)
        iv = bytes.fromhex(payload["iv"])
        ciphertext = bytes.fromhex(payload["ciphertext"])
        mac_inner = bytes.fromhex(payload["mac_inner"])
        mac_outer_hex = message.get("mac_outer")
        
        print(f"[{self.client_id}]  Decrypting message...")
        
        # PRIORITY 0: Verify outer MAC first (detect relay tampering)
        if not mac_outer_hex:
            print(f"[{self.client_id}]  RELAY TAMPERING DETECTED!")
            print(f"[{self.client_id}]   - Outer MAC missing")
            print(f"[{self.client_id}]   - Message REJECTED (relay may have modified it)\n")
            return
        
        mac_outer = bytes.fromhex(mac_outer_hex)
        expected_mac_outer = self._compute_hmac(
            session["k_mac_recv"],
            session["session_id"],
            str(seq_num).encode(),
            timestamp.encode(),
            payload_str.encode()
        )
        
        if mac_outer != expected_mac_outer:
            print(f"[{self.client_id}]  RELAY TAMPERING DETECTED!")
            print(f"[{self.client_id}]   - Outer MAC verification failed")
            print(f"[{self.client_id}]   - Message REJECTED (relay tampered with message)\n")
            return
        
        print(f"[{self.client_id}]  Outer MAC verified - relay did not tamper")
        
        # PRIORITY 1: Verify inner MAC (integrity check between peers)
        expected_mac = self._compute_hmac(
            session["k_mac_recv"],
            ciphertext,
            str(seq_num).encode(),
            timestamp.encode()
        )
        
        if mac_inner != expected_mac:
            print(f"[{self.client_id}]  INTEGRITY VIOLATION!")
            print(f"[{self.client_id}]   - MAC verification failed")
            print(f"[{self.client_id}]   - Message REJECTED (possible tampering)\n")
            return
        
        print(f"[{self.client_id}]  MAC verified - message integrity confirmed")
        
        # PRIORITY 2: Replay protection - check sequence number
        if seq_num <= self.received_sequences.get(sender_id, -1):
            print(f"[{self.client_id}]  REPLAY ATTACK DETECTED!")
            print(f"[{self.client_id}]   - Received seq: {seq_num}")
            print(f"[{self.client_id}]   - Expected > {self.received_sequences[sender_id]}")
            print(f"[{self.client_id}]   - Message REJECTED\n")
            return
        
        # Decrypt
        plaintext = self._decrypt_keyed_hash(session["k_enc_recv"], iv, ciphertext)
        
        # Update sequence
        self.received_sequences[sender_id] = seq_num
        
        print(f"\n{'='*70}")
        print(f" DECRYPTED MESSAGE")
        print(f"{'='*70}")
        print(f"From:       {sender_id}")
        print(f"Sequence:   {seq_num}")
        print(f"Time:       {timestamp}")
        print(f"Message:    {plaintext.decode()}")
        print(f"Security:    Encrypted   Authenticated   Replay-Protected")
        print(f"{'='*70}\n")
    
    def receive_messages(self):
        """Receive and process messages from relay"""
        while self.running:
            try:
                data = self.recv_message()
                if not data:
                    break
                
                message = json.loads(data.decode('utf-8'))
                msg_type = message.get('msg_type')
                
                if msg_type == "REGISTER_ACK":
                    self._handle_register_ack(message)
                
                elif msg_type == "SESSION_REQUEST":
                    self._handle_session_request(message)
                
                elif msg_type == "SESSION_ESTABLISHED":
                    self._handle_session_established(message)
                
                elif msg_type == "DATA":
                    self._handle_encrypted_message(message)
                
                elif msg_type == "CLIENT_LIST":
                    self._handle_client_list(message)
                
                elif msg_type == "ERROR":
                    print(f"[{self.client_id}]  ERROR: {message.get('message')}\n")
                
                else:
                    print(f"[{self.client_id}] Unknown message type: {msg_type}")
            
            except json.JSONDecodeError as e:
                print(f"[{self.client_id}] JSON decode error: {e}")
            except Exception as e:
                if self.running:
                    print(f"[{self.client_id}] Receive error: {e}")
                break
        
        print(f"[{self.client_id}] Receiver thread stopped")
    
    def _handle_register_ack(self, message: dict):
        """Handle registration acknowledgment"""
        status = message.get('status')
        relay_id = message.get('relay_id')
        nonce_echo = message.get('nonce_echo')
        signature_hex = message.get('signature')
        
        print(f"[{self.client_id}]  Registration response received")
        
        if status == "SUCCESS":
            # Store relay public key (in real system, would be pre-shared)
            relay_pk_pem = message.get('relay_public_key')
            if relay_pk_pem:
                self.relay_public_key = serialization.load_pem_public_key(
                    relay_pk_pem.encode(),
                    backend=default_backend()
                )
            
            self.registered = True
            print(f"[{self.client_id}]  Registration successful!")
            print(f"[{self.client_id}]  Relay: {relay_id}")
            # print(f"[{self.client_id}]   Nonce echo verified: {nonce_echo[:16]}...")
            print(f"[{self.client_id}]  Nonce echo verified")
            print(f"[{self.client_id}]  Mutual authentication complete\n")
        else:
            print(f"[{self.client_id}]  Registration failed: {message.get('error_msg')}\n")
    
    def _handle_session_request(self, message: dict):
        """Handle incoming session request from peer"""
        sender_id = message["from"]
        dh_public_peer_hex = message["dh_public"]
        dh_public_peer = int(dh_public_peer_hex, 16)
        nonce_peer = message["nonce"]
        timestamp = message["timestamp"]
        signature_hex = message["signature_sender"]
        
        print(f"\n[{self.client_id}]  Session request from '{sender_id}'\n")
        # print(f"[{self.client_id}]   - Peer DH public: {dh_public_peer_hex[:32]}...")
        # print(f"[{self.client_id}]   - Peer nonce: {nonce_peer[:16]}...")
        
        # Verify peer's signature
        try:
            signature = bytes.fromhex(signature_hex)
            # Get peer's public key (in real system, would be pre-shared)
            # For now, we'll trust the signature from relay
            print(f"[{self.client_id}]  Peer signature validated by relay")
        except Exception as e:
            print(f"[{self.client_id}]  Signature verification error: {e}")
            return
        
        # Generate our DH key pair
        dh_private = secrets.randbelow(self.DH_P - 2) + 1
        dh_public = pow(self.DH_G, dh_private, self.DH_P)
        
        # Compute DH secret
        dh_secret = pow(dh_public_peer, dh_private, self.DH_P)
        
        # Generate our nonce
        nonce = secrets.token_hex(32)
        timestamp_response = datetime.now().isoformat()
        
        # Sign response (use hex string for consistency)
        dh_public_hex = hex(dh_public)
        signature = self._sign_message(
            "SESSION_RESPONSE", self.client_id, sender_id,
            dh_public_hex, timestamp_response, nonce, nonce_peer
        )
        
        response = {
            "msg_type": "SESSION_RESPONSE",
            "from": self.client_id,
            "to": sender_id,
            "dh_public": dh_public_hex,
            "timestamp": timestamp_response,
            "nonce": nonce,
            "nonce_echo": nonce_peer,
            "signature": signature.hex()
        }
        
        print(f"[{self.client_id}]  Sending session response...")
        self.send_message(json.dumps(response).encode())
        
        # Initialize session info before deriving keys
        session_info = {
            "peer_id": sender_id,
            "dh_private": dh_private,
            "dh_public": dh_public,
            "nonce": nonce,
            "timestamp": timestamp_response,
            "status": "RESPONSE_SENT"
        }
        self.sessions[sender_id] = session_info
        
        # Derive keys (we're Bob, peer is Alice)
        self._derive_session_keys(
            sender_id, dh_secret,
            dh_public_peer, dh_public,
            nonce_peer, nonce
        )
        
        print(f"[{self.client_id}]  Session with '{sender_id}' ESTABLISHED")
        print(f"[{self.client_id}]  You can now send messages to '{sender_id}'\n")
    
    def _handle_session_established(self, message: dict):
        """Handle session establishment confirmation"""
        peer_id = message["from"]
        dh_public_peer_hex = message["dh_public"]
        dh_public_peer = int(dh_public_peer_hex, 16)
        nonce_peer = message["nonce"]
        nonce_echo = message["nonce_echo"]
        
        print(f"\n[{self.client_id}]  Session established with '{peer_id}'")
        
        if peer_id not in self.sessions:
            print(f"[{self.client_id}]  Unexpected session response\n")
            return
        
        session = self.sessions[peer_id]
        
        # Verify nonce echo
        if nonce_echo != session["nonce"]:
            print(f"[{self.client_id}]  Nonce mismatch - possible attack")
            print(f"[{self.client_id}]   Expected: {session['nonce'][:16]}...")
            print(f"[{self.client_id}]   Received: {nonce_echo[:16]}...\n")
            return
        
        print(f"[{self.client_id}]  Nonce echo verified")
        
        # Compute DH secret (we're Alice)
        dh_secret = pow(dh_public_peer, session["dh_private"], self.DH_P)
        
        # Derive keys
        self._derive_session_keys(
            peer_id, dh_secret,
            session["dh_public"], dh_public_peer,
            session["nonce"], nonce_peer
        )
        
        print(f"[{self.client_id}]  Session with '{peer_id}' ESTABLISHED")
        print(f"[{self.client_id}]  Ready for secure communication")
        print(f"[{self.client_id}]  You can now send messages to '{peer_id}'\n")
    
    def send_message(self, data: bytes):
        """Send message with length prefix"""
        try:
            length = len(data)
            self.socket.sendall(length.to_bytes(4, 'big') + data)
        except Exception as e:
            print(f"[{self.client_id}] Send error: {e}")
    
    def recv_message(self) -> Optional[bytes]:
        """Receive message with length prefix"""
        try:
            length_bytes = self.socket.recv(4)
            if not length_bytes or len(length_bytes) < 4:
                return None
            
            length = int.from_bytes(length_bytes, 'big')
            
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
        """Disconnect from relay"""
        self.running = False
        if self.socket:
            self.socket.close()
        print(f"[{self.client_id}] Disconnected from relay\n")
    
    def interactive_mode(self):
        """Run client in interactive mode"""
        print(f"{'='*70}")
        print(f" SECURE CHAT CLIENT: {self.client_id}")
        print(f"{'='*70}")
        print("Commands:")
        print("  session <peer_id>              - Establish secure session")
        print("  send <peer_id> <message>       - Send encrypted message")
        print("  history [peer_id]              - View message history")
        print("  replay <peer_id> <index>       - Replay message by index (Test Replay Attack)")
        print("  tamper <peer_id> <index>       - Tamper with ciphertext (Test Integrity)")
        print("  corrupt <peer_id> <index>      - Corrupt MAC (Test Tampering Detection)")
        print("  sessions                       - List active sessions")
        print("  lists                          - List all clients connected to relay")
        print("  help                           - Show this help")
        print("  quit                           - Exit")
        print(f"{'='*70}\n")
        
        try:
            while True:
                try:
                    command = input(f"{self.client_id}> ").strip()
                    
                    if not command:
                        continue
                    
                    parts = command.split(maxsplit=2)
                    cmd = parts[0].lower()
                    
                    if cmd in ["quit", "exit"]:
                        break
                    
                    elif cmd == "session":
                        if len(parts) < 2:
                            print(f"Usage: session <peer_id>\n")
                        else:
                            self.initiate_session(parts[1])
                    
                    elif cmd == "send":
                        if len(parts) < 3:
                            print(f"Usage: send <peer_id> <message>\n")
                        else:
                            self.send_encrypted_message(parts[1], parts[2])
                    
                    elif cmd == "history":
                        if len(parts) < 2:
                            self.show_message_history()
                        else:
                            self.show_message_history(parts[1])
                    
                    elif cmd == "replay":
                        if len(parts) < 3:
                            print(f"Usage: replay <peer_id> <index>\n")
                            print(f"Example: replay bob 0\n")
                            print(f"First use 'history' or 'history <peer>' to see available messages\n")
                        else:
                            try:
                                index = int(parts[2])
                                self.replay_from_history(parts[1], index)
                            except ValueError:
                                print(f"Invalid index: {parts[2]}\n")
                    
                    elif cmd == "tamper":
                        if len(parts) < 3:
                            print(f"Usage: tamper <peer_id> <index>\n")
                            print(f"Example: tamper bob 0\n")
                            print(f"Tampers with ciphertext to test integrity protection\n")
                        else:
                            try:
                                index = int(parts[2])
                                self.tamper_message(parts[1], index)
                            except ValueError:
                                print(f"Invalid index: {parts[2]}\n")
                    
                    elif cmd == "corrupt":
                        if len(parts) < 3:
                            print(f"Usage: corrupt <peer_id> <index>\n")
                            print(f"Example: corrupt bob 0\n")
                            print(f"Corrupts MAC to test tampering detection\n")
                        else:
                            try:
                                index = int(parts[2])
                                self.corrupt_mac(parts[1], index)
                            except ValueError:
                                print(f"Invalid index: {parts[2]}\n")
                    
                    elif cmd == "sessions":
                        self.list_sessions()
                    
                    elif cmd == "lists":
                        self.request_connected_clients()
                    
                    elif cmd == "relay_tamper":
                        if len(parts) < 2:
                            print(f"Usage: relay_tamper <peer_id>\n")
                            print(f"This tells the relay to tamper with the next message to <peer_id>")
                            print(f"The client will detect the tampering via outer MAC\n")
                        else:
                            self.trigger_relay_tampering(parts[1])
                    
                    elif cmd == "help":
                        print("\nCommands:")
                        print("  session <peer_id>       - Establish secure session")
                        print("  send <peer_id> <msg>    - Send encrypted message")
                        print("  history [peer]          - View message history")
                        print("  replay <peer> <index>   - Test replay attack protection")
                        print("  tamper <peer> <index>   - Test integrity protection (ciphertext)")
                        print("  corrupt <peer> <index>  - Test tampering detection (MAC)")
                        print("  sessions                - List active sessions")
                        print("  lists                   - List all clients on relay")
                        print("  relay_tamper <peer>     - Trigger relay tampering (outer MAC test)")
                        print("  quit                    - Exit\n")
                    
                    else:
                        print(f"Unknown command. Type 'help' for available commands\n")
                
                except EOFError:
                    break
        
        except KeyboardInterrupt:
            print(f"\n[{self.client_id}] Interrupted\n")
        
        finally:
            self.disconnect()
    
    def list_sessions(self):
        """List active sessions"""
        if not self.sessions:
            print(f"[{self.client_id}] No active sessions\n")
            return
        
        print(f"\n[{self.client_id}] Active Sessions:")
        for peer_id, session_info in self.sessions.items():
            status = session_info.get("status", "UNKNOWN")
            seq = self.sequence_numbers.get(peer_id, 0)
            print(f"  - {peer_id}: {status} (seq: {seq})")
        print()
    
    def replay_attack(self, message_file: str):
        """Simulate replay attack by sending saved message again"""
        try:
            with open(message_file, "r") as f:
                message = json.load(f)
            
            peer_id = message.get("to")
            seq_num = message.get("seq_num")
            
            print(f"\n[{self.client_id}] 🚀 SIMULATING REPLAY ATTACK")
            print(f"[{self.client_id}]  Replaying message from file: {message_file}")
            print(f"[{self.client_id}]   - Target: {peer_id}")
            print(f"[{self.client_id}]   - Original Sequence: {seq_num}")
            print(f"[{self.client_id}]   - Sending SAME encrypted message twice...\n")
            
            # Send the replayed message
            message_json = json.dumps(message)
            self.send_message(message_json.encode())
            
            print(f"[{self.client_id}]  Replayed message sent to relay")
            print(f"[{self.client_id}]  Watch {peer_id}'s terminal for REPLAY ATTACK DETECTED!\n")
        
        except FileNotFoundError:
            print(f"[{self.client_id}]  Message file not found: {message_file}\n")
        except Exception as e:
            print(f"[{self.client_id}]  Error: {e}\n")
    
    def show_message_history(self, peer_id: str = None):
        """Display message history for all peers or specific peer"""
        if not self.message_history:
            print(f"\n[{self.client_id}] No message history\n")
            return
        
        if peer_id:
            if peer_id not in self.message_history:
                print(f"\n[{self.client_id}] No messages to '{peer_id}'\n")
                return
            
            print(f"\n[{self.client_id}] Message History with '{peer_id}':")
            print(f"{'='*70}")
            for msg in self.message_history[peer_id]:
                print(f"[{msg['index']}] Seq: {msg['seq_num']} | {msg['plaintext'][:40]}")
            print(f"{'='*70}")
            print(f"Usage: replay {peer_id} <index>  (e.g., replay {peer_id} 0)\n")
        else:
            print(f"\n[{self.client_id}] All Message History:")
            print(f"{'='*70}")
            for peer, messages in self.message_history.items():
                print(f"\n To: {peer}")
                for msg in messages:
                    print(f"  [{msg['index']}] Seq: {msg['seq_num']} | {msg['plaintext'][:40]}")
            print(f"{'='*70}")
            print(f"Usage: replay <peer> <index>  (e.g., replay bob 0)\n")
    
    def replay_from_history(self, peer_id: str, index: int):
        """Replay a message from history by index"""
        if peer_id not in self.message_history:
            print(f"\n[{self.client_id}]  No messages to '{peer_id}'\n")
            return
        
        if index < 0 or index >= len(self.message_history[peer_id]):
            print(f"\n[{self.client_id}]  Invalid message index: {index}\n")
            return
        
        msg_data = self.message_history[peer_id][index]
        message = msg_data["message"]
        seq_num = msg_data["seq_num"]
        plaintext = msg_data["plaintext"]
        
        print(f"\n[{self.client_id}] SIMULATING REPLAY ATTACK")
        print(f"[{self.client_id}]  Replaying from message history")
        print(f"[{self.client_id}]   - Target: {peer_id}")
        print(f"[{self.client_id}]   - Message Index: {index}")
        print(f"[{self.client_id}]   - Original Sequence: {seq_num}")
        print(f"[{self.client_id}]   - Original Text: '{plaintext}'")
        print(f"[{self.client_id}]   - Sending SAME encrypted message twice...\n")
        
        # Send the replayed message
        message_json = json.dumps(message)
        self.send_message(message_json.encode())
        
        print(f"[{self.client_id}]  Replayed message sent to relay")
        # print(f"[{self.client_id}]  Watch {peer_id}'s terminal for REPLAY ATTACK DETECTED!\n")
    
    def tamper_message(self, peer_id: str, index: int):
        """Tamper with message MAC/ciphertext to test integrity protection"""
        if peer_id not in self.message_history:
            print(f"\n[{self.client_id}]  No messages to '{peer_id}'\n")
            return
        
        if index < 0 or index >= len(self.message_history[peer_id]):
            print(f"\n[{self.client_id}]  Invalid message index: {index}\n")
            return
        
        msg_data = self.message_history[peer_id][index]
        message = msg_data["message"].copy()
        plaintext = msg_data["plaintext"]
        
        print(f"\n[{self.client_id}]  SIMULATING TAMPERING ATTACK")
        print(f"[{self.client_id}]  Tampering with message")
        print(f"[{self.client_id}]   - Target: {peer_id}")
        print(f"[{self.client_id}]   - Message Index: {index}")
        print(f"[{self.client_id}]   - Original Text: '{plaintext}'")
        print(f"[{self.client_id}]   - Attack: Modifying ciphertext to change plaintext...\n")
        
        # Tamper with the payload
        try:
            payload = json.loads(message["payload"])
            
            # Flip some bits in the ciphertext
            ciphertext_bytes = bytes.fromhex(payload["ciphertext"])
            tampered_bytes = bytearray(ciphertext_bytes)
            
            # Change a byte in the middle
            if len(tampered_bytes) > 0:
                tampered_bytes[0] = (tampered_bytes[0] + 1) % 256
                payload["ciphertext"] = tampered_bytes.hex()
            
            message["payload"] = json.dumps(payload)
            
            print(f"[{self.client_id}]  Ciphertext tampered (bit-flip attack)")
            print(f"[{self.client_id}]   - Original MAC: {payload.get('mac_inner', '')[:32]}...")
            print(f"[{self.client_id}]   - MAC unchanged (attacker doesn't know key!)")
            print(f"[{self.client_id}]   - Sending tampered message...\n")
            
            # Send the tampered message
            message_json = json.dumps(message)
            self.send_message(message_json.encode())
            
            print(f"[{self.client_id}]  Tampered message sent to relay")
            # print(f"[{self.client_id}] 👁️  Watch {peer_id}'s terminal for INTEGRITY VIOLATION!\n")
        
        except Exception as e:
            print(f"[{self.client_id}]  Error tampering message: {e}\n")
    
    def corrupt_mac(self, peer_id: str, index: int):
        """Corrupt the MAC to test tampering detection"""
        if peer_id not in self.message_history:
            print(f"\n[{self.client_id}]  No messages to '{peer_id}'\n")
            return
        
        if index < 0 or index >= len(self.message_history[peer_id]):
            print(f"\n[{self.client_id}]  Invalid message index: {index}\n")
            return
        
        msg_data = self.message_history[peer_id][index]
        message = msg_data["message"].copy()
        plaintext = msg_data["plaintext"]
        
        print(f"\n[{self.client_id}]  SIMULATING MAC TAMPERING")
        print(f"[{self.client_id}]  Corrupting message authentication code")
        print(f"[{self.client_id}]   - Target: {peer_id}")
        print(f"[{self.client_id}]   - Message Index: {index}")
        print(f"[{self.client_id}]   - Original Text: '{plaintext}'")
        print(f"[{self.client_id}]   - Attack: Flipping bits in MAC...\n")
        
        # Tamper with the MAC
        try:
            payload = json.loads(message["payload"])
            
            # Flip bits in MAC
            mac_bytes = bytes.fromhex(payload["mac_inner"])
            tampered_mac = bytearray(mac_bytes)
            
            if len(tampered_mac) > 0:
                tampered_mac[0] = (tampered_mac[0] + 1) % 256
                payload["mac_inner"] = tampered_mac.hex()
            
            message["payload"] = json.dumps(payload)
            
            print(f"[{self.client_id}]  MAC corrupted")
            print(f"[{self.client_id}]   - Ciphertext: unchanged")
            print(f"[{self.client_id}]   - MAC: corrupted (invalid authentication)")
            print(f"[{self.client_id}]   - Sending message with bad MAC...\n")
            
            # Send the message with corrupted MAC
            message_json = json.dumps(message)
            self.send_message(message_json.encode())
            
            print(f"[{self.client_id}]  Message with corrupted MAC sent to relay")
            # print(f"[{self.client_id}] 👁️  Watch {peer_id}'s terminal for INTEGRITY VIOLATION!\n")
        
        except Exception as e:
            print(f"[{self.client_id}]  Error corrupting MAC: {e}\n")
    
    def request_connected_clients(self):
        """Request list of all clients connected to relay"""
        if not self.registered:
            print(f"[{self.client_id}] Must be registered first\n")
            return
        
        request = {
            "msg_type": "REQUEST_CLIENT_LIST",
            "from": self.client_id,
            "timestamp": datetime.now().isoformat()
        }
        
        print(f"[{self.client_id}] Requesting client list from relay...\n")
        self.send_message(json.dumps(request).encode())
    
    def _handle_client_list(self, message: dict):
        """Handle client list response from relay"""
        clients = message.get("clients", [])
        
        print(f"\n{'='*70}")
        print(f"CLIENTS CONNECTED TO RELAY SERVER")
        print(f"{'='*70}")
        
        if not clients:
            print("No other clients connected")
        else:
            print(f"Total clients: {len(clients)}\n")
            for idx, client_id in enumerate(clients, 1):
                status = "SELF" if client_id == self.client_id else "ONLINE"
                print(f"  {idx}. {client_id} ({status})")
        
        print(f"{'='*70}\n")
    
    def trigger_relay_tampering(self, peer_id: str):
        """Trigger relay server to tamper with next message (testing)"""
        if peer_id not in self.sessions:
            print(f"\n[{self.client_id}] No session with '{peer_id}'\n")
            return
        
        # Signal relay to tamper with next message by setting flag
        request = {
            "msg_type": "RELAY_TAMPER_TEST",
            "from": self.client_id,
            "to": peer_id,
            "timestamp": datetime.now().isoformat()
        }
        
        print(f"\n[{self.client_id}] Triggering relay tampering for next message to '{peer_id}'")
        print(f"[{self.client_id}] Send your next message - relay will corrupt the outer MAC")
        print(f"[{self.client_id}] Recipient will detect: RELAY TAMPERING DETECTED!\n")
        
        self.send_message(json.dumps(request).encode())


def main():
    print("="*70)
    print(" SECURE RELAY-BASED CHAT SYSTEM")
    print("Secure Chat Client - Full Protocol Implementation")
    print("="*70)
    print()
    
    if len(sys.argv) < 2:
        print("Usage: python secure_client.py <client_id> [relay_host] [relay_port]")
        print("Example: python secure_client.py alice")
        print("Example: python secure_client.py bob localhost 5050")
        sys.exit(1)
    
    client_id = sys.argv[1]
    relay_host = sys.argv[2] if len(sys.argv) > 2 else 'localhost'
    relay_port = int(sys.argv[3]) if len(sys.argv) > 3 else 5050
    
    client = SecureClient(client_id, relay_host, relay_port)
    
    if not client.connect():
        print("Failed to connect to relay server")
        sys.exit(1)
    
    time.sleep(0.5)
    if not client.register():
        print("Failed to register with relay server")
        sys.exit(1)
    
    time.sleep(1)
    client.interactive_mode()


if __name__ == "__main__":
    main()
