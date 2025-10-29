"""
Automated Demo and Testing Script for Deliverable 1
Tests basic functionality of the relay-based chat system
"""

import subprocess
import time
import sys
import os
from threading import Thread


def print_section(title):
    """Print a formatted section header"""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def run_relay_server():
    """Run the relay server in a subprocess"""
    print_section("Starting Relay Server")
    
    try:
        process = subprocess.Popen(
            [sys.executable, "relay_server.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        time.sleep(2)  # Give server time to start
        
        if process.poll() is None:
            print("✓ Relay server started successfully")
            print(f"  PID: {process.pid}")
            return process
        else:
            print("✗ Relay server failed to start")
            return None
    
    except Exception as e:
        print(f"✗ Error starting relay server: {e}")
        return None


def test_client_registration():
    """Test client registration"""
    print_section("TEST 1: Client Registration")
    
    print("Starting client 'alice'...")
    
    # Create test script for alice
    test_script = """
import sys
import time
sys.path.insert(0, '.')
from client import Client

client = Client('alice', 'localhost', 5000)
if client.connect():
    time.sleep(0.5)
    if client.register():
        print("TEST_PASS: Registration successful")
        time.sleep(1)
        client.disconnect()
    else:
        print("TEST_FAIL: Registration failed")
else:
    print("TEST_FAIL: Connection failed")
"""
    
    try:
        result = subprocess.run(
            [sys.executable, "-c", test_script],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if "TEST_PASS" in result.stdout:
            print("✓ PASSED: Client registration works")
            return True
        else:
            print("✗ FAILED: Client registration failed")
            print(f"Output: {result.stdout}")
            print(f"Error: {result.stderr}")
            return False
    
    except Exception as e:
        print(f"✗ FAILED: Exception during test: {e}")
        return False


def test_message_forwarding():
    """Test message forwarding between two clients"""
    print_section("TEST 2: Message Forwarding")
    
    print("Starting clients 'alice' and 'bob'...")
    
    # Script for alice (sender)
    alice_script = """
import sys
import time
sys.path.insert(0, '.')
from client import Client

client = Client('alice', 'localhost', 5000)
if client.connect():
    time.sleep(0.5)
    client.register()
    time.sleep(2)  # Wait for bob to register
    
    # Send message to bob
    client.send_chat_message('bob', 'Hello Bob from automated test!')
    time.sleep(2)
    client.disconnect()
    print("TEST_ALICE_COMPLETE")
"""
    
    # Script for bob (receiver)
    bob_script = """
import sys
import time
sys.path.insert(0, '.')
from client import Client

received_message = False

original_handle = Client.handle_incoming_message

def patched_handle(self, message):
    global received_message
    original_handle(self, message)
    if message.get('from') == 'alice':
        received_message = True
        print("TEST_BOB_RECEIVED_MESSAGE")

Client.handle_incoming_message = patched_handle

client = Client('bob', 'localhost', 5000)
if client.connect():
    time.sleep(0.5)
    client.register()
    time.sleep(5)  # Wait for message
    client.disconnect()
    
    if received_message:
        print("TEST_PASS: Message received")
    else:
        print("TEST_FAIL: Message not received")
"""
    
    try:
        # Start bob first
        bob_process = subprocess.Popen(
            [sys.executable, "-c", bob_script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        time.sleep(1)
        
        # Start alice
        alice_result = subprocess.run(
            [sys.executable, "-c", alice_script],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # Wait for bob
        bob_result, _ = bob_process.communicate(timeout=10)
        
        alice_ok = "TEST_ALICE_COMPLETE" in alice_result.stdout
        bob_ok = "TEST_PASS" in bob_result
        
        if alice_ok and bob_ok:
            print("✓ PASSED: Message forwarding works")
            print("  Alice sent message successfully")
            print("  Bob received message successfully")
            return True
        else:
            print("✗ FAILED: Message forwarding failed")
            if not alice_ok:
                print("  Alice did not complete")
            if not bob_ok:
                print("  Bob did not receive message")
            return False
    
    except Exception as e:
        print(f"✗ FAILED: Exception during test: {e}")
        return False


def test_multiple_clients():
    """Test multiple concurrent clients"""
    print_section("TEST 3: Multiple Concurrent Clients")
    
    print("Starting 3 clients simultaneously...")
    
    client_script = """
import sys
import time
sys.path.insert(0, '.')
from client import Client

client_id = sys.argv[1]
client = Client(client_id, 'localhost', 5000)
if client.connect():
    time.sleep(0.5)
    if client.register():
        print(f"TEST_PASS_{client_id}: Registration successful")
        time.sleep(2)
        client.disconnect()
    else:
        print(f"TEST_FAIL_{client_id}: Registration failed")
else:
    print(f"TEST_FAIL_{client_id}: Connection failed")
"""
    
    try:
        processes = []
        client_ids = ['alice', 'bob', 'charlie']
        
        # Start all clients
        for client_id in client_ids:
            process = subprocess.Popen(
                [sys.executable, "-c", client_script, client_id],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            processes.append((client_id, process))
            time.sleep(0.3)
        
        # Wait for all to complete
        results = []
        for client_id, process in processes:
            stdout, stderr = process.communicate(timeout=10)
            results.append((client_id, "TEST_PASS" in stdout))
        
        # Check results
        all_passed = all(passed for _, passed in results)
        
        if all_passed:
            print("✓ PASSED: Multiple concurrent clients work")
            for client_id, _ in results:
                print(f"  {client_id}: ✓ registered successfully")
            return True
        else:
            print("✗ FAILED: Some clients failed")
            for client_id, passed in results:
                status = "✓" if passed else "✗"
                print(f"  {client_id}: {status}")
            return False
    
    except Exception as e:
        print(f"✗ FAILED: Exception during test: {e}")
        return False


def test_invalid_recipient():
    """Test sending message to non-existent recipient"""
    print_section("TEST 4: Invalid Recipient Handling")
    
    print("Testing message to non-existent client...")
    
    test_script = """
import sys
import time
sys.path.insert(0, '.')
from client import Client

error_received = False

original_handle = Client.handle_error

def patched_handle(self, message):
    global error_received
    original_handle(self, message)
    if 'not found' in message.get('message', '').lower():
        error_received = True
        print("TEST_ERROR_RECEIVED")

Client.handle_error = patched_handle

client = Client('alice', 'localhost', 5000)
if client.connect():
    time.sleep(0.5)
    client.register()
    time.sleep(1)
    
    # Send to non-existent client
    client.send_chat_message('nonexistent_user', 'Test message')
    time.sleep(2)
    
    if error_received:
        print("TEST_PASS: Error handling works")
    else:
        print("TEST_FAIL: No error received")
    
    client.disconnect()
"""
    
    try:
        result = subprocess.run(
            [sys.executable, "-c", test_script],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if "TEST_PASS" in result.stdout:
            print("✓ PASSED: Invalid recipient error handling works")
            return True
        else:
            print("✗ FAILED: Error not properly handled")
            return False
    
    except Exception as e:
        print(f"✗ FAILED: Exception during test: {e}")
        return False


def run_all_tests():
    """Run all automated tests"""
    print("\n" + "="*70)
    print("  DELIVERABLE 1 - AUTOMATED TESTING SUITE")
    print("  Secure Relay-Based Chat System")
    print("="*70)
    
    # Start relay server
    relay_process = run_relay_server()
    
    if not relay_process:
        print("\n✗ Cannot proceed without relay server")
        return
    
    try:
        # Run tests
        results = []
        
        time.sleep(1)
        results.append(("Client Registration", test_client_registration()))
        
        time.sleep(1)
        results.append(("Message Forwarding", test_message_forwarding()))
        
        time.sleep(1)
        results.append(("Multiple Clients", test_multiple_clients()))
        
        time.sleep(1)
        results.append(("Invalid Recipient", test_invalid_recipient()))
        
        # Summary
        print_section("TEST SUMMARY")
        
        total = len(results)
        passed = sum(1 for _, result in results if result)
        failed = total - passed
        
        for test_name, result in results:
            status = "✓ PASS" if result else "✗ FAIL"
            print(f"{status}: {test_name}")
        
        print(f"\nTotal: {total} | Passed: {passed} | Failed: {failed}")
        
        if passed == total:
            print("\n🎉 All tests PASSED! System ready for Deliverable 1 submission.")
        else:
            print(f"\n⚠️  {failed} test(s) FAILED. Please review the output above.")
    
    finally:
        # Cleanup
        print_section("Cleanup")
        print("Stopping relay server...")
        relay_process.terminate()
        relay_process.wait(timeout=5)
        print("✓ Relay server stopped")


def interactive_demo():
    """Run interactive demonstration"""
    print("\n" + "="*70)
    print("  DELIVERABLE 1 - INTERACTIVE DEMONSTRATION")
    print("  Secure Relay-Based Chat System")
    print("="*70)
    
    print("\nThis demo requires 3 terminal windows:")
    print("  Terminal 1: python relay_server.py")
    print("  Terminal 2: python client.py alice")
    print("  Terminal 3: python client.py bob")
    print("\nAfter starting all terminals:")
    print("  1. Both clients will auto-register")
    print("  2. In alice's terminal: send bob Hello Bob!")
    print("  3. In bob's terminal: send alice Hi Alice!")
    print("  4. Type 'list' in any terminal to see registered clients")
    print("  5. Type 'quit' to exit")
    print("\nPress Enter to continue or Ctrl+C to exit...")
    
    try:
        input()
    except KeyboardInterrupt:
        print("\n\nDemo cancelled.")
        return


if __name__ == "__main__":
    print("DELIVERABLE 1 - Demo & Testing Tool")
    print("\nOptions:")
    print("  1. Run automated tests")
    print("  2. Show interactive demo instructions")
    print("  3. Exit")
    
    try:
        choice = input("\nEnter choice (1-3): ").strip()
        
        if choice == "1":
            run_all_tests()
        elif choice == "2":
            interactive_demo()
        else:
            print("Exiting...")
    
    except KeyboardInterrupt:
        print("\n\nExiting...")