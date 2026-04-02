#!/usr/bin/env python3
"""
BB84 QKD System - Simplified Test Runner
Executes key test cases and generates clear results
"""

import sys
import os
import time
import hashlib
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ''))

from app.services.bb84_engine import BB84Engine
from app.services.crypto_service import CryptoService, EncryptedFile, EncryptedMessage
from app.services.eve_module import EveModule

# Terminal colors
GREEN = '\033[92m'
RED = '\033[91m'
BLUE = '\033[94m'
RESET = '\033[0m'
BOLD = '\033[1m'

class TestRunner:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        
    def print_test(self, test_num, name):
        print(f"\n{BLUE}{BOLD}[Test {test_num}] {name}{RESET}")
        print(f"{BLUE}{'─'*70}{RESET}")
        
    def result(self, passed, message, details=""):
        status = f"{GREEN}✓ PASS{RESET}" if passed else f"{RED}✗ FAIL{RESET}"
        print(f"  {status} - {message}")
        if details:
            print(f"       {details}")
        if passed:
            self.passed += 1
        else:
            self.failed += 1
        return passed
        
    def summary(self):
        total = self.passed + self.failed
        rate = (self.passed / total * 100) if total > 0 else 0
        print(f"\n{BOLD}{'═'*70}{RESET}")
        print(f"{BOLD}RESULTS: {self.passed}/{total} tests passed ({rate:.0f}%){RESET}")
        print(f"{BOLD}{'═'*70}{RESET}\n")


def test_1_privacy_amplification(runner):
    """Test SHA-256 privacy amplification"""
    runner.print_test(1, "Privacy Amplification (SHA-256)")
    
    try:
        bb84 = BB84Engine()
        test_bits = [1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1]
        key = bb84._privacy_amplification(test_bits)
        
        # Check output is 32 bytes
        runner.result(len(key) == 32, "Output is 32 bytes", f"Got {len(key)} bytes")
        
        # Check determinism
        key2 = bb84._privacy_amplification(test_bits)
        runner.result(key == key2, "Deterministic (same input → same output)")
        
        # Check avalanche effect
        test_bits_diff = test_bits[:]
        test_bits_diff[-1] = 0 if test_bits_diff[-1] == 1 else 1
        key3 = bb84._privacy_amplification(test_bits_diff) 
        runner.result(key != key3, "Avalanche effect (different input → different output)")
        
    except Exception as e:
        runner.result(False, f"Exception: {str(e)}")


def test_2_hkdf_derivation(runner):
    """Test HKDF key derivation"""
    runner.print_test(2, "HKDF Key Derivation")
    
    try:
        crypto = CryptoService()
        master_key = hashlib.sha256(b"test_master_key").digest()
        derived = crypto.derive_keys(master_key, "SESSION-001")
        
        # Check all keys are 32 bytes
        keys = [derived.key_stream_seed, derived.key_mac, derived.key_file]
        all_32 = all(len(k) == 32 for k in keys)
        runner.result(all_32, "All derived keys are 32 bytes")
        
        # Check all keys are different
        all_different = len(set(keys)) == len(keys)
        runner.result(all_different, "Message key ≠ MAC key ≠ File key")
        
    except Exception as e:
        runner.result(False, f"Exception: {str(e)}")


def test_3_session_isolation(runner):
    """Test session isolation"""
    runner.print_test(3, "Session Isolation")
    
    try:
        crypto1, crypto2 = CryptoService(), CryptoService()
        master_key = hashlib.sha256(b"shared_master").digest()
        
        keys1 = crypto1.derive_keys(master_key, "SESSION-A")
        keys2 = crypto2.derive_keys(master_key, "SESSION-B")
        
        different = keys1.key_stream_seed != keys2.key_stream_seed
        runner.result(different, "Different sessions produce different keys",
                     "Prevents cross-session replay attacks")
        
    except Exception as e:
        runner.result(False, f"Exception: {str(e)}")


def test_4_file_encryption(runner):
    """Test file encryption/decryption"""
    runner.print_test(4, "File Encryption (XChaCha20-Poly1305)")
    
    try:
        crypto = CryptoService()
        master_key = hashlib.sha256(b"file_test_key").digest()
        crypto.derive_keys(master_key, "FILE-SESSION")
        
        original_data = b"Hello World! Testing BB84 QKD file encryption..."
        filename = "test.txt"
        
        # Encrypt
        start = time.time()
        encrypted = crypto.encrypt_file_xchacha20(original_data, filename)
        encrypt_ms = (time.time() - start) * 1000
        
        # Check encrypted components
        runner.result(len(encrypted.nonce) == 24, "Nonce is 24 bytes")
        runner.result(len(encrypted.ciphertext) > len(original_data), 
                     "Ciphertext includes auth tag")
        
        # Decrypt
        start = time.time()
        decrypted_data, decrypted_name = crypto.decrypt_file_xchacha20(encrypted)
        decrypt_ms = (time.time() - start) * 1000
        
        # Verify
        runner.result(decrypted_data == original_data, "Decrypted data matches original")
        runner.result(decrypted_name == filename, "Filename preserved",
                     f"Encrypt: {encrypt_ms:.2f}ms, Decrypt: {decrypt_ms:.2f}ms")
        
    except Exception as e:
        runner.result(False, f"Exception: {str(e)}")


def test_5_file_tampering_detection(runner):
    """Test file tampering detection"""
    runner.print_test(5, "File Tampering Detection")
    
    try:
        crypto = CryptoService()
        master_key = hashlib.sha256(b"tamper_test").digest()
        crypto.derive_keys(master_key, "TAMPER-SESSION")
        
        original_data = b"Important document content"
        encrypted = crypto.encrypt_file_xchacha20(original_data, "document.pdf")
        
        # TAMPER: Flip one bit in ciphertext
        tampered_ct = bytearray(encrypted.ciphertext)
        tampered_ct[10] ^= 0xFF
        
        tampered = EncryptedFile(
            ciphertext=bytes(tampered_ct),
            nonce=encrypted.nonce,
            aad=encrypted.aad,
            filename=encrypted.filename,
            file_seq_no=encrypted.file_seq_no,
            session_id=encrypted.session_id
        )
        
        # Try to decrypt
        detected = False
        try:
            crypto.decrypt_file_xchacha20(tampered)
        except:
            detected = True
        
        runner.result(detected, "Tampering detected by Poly1305 tag",
                     "Modified ciphertext rejected")
        
    except Exception as e:
        runner.result(False, f"Exception: {str(e)}")


def test_6_message_encryption(runner):
    """Test message encryption"""
    runner.print_test(6, "Message Encryption (OTP + HMAC)")
    
    try:
        crypto = CryptoService()
        master_key = hashlib.sha256(b"message_key").digest()
        crypto.derive_keys(master_key, "MSG-SESSION")
        
        original = "Secret message from Alice to Bob! 🔐"
        
        # Encrypt
        encrypted = crypto.encrypt_message_otp(original)
        runner.result(len(encrypted.hmac_tag) == 32, "HMAC tag is 32 bytes (SHA3-256)")
        
        # Decrypt
        decrypted = crypto.decrypt_message_otp(encrypted)
        runner.result(decrypted == original, "Decrypted message matches original",
                     f"Message: '{original}'")
        
    except Exception as e:
        runner.result(False, f"Exception: {str(e)}")


def test_7_message_tampering_detection(runner):
    """Test message tampering detection"""
    runner.print_test(7, "Message Tampering Detection")
    
    try:
        crypto = CryptoService()
        master_key = hashlib.sha256(b"integrity_key").digest()
        crypto.derive_keys(master_key, "INTEGRITY-SESSION")
        
        original = "Transfer $100"
        encrypted = crypto.encrypt_message_otp(original)
        
        # TAMPER: Modify ciphertext
        tampered = EncryptedMessage(
            ciphertext=b"TAMPERED" + encrypted.ciphertext[8:],
            hmac_tag=encrypted.hmac_tag,  # Keep original HMAC
            seq_no=encrypted.seq_no,
            timestamp=encrypted.timestamp,
            session_id=encrypted.session_id
        )
        
        # Try to decrypt
        detected = False
        try:
            crypto.decrypt_message_otp(tampered)
        except:
            detected = True
        
        runner.result(detected, "Message tampering detected by HMAC",
                     "Modified message rejected")
        
    except Exception as e:
        runner.result(False, f"Exception: {str(e)}")


def test_8_unique_nonces(runner):
    """Test unique nonce generation"""
    runner.print_test(8, "Unique Nonce Generation")
    
    try:
        crypto = CryptoService()
        master_key = hashlib.sha256(b"nonce_test").digest()
        crypto.derive_keys(master_key, "NONCE-SESSION")
        
        nonces = []
        for i in range(100):
            encrypted = crypto.encrypt_file_xchacha20(f"Test{i}".encode(), f"file{i}.txt")
            nonces.append(encrypted.nonce)
        
        unique_nonces = len(set(nonces))
        runner.result(unique_nonces == 100, f"All {unique_nonces}/100 nonces are unique",
                     "No collisions detected")
        
    except Exception as e:
        runner.result(False, f"Exception: {str(e)}")


def test_9_bb84_sifting(runner):
    """Test BB84 sifting logic"""
    runner.print_test(9, "BB84 Sifting Logic")
    
    try:
        bb84 = BB84Engine()
        
        # Simulate Alice and Bob data
        alice_bits = [1, 0, 1, 0, 1, 1, 0, 0]
        alice_bases = [0, 0, 1, 1, 0, 1, 0, 1]
        bob_bases = [0, 1, 1, 0, 0, 1, 1, 1]
        bob_results = [1, 0, 1, 1, 1, 1, 0, 0]
        
        sifted_alice, sifted_bob, indices = bb84._sifting(
            alice_bits, alice_bases, bob_bases, bob_results
        )
        
        # Expected matching bases at indices: 0, 2, 4, 5, 7
        expected_length = 5
        runner.result(len(sifted_alice) == expected_length, 
                     f"Sifted {len(sifted_alice)} bits (expected ~{expected_length})")
        
        # Check sifted keys match
        runner.result(sifted_alice == sifted_bob, "Sifted keys match (no Eve)")
        
    except Exception as e:
        runner.result(False, f"Exception: {str(e)}")


def test_10_qber_calculation(runner):
    """Test QBER calculation"""
    runner.print_test(10, "QBER Calculation")
    
    try:
        bb84 = BB84Engine()
        
        # Perfect match (0% error)
        alice_bits = [1, 0, 1, 1, 0, 1, 0, 0, 1, 1]
        bob_bits = [1, 0, 1, 1, 0, 1, 0, 0, 1, 1]
        test_pos, qber = bb84._compute_qber(alice_bits, bob_bits, 0.5)
        
        runner.result(qber == 0.0, f"QBER with perfect match: {qber:.1%}",
                     "Expected 0%")
        
        # With errors (20% error)
        bob_bits_with_errors = [1, 0, 1, 1, 0, 1, 0, 0, 0, 0]  # Last 2 flipped
        test_pos, qber = bb84._compute_qber(alice_bits, bob_bits_with_errors, 1.0)
        
        runner.result(qber == 0.2, f"QBER with 2/10 errors: {qber:.1%}",
                     "Expected 20%")
        
    except Exception as e:
        runner.result(False, f"Exception: {str(e)}")


def main():
    print(f"\n{BOLD}{BLUE}")
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║        BB84 QKD SYSTEM - TEST EXECUTION RESULTS                      ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print(f"{RESET}")
    
    runner = TestRunner()
    start = time.time()
    
    # Run tests
    test_1_privacy_amplification(runner)
    test_2_hkdf_derivation(runner)
    test_3_session_isolation(runner)
    test_4_file_encryption(runner)
    test_5_file_tampering_detection(runner)
    test_6_message_encryption(runner)
    test_7_message_tampering_detection(runner)
    test_8_unique_nonces(runner)
    test_9_bb84_sifting(runner)
    test_10_qber_calculation(runner)
    
    runner.summary()
    
    elapsed = time.time() - start
    print(f"Execution time: {elapsed:.2f}s")
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    sys.exit(0 if runner.failed == 0 else 1)


if __name__ == "__main__":
    main()
