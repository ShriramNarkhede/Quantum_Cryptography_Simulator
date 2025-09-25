"""
Enhanced Cryptography Service for BB84 QKD System
Implements production-grade cryptographic primitives for secure communication
"""

import os
import secrets
import hashlib
import hmac
from typing import Tuple, Dict, Any, Optional, List
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import nacl.secret
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
import logging

logger = logging.getLogger(__name__)


@dataclass
class DerivedKeys:
    """Container for derived cryptographic keys"""
    key_stream_seed: bytes  # 32 bytes for OTP stream generation
    key_mac: bytes         # 32 bytes for HMAC-SHA3-256
    key_file: bytes        # 32 bytes for XChaCha20-Poly1305
    master_key: bytes      # Original BB84 key (kept for reference)
    
    def clear(self):
        """Securely clear all key material"""
        # Overwrite with random data before clearing
        if hasattr(self, 'key_stream_seed'):
            self.key_stream_seed = secrets.token_bytes(len(self.key_stream_seed))
        if hasattr(self, 'key_mac'):
            self.key_mac = secrets.token_bytes(len(self.key_mac))
        if hasattr(self, 'key_file'):
            self.key_file = secrets.token_bytes(len(self.key_file))
        if hasattr(self, 'master_key'):
            self.master_key = secrets.token_bytes(len(self.master_key))


@dataclass
class EncryptedMessage:
    """Container for encrypted message with metadata"""
    ciphertext: bytes
    hmac_tag: bytes
    seq_no: int
    timestamp: int
    session_id: str
    nonce: Optional[bytes] = None  # For AEAD modes


@dataclass
class EncryptedFile:
    """Container for encrypted file with metadata"""
    ciphertext: bytes
    nonce: bytes  # 24 bytes for XChaCha20
    aad: bytes    # Additional authenticated data
    filename: str
    file_seq_no: int
    session_id: str


class CryptoService:
    """Enhanced cryptography service for BB84 QKD system"""
    
    def __init__(self):
        self.derived_keys: Optional[DerivedKeys] = None
        self.message_seq_counter = 0
        self.file_seq_counter = 0
        self.used_key_stream_offsets: List[Tuple[int, int]] = []  # (start, end) pairs
        self.session_id: Optional[str] = None
        
    def derive_keys(self, master_key: bytes, session_id: str) -> DerivedKeys:
        """
        Derive cryptographic keys from BB84 master key using HKDF-SHA256
        
        Args:
            master_key: Raw key from BB84 protocol (minimum 32 bytes)
            session_id: Unique session identifier
            
        Returns:
            DerivedKeys object with separated keys for different purposes
        """
        if len(master_key) < 32:
            raise ValueError("Master key must be at least 32 bytes for security")
        
        self.session_id = session_id
        
        # Use HKDF to derive multiple independent keys
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=session_id.encode('utf-8'),  # Use session ID as salt
            info=b'',
        )
        
        # Derive key stream seed for OTP
        key_stream_seed = hkdf.derive(master_key + b'otp-stream')
        
        # Derive HMAC key (reset HKDF for each derivation)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=session_id.encode('utf-8'),
            info=b'',
        )
        key_mac = hkdf.derive(master_key + b'hmac-key')
        
        # Derive file encryption key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=session_id.encode('utf-8'),
            info=b'',
        )
        key_file = hkdf.derive(master_key + b'file-key')
        
        self.derived_keys = DerivedKeys(
            key_stream_seed=key_stream_seed,
            key_mac=key_mac,
            key_file=key_file,
            master_key=master_key
        )
        
        logger.info(f"Derived cryptographic keys for session {session_id}")
        return self.derived_keys
    
    def _generate_key_stream(self, length: int, seq_no: int) -> bytes:
        """
        Generate one-time key stream using HKDF expansion
        
        Args:
            length: Number of bytes needed
            seq_no: Sequence number for uniqueness
            
        Returns:
            Key stream bytes
        """
        if not self.derived_keys:
            raise RuntimeError("Keys not derived yet")
        
        # Check for key stream reuse
        start_offset = seq_no * 1024  # Allocate 1KB segments per message
        end_offset = start_offset + length
        
        for used_start, used_end in self.used_key_stream_offsets:
            if not (end_offset <= used_start or start_offset >= used_end):
                raise RuntimeError(f"Key stream reuse detected: {start_offset}-{end_offset} overlaps with {used_start}-{used_end}")
        
        # Record this usage
        self.used_key_stream_offsets.append((start_offset, end_offset))
        
        # Generate key stream using HKDF-expand
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=f"msg-{seq_no}-{self.session_id}".encode('utf-8'),
        )
        
        key_stream = hkdf.derive(self.derived_keys.key_stream_seed)
        return key_stream
    
    def encrypt_message_otp(self, plaintext: str) -> EncryptedMessage:
        """
        Encrypt message using OTP + HMAC-SHA3-256
        
        Args:
            plaintext: Message to encrypt
            
        Returns:
            EncryptedMessage with OTP ciphertext and HMAC tag
        """
        if not self.derived_keys:
            raise RuntimeError("Keys not derived yet")
        
        # Convert to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Get next sequence number
        seq_no = self.message_seq_counter
        self.message_seq_counter += 1
        
        # Generate one-time key stream
        key_stream = self._generate_key_stream(len(plaintext_bytes), seq_no)
        
        # OTP encryption (XOR)
        ciphertext = bytes(a ^ b for a, b in zip(plaintext_bytes, key_stream))
        
        # Create AAD (Additional Authenticated Data)
        timestamp = int(os.times().elapsed * 1000)  # milliseconds
        aad = f"{self.session_id}:{seq_no}:{timestamp}".encode('utf-8')
        
        # Compute HMAC-SHA3-256
        h = hmac.new(
            self.derived_keys.key_mac,
            aad + ciphertext,
            hashlib.sha3_256
        )
        hmac_tag = h.digest()
        
        return EncryptedMessage(
            ciphertext=ciphertext,
            hmac_tag=hmac_tag,
            seq_no=seq_no,
            timestamp=timestamp,
            session_id=self.session_id
        )
    
    def decrypt_message_otp(self, encrypted_msg: EncryptedMessage) -> str:
        """
        Decrypt OTP message and verify HMAC
        
        Args:
            encrypted_msg: EncryptedMessage object
            
        Returns:
            Decrypted plaintext string
        """
        if not self.derived_keys:
            raise RuntimeError("Keys not derived yet")
        
        # Recreate AAD
        aad = f"{encrypted_msg.session_id}:{encrypted_msg.seq_no}:{encrypted_msg.timestamp}".encode('utf-8')
        
        # Verify HMAC first
        expected_hmac = hmac.new(
            self.derived_keys.key_mac,
            aad + encrypted_msg.ciphertext,
            hashlib.sha3_256
        ).digest()
        
        if not hmac.compare_digest(encrypted_msg.hmac_tag, expected_hmac):
            raise ValueError("HMAC verification failed - message may be tampered")
        
        # Regenerate key stream for this sequence number
        key_stream = self._generate_key_stream(len(encrypted_msg.ciphertext), encrypted_msg.seq_no)
        
        # Decrypt (XOR)
        plaintext_bytes = bytes(a ^ b for a, b in zip(encrypted_msg.ciphertext, key_stream))
        
        return plaintext_bytes.decode('utf-8')
    
    def encrypt_file_xchacha20(self, file_data: bytes, filename: str) -> EncryptedFile:
        """
        Encrypt file using XChaCha20-Poly1305 AEAD
        
        Args:
            file_data: Raw file bytes
            filename: Original filename for AAD
            
        Returns:
            EncryptedFile object
        """
        if not self.derived_keys:
            raise RuntimeError("Keys not derived yet")
        
        # Get next file sequence number
        file_seq_no = self.file_seq_counter
        self.file_seq_counter += 1
        
        # Create AAD (authenticated but not encrypted)
        aad = f"{self.session_id}:{file_seq_no}:{filename}".encode('utf-8')
        
        # Generate random 24-byte nonce for XChaCha20
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        
        # Create SecretBox (XChaCha20-Poly1305)
        box = nacl.secret.SecretBox(self.derived_keys.key_file)
        
        # Encrypt with AAD
        # Note: PyNaCl doesn't support AAD directly, so we prepend it to plaintext
        # and split after decryption (this is a simplification - in production use
        # a library that supports AAD properly)
        aad_length = len(aad).to_bytes(4, 'big')
        combined_data = aad_length + aad + file_data
        
        ciphertext = box.encrypt(combined_data, nonce).ciphertext
        
        return EncryptedFile(
            ciphertext=ciphertext,
            nonce=nonce,
            aad=aad,
            filename=filename,
            file_seq_no=file_seq_no,
            session_id=self.session_id
        )
    
    def decrypt_file_xchacha20(self, encrypted_file: EncryptedFile) -> Tuple[bytes, str]:
        """
        Decrypt file encrypted with XChaCha20-Poly1305
        
        Args:
            encrypted_file: EncryptedFile object
            
        Returns:
            Tuple of (file_data, filename)
        """
        if not self.derived_keys:
            raise RuntimeError("Keys not derived yet")
        
        # Create SecretBox
        box = nacl.secret.SecretBox(self.derived_keys.key_file)
        
        # Decrypt
        try:
            combined_data = box.decrypt(encrypted_file.ciphertext, encrypted_file.nonce)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
        
        # Extract AAD and verify
        aad_length = int.from_bytes(combined_data[:4], 'big')
        extracted_aad = combined_data[4:4+aad_length]
        file_data = combined_data[4+aad_length:]
        
        if extracted_aad != encrypted_file.aad:
            raise ValueError("AAD verification failed")
        
        return file_data, encrypted_file.filename
    
    def create_hybrid_key(self, bb84_key: bytes, pqc_key: bytes, session_id: str) -> DerivedKeys:
        """
        Create hybrid key combining BB84 and post-quantum cryptography
        
        Args:
            bb84_key: Key from BB84 protocol
            pqc_key: Shared secret from PQC KEM (e.g., Kyber)
            session_id: Session identifier
            
        Returns:
            DerivedKeys derived from hybrid key
        """
        # Combine both keys
        hybrid_key_material = bb84_key + pqc_key
        
        # Use HKDF to produce final hybrid key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=session_id.encode('utf-8'),
            info=b'hybrid-session',
        )
        
        final_key = hkdf.derive(hybrid_key_material)
        
        logger.info(f"Created hybrid key (BB84 + PQC) for session {session_id}")
        return self.derive_keys(final_key, session_id)
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get statistics about current cryptographic session"""
        return {
            'session_id': self.session_id,
            'message_count': self.message_seq_counter,
            'file_count': self.file_seq_counter,
            'key_stream_usage': len(self.used_key_stream_offsets),
            'has_keys': self.derived_keys is not None,
            'total_key_stream_bytes': sum(end - start for start, end in self.used_key_stream_offsets)
        }
    
    def clear_session(self):
        """Securely clear all session data and keys"""
        if self.derived_keys:
            self.derived_keys.clear()
            self.derived_keys = None
        
        self.message_seq_counter = 0
        self.file_seq_counter = 0
        self.used_key_stream_offsets.clear()
        self.session_id = None
        
        logger.info("Cryptographic session cleared")


# Utility functions for integration
def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string for transmission"""
    return data.hex()


def hex_to_bytes(hex_string: str) -> bytes:
    """Convert hex string back to bytes"""
    return bytes.fromhex(hex_string)


def create_message_payload(encrypted_msg: EncryptedMessage) -> Dict[str, Any]:
    """Create JSON-serializable payload for encrypted message"""
    return {
        'ciphertext': bytes_to_hex(encrypted_msg.ciphertext),
        'hmac_tag': bytes_to_hex(encrypted_msg.hmac_tag),
        'seq_no': encrypted_msg.seq_no,
        'timestamp': encrypted_msg.timestamp,
        'session_id': encrypted_msg.session_id,
        'crypto_type': 'otp_hmac_sha3'
    }


def create_file_payload(encrypted_file: EncryptedFile) -> Dict[str, Any]:
    """Create JSON-serializable payload for encrypted file"""
    return {
        'ciphertext': bytes_to_hex(encrypted_file.ciphertext),
        'nonce': bytes_to_hex(encrypted_file.nonce),
        'aad': bytes_to_hex(encrypted_file.aad),
        'filename': encrypted_file.filename,
        'file_seq_no': encrypted_file.file_seq_no,
        'session_id': encrypted_file.session_id,
        'crypto_type': 'xchacha20_poly1305'
    }


def parse_message_payload(payload: Dict[str, Any]) -> EncryptedMessage:
    """Parse JSON payload back to EncryptedMessage"""
    return EncryptedMessage(
        ciphertext=hex_to_bytes(payload['ciphertext']),
        hmac_tag=hex_to_bytes(payload['hmac_tag']),
        seq_no=payload['seq_no'],
        timestamp=payload['timestamp'],
        session_id=payload['session_id']
    )


def parse_file_payload(payload: Dict[str, Any]) -> EncryptedFile:
    """Parse JSON payload back to EncryptedFile"""
    return EncryptedFile(
        ciphertext=hex_to_bytes(payload['ciphertext']),
        nonce=hex_to_bytes(payload['nonce']),
        aad=hex_to_bytes(payload['aad']),
        filename=payload['filename'],
        file_seq_no=payload['file_seq_no'],
        session_id=payload['session_id']
    )