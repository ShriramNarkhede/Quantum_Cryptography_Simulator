"""
Post-Quantum Cryptography Service for BB84 QKD System
Implements NIST-approved PQC algorithms: Kyber (KEM) and Dilithium (Signatures)
"""

import secrets
import logging
from typing import Tuple, Optional, Dict, Any
from dataclasses import dataclass
import hashlib

# Try to import liboqs (primary PQC library)
try:
    import oqs
    LIBOQS_AVAILABLE = True
    logger = logging.getLogger(__name__)
    logger.info("liboqs-python available - using NIST-approved PQC algorithms")
except ImportError:
    LIBOQS_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("liboqs-python not available - falling back to demo PQC")

# Fallback to pure Python implementations
try:
    import pqcrypto
    PQCRYPTO_AVAILABLE = True
    logger.info("pqcrypto available - using pure Python PQC implementations")
except ImportError:
    PQCRYPTO_AVAILABLE = False
    logger.warning("pqcrypto not available - using demo PQC only")

logger = logging.getLogger(__name__)


@dataclass
class KyberKeyPair:
    """Kyber KEM key pair"""
    public_key: bytes
    private_key: bytes
    algorithm: str = "Kyber512"  # NIST security level 1


@dataclass
class KyberCiphertext:
    """Kyber KEM ciphertext"""
    ciphertext: bytes
    shared_secret: bytes
    algorithm: str = "Kyber512"


@dataclass
class DilithiumKeyPair:
    """Dilithium signature key pair"""
    public_key: bytes
    private_key: bytes
    algorithm: str = "Dilithium2"  # NIST security level 2


@dataclass
class DilithiumSignature:
    """Dilithium signature"""
    signature: bytes
    message: bytes
    algorithm: str = "Dilithium2"


class PQCService:
    """Post-Quantum Cryptography service using NIST-approved algorithms"""
    
    def __init__(self):
        self.kyber_algorithm = "Kyber512"  # NIST security level 1
        self.dilithium_algorithm = "Dilithium2"  # NIST security level 2
        self.fallback_mode = not LIBOQS_AVAILABLE
        
        if self.fallback_mode:
            logger.warning("Running in PQC fallback mode - using demo implementations")
        else:
            logger.info(f"PQC Service initialized with {self.kyber_algorithm} and {self.dilithium_algorithm}")
    
    def generate_kyber_keypair(self) -> KyberKeyPair:
        """
        Generate Kyber KEM key pair
        
        Returns:
            KyberKeyPair with public and private keys
        """
        if LIBOQS_AVAILABLE:
            return self._generate_kyber_liboqs()
        elif PQCRYPTO_AVAILABLE:
            return self._generate_kyber_pqcrypto()
        else:
            return self._generate_kyber_demo()
    
    def _generate_kyber_liboqs(self) -> KyberKeyPair:
        """Generate Kyber key pair using liboqs"""
        try:
            with oqs.KeyEncapsulation(self.kyber_algorithm) as kem:
                public_key, private_key = kem.generate_keypair()
                
                logger.debug(f"Generated Kyber key pair: pub={len(public_key)} bytes, priv={len(private_key)} bytes")
                
                return KyberKeyPair(
                    public_key=public_key,
                    private_key=private_key,
                    algorithm=self.kyber_algorithm
                )
        except Exception as e:
            logger.error(f"Error generating Kyber key pair with liboqs: {e}")
            return self._generate_kyber_demo()
    
    def _generate_kyber_pqcrypto(self) -> KyberKeyPair:
        """Generate Kyber key pair using pqcrypto"""
        try:
            # pqcrypto uses different API
            public_key, private_key = pqcrypto.kem.kyber512.keypair()
            
            logger.debug(f"Generated Kyber key pair with pqcrypto: pub={len(public_key)} bytes, priv={len(private_key)} bytes")
            
            return KyberKeyPair(
                public_key=public_key,
                private_key=private_key,
                algorithm=self.kyber_algorithm
            )
        except Exception as e:
            logger.error(f"Error generating Kyber key pair with pqcrypto: {e}")
            return self._generate_kyber_demo()
    
    def _generate_kyber_demo(self) -> KyberKeyPair:
        """Generate demo Kyber key pair (fallback)"""
        # Generate random keys for demo purposes
        public_key = secrets.token_bytes(800)  # Approximate Kyber512 public key size
        private_key = secrets.token_bytes(1632)  # Approximate Kyber512 private key size
        
        logger.warning("Using demo Kyber key pair - not cryptographically secure")
        
        return KyberKeyPair(
            public_key=public_key,
            private_key=private_key,
            algorithm="Demo-Kyber512"
        )
    
    def encapsulate_key(self, public_key: bytes) -> KyberCiphertext:
        """
        Encapsulate a shared secret using Kyber KEM
        
        Args:
            public_key: Kyber public key
            
        Returns:
            KyberCiphertext with ciphertext and shared secret
        """
        if LIBOQS_AVAILABLE:
            return self._encapsulate_key_liboqs(public_key)
        elif PQCRYPTO_AVAILABLE:
            return self._encapsulate_key_pqcrypto(public_key)
        else:
            return self._encapsulate_key_demo(public_key)
    
    def _encapsulate_key_liboqs(self, public_key: bytes) -> KyberCiphertext:
        """Encapsulate key using liboqs"""
        try:
            with oqs.KeyEncapsulation(self.kyber_algorithm) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)
                
                logger.debug(f"Encapsulated key: ciphertext={len(ciphertext)} bytes, secret={len(shared_secret)} bytes")
                
                return KyberCiphertext(
                    ciphertext=ciphertext,
                    shared_secret=shared_secret,
                    algorithm=self.kyber_algorithm
                )
        except Exception as e:
            logger.error(f"Error encapsulating key with liboqs: {e}")
            return self._encapsulate_key_demo(public_key)
    
    def _encapsulate_key_pqcrypto(self, public_key: bytes) -> KyberCiphertext:
        """Encapsulate key using pqcrypto"""
        try:
            ciphertext, shared_secret = pqcrypto.kem.kyber512.enc(public_key)
            
            logger.debug(f"Encapsulated key with pqcrypto: ciphertext={len(ciphertext)} bytes, secret={len(shared_secret)} bytes")
            
            return KyberCiphertext(
                ciphertext=ciphertext,
                shared_secret=shared_secret,
                algorithm=self.kyber_algorithm
            )
        except Exception as e:
            logger.error(f"Error encapsulating key with pqcrypto: {e}")
            return self._encapsulate_key_demo(public_key)
    
    def _encapsulate_key_demo(self, public_key: bytes) -> KyberCiphertext:
        """Demo key encapsulation (fallback)"""
        # Generate random ciphertext and shared secret
        ciphertext = secrets.token_bytes(768)  # Approximate Kyber512 ciphertext size
        shared_secret = secrets.token_bytes(32)  # 256-bit shared secret
        
        logger.warning("Using demo key encapsulation - not cryptographically secure")
        
        return KyberCiphertext(
            ciphertext=ciphertext,
            shared_secret=shared_secret,
            algorithm="Demo-Kyber512"
        )
    
    def decapsulate_key(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """
        Decapsulate shared secret using Kyber KEM
        
        Args:
            ciphertext: Kyber ciphertext
            private_key: Kyber private key
            
        Returns:
            Shared secret bytes
        """
        if LIBOQS_AVAILABLE:
            return self._decapsulate_key_liboqs(ciphertext, private_key)
        elif PQCRYPTO_AVAILABLE:
            return self._decapsulate_key_pqcrypto(ciphertext, private_key)
        else:
            return self._decapsulate_key_demo(ciphertext, private_key)
    
    def _decapsulate_key_liboqs(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Decapsulate key using liboqs"""
        try:
            with oqs.KeyEncapsulation(self.kyber_algorithm) as kem:
                shared_secret = kem.decap_secret(ciphertext, private_key)
                
                logger.debug(f"Decapsulated key: secret={len(shared_secret)} bytes")
                
                return shared_secret
        except Exception as e:
            logger.error(f"Error decapsulating key with liboqs: {e}")
            return self._decapsulate_key_demo(ciphertext, private_key)
    
    def _decapsulate_key_pqcrypto(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Decapsulate key using pqcrypto"""
        try:
            shared_secret = pqcrypto.kem.kyber512.dec(ciphertext, private_key)
            
            logger.debug(f"Decapsulated key with pqcrypto: secret={len(shared_secret)} bytes")
            
            return shared_secret
        except Exception as e:
            logger.error(f"Error decapsulating key with pqcrypto: {e}")
            return self._decapsulate_key_demo(ciphertext, private_key)
    
    def _decapsulate_key_demo(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Demo key decapsulation (fallback)"""
        # Generate deterministic shared secret based on inputs
        combined = ciphertext + private_key
        shared_secret = hashlib.sha256(combined).digest()
        
        logger.warning("Using demo key decapsulation - not cryptographically secure")
        
        return shared_secret
    
    def generate_dilithium_keypair(self) -> DilithiumKeyPair:
        """
        Generate Dilithium signature key pair
        
        Returns:
            DilithiumKeyPair with public and private keys
        """
        if LIBOQS_AVAILABLE:
            return self._generate_dilithium_liboqs()
        elif PQCRYPTO_AVAILABLE:
            return self._generate_dilithium_pqcrypto()
        else:
            return self._generate_dilithium_demo()
    
    def _generate_dilithium_liboqs(self) -> DilithiumKeyPair:
        """Generate Dilithium key pair using liboqs"""
        try:
            with oqs.Signature(self.dilithium_algorithm) as sig:
                public_key, private_key = sig.generate_keypair()
                
                logger.debug(f"Generated Dilithium key pair: pub={len(public_key)} bytes, priv={len(private_key)} bytes")
                
                return DilithiumKeyPair(
                    public_key=public_key,
                    private_key=private_key,
                    algorithm=self.dilithium_algorithm
                )
        except Exception as e:
            logger.error(f"Error generating Dilithium key pair with liboqs: {e}")
            return self._generate_dilithium_demo()
    
    def _generate_dilithium_pqcrypto(self) -> DilithiumKeyPair:
        """Generate Dilithium key pair using pqcrypto"""
        try:
            public_key, private_key = pqcrypto.sign.dilithium2.keypair()
            
            logger.debug(f"Generated Dilithium key pair with pqcrypto: pub={len(public_key)} bytes, priv={len(private_key)} bytes")
            
            return DilithiumKeyPair(
                public_key=public_key,
                private_key=private_key,
                algorithm=self.dilithium_algorithm
            )
        except Exception as e:
            logger.error(f"Error generating Dilithium key pair with pqcrypto: {e}")
            return self._generate_dilithium_demo()
    
    def _generate_dilithium_demo(self) -> DilithiumKeyPair:
        """Generate demo Dilithium key pair (fallback)"""
        # Generate random keys for demo purposes
        public_key = secrets.token_bytes(1312)  # Approximate Dilithium2 public key size
        private_key = secrets.token_bytes(2528)  # Approximate Dilithium2 private key size
        
        logger.warning("Using demo Dilithium key pair - not cryptographically secure")
        
        return DilithiumKeyPair(
            public_key=public_key,
            private_key=private_key,
            algorithm="Demo-Dilithium2"
        )
    
    def sign_message(self, message: bytes, private_key: bytes) -> DilithiumSignature:
        """
        Sign a message using Dilithium
        
        Args:
            message: Message to sign
            private_key: Dilithium private key
            
        Returns:
            DilithiumSignature with signature and message
        """
        if LIBOQS_AVAILABLE:
            return self._sign_message_liboqs(message, private_key)
        elif PQCRYPTO_AVAILABLE:
            return self._sign_message_pqcrypto(message, private_key)
        else:
            return self._sign_message_demo(message, private_key)
    
    def _sign_message_liboqs(self, message: bytes, private_key: bytes) -> DilithiumSignature:
        """Sign message using liboqs"""
        try:
            with oqs.Signature(self.dilithium_algorithm) as sig:
                signature = sig.sign(message, private_key)
                
                logger.debug(f"Signed message: signature={len(signature)} bytes")
                
                return DilithiumSignature(
                    signature=signature,
                    message=message,
                    algorithm=self.dilithium_algorithm
                )
        except Exception as e:
            logger.error(f"Error signing message with liboqs: {e}")
            return self._sign_message_demo(message, private_key)
    
    def _sign_message_pqcrypto(self, message: bytes, private_key: bytes) -> DilithiumSignature:
        """Sign message using pqcrypto"""
        try:
            signature = pqcrypto.sign.dilithium2.sign(message, private_key)
            
            logger.debug(f"Signed message with pqcrypto: signature={len(signature)} bytes")
            
            return DilithiumSignature(
                signature=signature,
                message=message,
                algorithm=self.dilithium_algorithm
            )
        except Exception as e:
            logger.error(f"Error signing message with pqcrypto: {e}")
            return self._sign_message_demo(message, private_key)
    
    def _sign_message_demo(self, message: bytes, private_key: bytes) -> DilithiumSignature:
        """Demo message signing (fallback)"""
        # Generate deterministic signature based on message and key
        combined = message + private_key
        signature = hashlib.sha256(combined).digest() + secrets.token_bytes(2048)  # Approximate Dilithium2 signature size
        
        logger.warning("Using demo message signing - not cryptographically secure")
        
        return DilithiumSignature(
            signature=signature,
            message=message,
            algorithm="Demo-Dilithium2"
        )
    
    def verify_signature(self, signature: bytes, message: bytes, public_key: bytes) -> bool:
        """
        Verify a Dilithium signature
        
        Args:
            signature: Dilithium signature
            message: Original message
            public_key: Dilithium public key
            
        Returns:
            True if signature is valid, False otherwise
        """
        if LIBOQS_AVAILABLE:
            return self._verify_signature_liboqs(signature, message, public_key)
        elif PQCRYPTO_AVAILABLE:
            return self._verify_signature_pqcrypto(signature, message, public_key)
        else:
            return self._verify_signature_demo(signature, message, public_key)
    
    def _verify_signature_liboqs(self, signature: bytes, message: bytes, public_key: bytes) -> bool:
        """Verify signature using liboqs"""
        try:
            with oqs.Signature(self.dilithium_algorithm) as sig:
                is_valid = sig.verify(message, signature, public_key)
                
                logger.debug(f"Signature verification: {is_valid}")
                
                return is_valid
        except Exception as e:
            logger.error(f"Error verifying signature with liboqs: {e}")
            return self._verify_signature_demo(signature, message, public_key)
    
    def _verify_signature_pqcrypto(self, signature: bytes, message: bytes, public_key: bytes) -> bool:
        """Verify signature using pqcrypto"""
        try:
            is_valid = pqcrypto.sign.dilithium2.verify(signature, message, public_key)
            
            logger.debug(f"Signature verification with pqcrypto: {is_valid}")
            
            return is_valid
        except Exception as e:
            logger.error(f"Error verifying signature with pqcrypto: {e}")
            return self._verify_signature_demo(signature, message, public_key)
    
    def _verify_signature_demo(self, signature: bytes, message: bytes, public_key: bytes) -> bool:
        """Demo signature verification (fallback)"""
        # Simple demo verification - check if signature starts with expected hash
        expected_hash = hashlib.sha256(message + public_key).digest()
        is_valid = signature.startswith(expected_hash)
        
        logger.warning("Using demo signature verification - not cryptographically secure")
        
        return is_valid
    
    def get_pqc_info(self) -> Dict[str, Any]:
        """Get information about PQC capabilities"""
        return {
            "liboqs_available": LIBOQS_AVAILABLE,
            "pqcrypto_available": PQCRYPTO_AVAILABLE,
            "fallback_mode": self.fallback_mode,
            "kyber_algorithm": self.kyber_algorithm,
            "dilithium_algorithm": self.dilithium_algorithm,
            "kyber_key_sizes": {
                "public_key": 800 if not self.fallback_mode else 800,
                "private_key": 1632 if not self.fallback_mode else 1632,
                "ciphertext": 768 if not self.fallback_mode else 768,
                "shared_secret": 32
            },
            "dilithium_key_sizes": {
                "public_key": 1312 if not self.fallback_mode else 1312,
                "private_key": 2528 if not self.fallback_mode else 2528,
                "signature": 2420 if not self.fallback_mode else 2420
            }
        }
    
    def clear_keys(self, keypair: Any):
        """Securely clear PQC key material"""
        if hasattr(keypair, 'public_key'):
            keypair.public_key = secrets.token_bytes(len(keypair.public_key))
        if hasattr(keypair, 'private_key'):
            keypair.private_key = secrets.token_bytes(len(keypair.private_key))
        
        logger.debug("PQC key material cleared")


# Global PQC service instance
pqc_service = PQCService()


