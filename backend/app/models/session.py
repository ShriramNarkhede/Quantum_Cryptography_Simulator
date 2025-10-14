"""
Complete Session and User models for BB84 QKD simulation with enhanced cryptography
"""

import secrets
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import uuid
import logging

# Import will be available after crypto_service.py is created
try:
    from app.services.crypto_service import CryptoService, DerivedKeys
except ImportError:
    # Fallback for initial setup
    CryptoService = None
    DerivedKeys = None

logger = logging.getLogger(__name__)


class UserRole(Enum):
    """User roles in QKD session"""
    ALICE = "alice"
    BOB = "bob" 
    EVE = "eve"


class SessionStatus(Enum):
    """Session status states"""
    CREATED = "created"
    ACTIVE = "active"
    BB84_RUNNING = "bb84_running"
    KEY_ESTABLISHED = "key_established"
    COMPROMISED = "compromised"
    TERMINATED = "terminated"


class MessageType(Enum):
    """Types of messages in the session"""
    SYSTEM = "system"
    CHAT_OTP = "chat_otp"
    FILE_XCHACHA20 = "file_xchacha20"
    KEY_EXCHANGE = "key_exchange"


@dataclass
class User:
    """Represents a user in a QKD session"""
    user_id: str
    role: UserRole
    connected: bool = False
    socket_id: Optional[str] = None
    joined_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary"""
        return {
            "user_id": self.user_id,
            "role": self.role.value,
            "connected": self.connected,
            "joined_at": self.joined_at.isoformat(),
            "last_activity": self.last_activity.isoformat()
        }


@dataclass 
class BB84Data:
    """Stores BB84 simulation data"""
    alice_bits: Optional[List[int]] = None
    alice_bases: Optional[List[int]] = None
    bob_bases: Optional[List[int]] = None
    bob_results: Optional[List[int]] = None
    sifted_key: Optional[List[int]] = None
    test_bits_positions: Optional[List[int]] = None
    qber: Optional[float] = None
    eve_detected: bool = False
    final_key_length: int = 0
    transmission_errors: int = 0
    total_qubits: int = 0
    sifted_bits: int = 0
    
    def clear(self):
        """Clear all BB84 data securely"""
        # Overwrite sensitive data with random values before clearing
        if self.alice_bits:
            self.alice_bits = [secrets.randbelow(2) for _ in self.alice_bits]
        if self.alice_bases:
            self.alice_bases = [secrets.randbelow(2) for _ in self.alice_bases]
        if self.bob_bases:
            self.bob_bases = [secrets.randbelow(2) for _ in self.bob_bases]
        if self.bob_results:
            self.bob_results = [secrets.randbelow(2) for _ in self.bob_results]
        if self.sifted_key:
            self.sifted_key = [secrets.randbelow(2) for _ in self.sifted_key]
        if self.test_bits_positions:
            self.test_bits_positions = [secrets.randbelow(1000) for _ in self.test_bits_positions]
        
        # Clear all data
        self.alice_bits = None
        self.alice_bases = None
        self.bob_bases = None
        self.bob_results = None
        self.sifted_key = None
        self.test_bits_positions = None
        self.qber = None
        self.eve_detected = False
        self.final_key_length = 0
        self.transmission_errors = 0
        self.total_qubits = 0
        self.sifted_bits = 0
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get BB84 statistics"""
        sift_efficiency = (self.sifted_bits / self.total_qubits) if self.total_qubits > 0 else 0
        return {
            "total_qubits": self.total_qubits,
            "sifted_bits": self.sifted_bits,
            "final_key_length": self.final_key_length,
            "qber": self.qber,
            "transmission_errors": self.transmission_errors,
            "sift_efficiency": sift_efficiency,
            "eve_detected": self.eve_detected
        }


@dataclass
class SecureMessage:
    """Represents a secure message in session with enhanced crypto"""
    message_id: str
    sender_id: str
    message_type: MessageType
    encrypted_payload: Dict[str, Any]  # Serialized encrypted message
    timestamp: datetime = field(default_factory=datetime.now)
    seq_no: Optional[int] = None
    verified: bool = False  # Whether HMAC/AEAD verification passed
    size_bytes: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary"""
        return {
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "message_type": self.message_type.value,
            "encrypted_payload": self.encrypted_payload,
            "timestamp": self.timestamp.isoformat(),
            "seq_no": self.seq_no,
            "verified": self.verified,
            "size_bytes": self.size_bytes
        }


@dataclass
class CryptoSession:
    """Cryptographic session state"""
    crypto_service: Optional[Any] = None  # Will be CryptoService when available
    derived_keys: Optional[Any] = None    # Will be DerivedKeys when available
    key_established: bool = False
    hybrid_mode: bool = False  # Whether using PQC hybrid approach
    pqc_shared_secret: Optional[bytes] = None
    key_establishment_time: Optional[datetime] = None
    last_key_rotation: Optional[datetime] = None
    
    def __post_init__(self):
        """Initialize crypto service if available"""
        if CryptoService is not None and self.crypto_service is None:
            self.crypto_service = CryptoService()
    
    def initialize_keys(self, master_key: bytes, session_id: str, pqc_key: Optional[bytes] = None) -> bool:
        """Initialize cryptographic keys from BB84 output"""
        if not self.crypto_service:
            logger.error("Crypto service not available")
            return False
            
        try:
            if pqc_key:
                # Use hybrid approach
                self.derived_keys = self.crypto_service.create_hybrid_key(master_key, pqc_key, session_id)
                self.hybrid_mode = True
                self.pqc_shared_secret = pqc_key
                logger.info(f"Initialized hybrid cryptographic session for {session_id}")
            else:
                # Pure BB84 approach
                self.derived_keys = self.crypto_service.derive_keys(master_key, session_id)
                self.hybrid_mode = False
                logger.info(f"Initialized BB84 cryptographic session for {session_id}")
            
            self.key_established = True
            self.key_establishment_time = datetime.now()
            self.last_key_rotation = datetime.now()
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize cryptographic keys: {e}")
            return False
    
    def needs_key_rotation(self, max_age_hours: int = 24) -> bool:
        """Check if keys need rotation based on age"""
        if not self.last_key_rotation:
            return True
        
        age = datetime.now() - self.last_key_rotation
        return age.total_seconds() > (max_age_hours * 3600)
    
    def get_key_age_seconds(self) -> float:
        """Get age of current keys in seconds"""
        if not self.key_establishment_time:
            return 0.0
        return (datetime.now() - self.key_establishment_time).total_seconds()
    
    def clear(self):
        """Securely clear all cryptographic state"""
        if self.derived_keys and hasattr(self.derived_keys, 'clear'):
            self.derived_keys.clear()
            self.derived_keys = None
        
        if self.pqc_shared_secret:
            # Overwrite with random data
            self.pqc_shared_secret = secrets.token_bytes(len(self.pqc_shared_secret))
            self.pqc_shared_secret = None
        
        if self.crypto_service and hasattr(self.crypto_service, 'clear_session'):
            self.crypto_service.clear_session()
            
        self.key_established = False
        self.hybrid_mode = False
        self.key_establishment_time = None
        self.last_key_rotation = None
        
        logger.info("Cryptographic session cleared")


@dataclass
class SessionMetrics:
    """Session performance and security metrics"""
    creation_time: datetime = field(default_factory=datetime.now)
    bb84_start_time: Optional[datetime] = None
    bb84_completion_time: Optional[datetime] = None
    key_establishment_time: Optional[datetime] = None
    total_messages_sent: int = 0
    total_files_sent: int = 0
    total_bytes_encrypted: int = 0
    peak_qber: float = 0.0
    eve_detection_events: int = 0
    connection_drops: int = 0
    security_violations: List[str] = field(default_factory=list)
    
    def add_security_violation(self, violation: str):
        """Add a security violation to the log"""
        timestamp = datetime.now().isoformat()
        violation_entry = f"{timestamp}: {violation}"
        self.security_violations.append(violation_entry)
        logger.warning(f"Security violation in session: {violation}")
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        total_time = (datetime.now() - self.creation_time).total_seconds()
        bb84_duration = 0.0
        
        if self.bb84_start_time and self.bb84_completion_time:
            bb84_duration = (self.bb84_completion_time - self.bb84_start_time).total_seconds()
        
        return {
            "total_session_time": total_time,
            "bb84_duration": bb84_duration,
            "messages_per_minute": (self.total_messages_sent / (total_time / 60)) if total_time > 0 else 0,
            "avg_message_size": (self.total_bytes_encrypted / self.total_messages_sent) if self.total_messages_sent > 0 else 0,
            "peak_qber": self.peak_qber,
            "security_incidents": len(self.security_violations)
        }


@dataclass
class Session:
    """Enhanced QKD session with production-grade cryptography"""
    session_id: str
    users: Dict[str, User] = field(default_factory=dict)
    status: SessionStatus = SessionStatus.CREATED
    created_at: datetime = field(default_factory=datetime.now)
    
    # BB84 related data
    bb84_data: BB84Data = field(default_factory=BB84Data)
    
    # Enhanced cryptographic session
    crypto_session: CryptoSession = field(default_factory=CryptoSession)
    
    # Eve simulation parameters
    eve_params: Optional[Dict[str, Any]] = None
    
    # Secure message storage (ephemeral)
    messages: List[SecureMessage] = field(default_factory=list)
    max_messages: int = 100  # Limit message history
    
    # Session security settings
    qber_threshold: float = 0.11
    max_session_duration: int = 3600  # 1 hour in seconds
    require_authentication: bool = True
    
    # Session metrics
    metrics: SessionMetrics = field(default_factory=SessionMetrics)
    
    def add_user(self, role: UserRole) -> Optional[User]:
        """Add user with specified role if not already taken"""
        # Check if role is already taken
        for user in self.users.values():
            if user.role == role:
                return None
        
        user_id = str(uuid.uuid4())
        user = User(user_id=user_id, role=role)
        self.users[user_id] = user
        logger.info(f"Added user {user_id} as {role.value} to session {self.session_id}")
        return user
    
    def get_user_by_role(self, role: UserRole) -> Optional[User]:
        """Get user by their role"""
        for user in self.users.values():
            if user.role == role:
                return user
        return None
    
    def get_connected_users(self) -> List[User]:
        """Get list of currently connected users"""
        return [user for user in self.users.values() if user.connected]
    
    def establish_secure_session(self, bb84_key: bytes, pqc_key: Optional[bytes] = None) -> bool:
        """Establish secure session with derived keys"""
        success = self.crypto_session.initialize_keys(bb84_key, self.session_id, pqc_key)
        if success:
            self.status = SessionStatus.KEY_ESTABLISHED
            self.metrics.key_establishment_time = datetime.now()
            logger.info(f"Secure session established for {self.session_id}")
        return success
    
    def add_secure_message(self, sender_id: str, message_content: str, message_type: MessageType = MessageType.CHAT_OTP) -> Optional[SecureMessage]:
        """Add encrypted message to session history"""
        if not self.crypto_session.key_established:
            logger.error("Cannot add secure message: no keys established")
            return None
        
        if not self.crypto_session.crypto_service:
            logger.error("Crypto service not available")
            return None
        
        try:
            # Update sender activity
            if sender_id in self.users:
                self.users[sender_id].update_activity()
            
            # Encrypt message using OTP + HMAC
            if message_type == MessageType.CHAT_OTP:
                encrypted_msg = self.crypto_session.crypto_service.encrypt_message_otp(message_content)
                payload = {
                    'ciphertext': encrypted_msg.ciphertext.hex(),
                    'hmac_tag': encrypted_msg.hmac_tag.hex(),
                    'seq_no': encrypted_msg.seq_no,
                    'timestamp': encrypted_msg.timestamp,
                    'session_id': encrypted_msg.session_id,
                    'crypto_type': 'otp_hmac_sha3'
                }
                size_bytes = len(encrypted_msg.ciphertext) + len(encrypted_msg.hmac_tag)
                seq_no = encrypted_msg.seq_no
            else:
                # Handle other message types
                payload = {'content': message_content, 'crypto_type': 'none'}
                size_bytes = len(message_content.encode('utf-8'))
                seq_no = None
            
            secure_msg = SecureMessage(
                message_id=str(uuid.uuid4()),
                sender_id=sender_id,
                message_type=message_type,
                encrypted_payload=payload,
                seq_no=seq_no,
                verified=True,
                size_bytes=size_bytes
            )
            
            self.messages.append(secure_msg)
            
            # Update metrics
            self.metrics.total_messages_sent += 1
            self.metrics.total_bytes_encrypted += size_bytes
            
            # Keep only recent messages to prevent memory bloat
            if len(self.messages) > self.max_messages:
                self.messages = self.messages[-self.max_messages:]
            
            logger.debug(f"Added secure message from {sender_id} to session {self.session_id}")
            return secure_msg
            
        except Exception as e:
            logger.error(f"Failed to add secure message: {e}")
            self.metrics.add_security_violation(f"Message encryption failed: {str(e)}")
            return None
    
    def decrypt_message(self, secure_msg: SecureMessage) -> Optional[str]:
        """Decrypt a secure message"""
        if not self.crypto_session.key_established:
            return None
        
        if not self.crypto_session.crypto_service:
            return None
        
        try:
            if secure_msg.message_type == MessageType.CHAT_OTP:
                payload = secure_msg.encrypted_payload
                
                # Import here to avoid circular imports
                try:
                    from app.services.crypto_service import EncryptedMessage
                    
                    encrypted_msg = EncryptedMessage(
                        ciphertext=bytes.fromhex(payload['ciphertext']),
                        hmac_tag=bytes.fromhex(payload['hmac_tag']),
                        seq_no=payload['seq_no'],
                        timestamp=payload['timestamp'],
                        session_id=payload['session_id']
                    )
                    
                    return self.crypto_session.crypto_service.decrypt_message_otp(encrypted_msg)
                except ImportError:
                    logger.error("Crypto service not available for decryption")
                    return None
            else:
                return secure_msg.encrypted_payload.get('content', '[Unknown message type]')
                
        except Exception as e:
            logger.error(f"Failed to decrypt message {secure_msg.message_id}: {e}")
            self.metrics.add_security_violation(f"Message decryption failed: {str(e)}")
            return None
    
    def add_encrypted_file(self, sender_id: str, file_data: bytes, filename: str) -> Optional[SecureMessage]:
        """Add encrypted file to session"""
        if not self.crypto_session.key_established:
            logger.error("Cannot add encrypted file: no keys established")
            return None
        
        if not self.crypto_session.crypto_service:
            logger.error("Crypto service not available")
            return None
        
        try:
            # Update sender activity
            if sender_id in self.users:
                self.users[sender_id].update_activity()
            
            # Encrypt file using XChaCha20-Poly1305
            encrypted_file = self.crypto_session.crypto_service.encrypt_file_xchacha20(file_data, filename)
            
            payload = {
                'ciphertext': encrypted_file.ciphertext.hex(),
                'nonce': encrypted_file.nonce.hex(),
                'aad': encrypted_file.aad.hex(),
                'filename': encrypted_file.filename,
                'file_seq_no': encrypted_file.file_seq_no,
                'session_id': encrypted_file.session_id,
                'crypto_type': 'xchacha20_poly1305',
                'file_size': len(file_data)
            }
            
            secure_msg = SecureMessage(
                message_id=str(uuid.uuid4()),
                sender_id=sender_id,
                message_type=MessageType.FILE_XCHACHA20,
                encrypted_payload=payload,
                seq_no=encrypted_file.file_seq_no,
                verified=True,
                size_bytes=len(encrypted_file.ciphertext)
            )
            
            self.messages.append(secure_msg)
            
            # Update metrics
            self.metrics.total_files_sent += 1
            self.metrics.total_bytes_encrypted += len(encrypted_file.ciphertext)
            
            # Keep only recent messages to prevent memory bloat
            if len(self.messages) > self.max_messages:
                self.messages = self.messages[-self.max_messages:]
            
            logger.debug(f"Added encrypted file {filename} from {sender_id} to session {self.session_id}")
            return secure_msg
            
        except Exception as e:
            logger.error(f"Failed to add encrypted file: {e}")
            self.metrics.add_security_violation(f"File encryption failed: {str(e)}")
            return None
    
    def decrypt_file(self, secure_msg: SecureMessage) -> Optional[Tuple[bytes, str]]:
        """Decrypt an encrypted file message"""
        if not self.crypto_session.key_established:
            return None
        
        if secure_msg.message_type != MessageType.FILE_XCHACHA20:
            return None
        
        if not self.crypto_session.crypto_service:
            return None
        
        try:
            payload = secure_msg.encrypted_payload
            
            # Import here to avoid circular imports
            try:
                from app.services.crypto_service import EncryptedFile
                
                encrypted_file = EncryptedFile(
                    ciphertext=bytes.fromhex(payload['ciphertext']),
                    nonce=bytes.fromhex(payload['nonce']),
                    aad=bytes.fromhex(payload['aad']),
                    filename=payload['filename'],
                    file_seq_no=payload['file_seq_no'],
                    session_id=payload['session_id']
                )
                
                return self.crypto_session.crypto_service.decrypt_file_xchacha20(encrypted_file)
            except ImportError:
                logger.error("Crypto service not available for file decryption")
                return None
            
        except Exception as e:
            logger.error(f"Failed to decrypt file {secure_msg.message_id}: {e}")
            self.metrics.add_security_violation(f"File decryption failed: {str(e)}")
            return None
    
    def update_bb84_progress(self, qber: Optional[float] = None, eve_detected: bool = False):
        """Update BB84 progress and metrics"""
        if qber is not None:
            self.bb84_data.qber = qber
            if qber > self.metrics.peak_qber:
                self.metrics.peak_qber = qber
            
            # Check for QBER threshold violation
            if qber > self.qber_threshold:
                self.metrics.add_security_violation(f"QBER ({qber:.3f}) exceeded threshold ({self.qber_threshold})")
        
        if eve_detected and not self.bb84_data.eve_detected:
            self.bb84_data.eve_detected = True
            self.metrics.eve_detection_events += 1
            self.metrics.add_security_violation("Eavesdropping (Eve) detected via QBER analysis")
            self.status = SessionStatus.COMPROMISED
    
    def handle_user_disconnect(self, user_id: str):
        """Handle user disconnection and update metrics"""
        if user_id in self.users:
            self.users[user_id].connected = False
            self.users[user_id].socket_id = None
            self.metrics.connection_drops += 1
            
            # Check if session should be terminated due to no active users
            if len(self.get_connected_users()) == 0:
                logger.info(f"No connected users remaining in session {self.session_id}")
    
    def clear_ephemeral_data(self):
        """Clear all ephemeral data (keys, messages, BB84 data)"""
        # Clear cryptographic session
        self.crypto_session.clear()
        
        # Clear BB84 data
        self.bb84_data.clear()
        
        # Clear messages (overwrite sensitive data first)
        for msg in self.messages:
            if 'ciphertext' in msg.encrypted_payload:
                # Overwrite hex ciphertext with random data
                original_length = len(msg.encrypted_payload['ciphertext'])
                msg.encrypted_payload['ciphertext'] = secrets.token_hex(original_length // 2)
        
        self.messages.clear()
        
        # Clear Eve parameters
        if self.eve_params:
            self.eve_params = {'cleared': True}
            self.eve_params = None
        
        # Disconnect all users
        for user in self.users.values():
            user.connected = False
            user.socket_id = None
        
        # Update status
        self.status = SessionStatus.TERMINATED
        
        logger.info(f"Cleared all ephemeral data for session {self.session_id}")
    
    def is_ready_for_bb84(self) -> bool:
        """Check if session has Alice and Bob to start BB84"""
        alice = self.get_user_by_role(UserRole.ALICE)
        bob = self.get_user_by_role(UserRole.BOB)
        return (alice is not None and bob is not None and 
                alice.connected and bob.connected and
                self.status in [SessionStatus.CREATED, SessionStatus.ACTIVE])
    
    def has_eve(self) -> bool:
        """Check if Eve is present in session"""
        eve = self.get_user_by_role(UserRole.EVE)
        return eve is not None and eve.connected
    
    def get_session_security_info(self) -> Dict[str, Any]:
        """Get comprehensive security information about the session"""
        crypto_stats = {}
        if (self.crypto_session.key_established and 
            self.crypto_session.crypto_service and 
            hasattr(self.crypto_session.crypto_service, 'get_session_stats')):
            crypto_stats = self.crypto_session.crypto_service.get_session_stats()
        
        performance_metrics = self.metrics.get_performance_metrics()
        
        return {
            'session_id': self.session_id,
            'crypto_established': self.crypto_session.key_established,
            'hybrid_mode': self.crypto_session.hybrid_mode,
            'key_age_seconds': self.crypto_session.get_key_age_seconds(),
            'needs_key_rotation': self.crypto_session.needs_key_rotation(),
            'qber': self.bb84_data.qber,
            'qber_threshold': self.qber_threshold,
            'peak_qber': self.metrics.peak_qber,
            'eve_detected': self.bb84_data.eve_detected,
            'eve_detection_events': self.metrics.eve_detection_events,
            'message_count': len(self.messages),
            'crypto_stats': crypto_stats,
            'bb84_stats': self.bb84_data.get_statistics(),
            'final_key_length': self.bb84_data.final_key_length,
            'session_age_seconds': (datetime.now() - self.created_at).total_seconds(),
            'performance_metrics': performance_metrics,
            'security_violations': len(self.metrics.security_violations),
            'connection_drops': self.metrics.connection_drops,
            'total_bytes_encrypted': self.metrics.total_bytes_encrypted
        }
    
    def is_session_expired(self) -> bool:
        """Check if session has exceeded maximum duration"""
        age = (datetime.now() - self.created_at).total_seconds()
        return age > self.max_session_duration
    
    def is_session_compromised(self) -> bool:
        """Check if session is considered compromised"""
        return (self.status == SessionStatus.COMPROMISED or 
                self.bb84_data.eve_detected or
                (self.bb84_data.qber and self.bb84_data.qber > self.qber_threshold) or
                len(self.metrics.security_violations) > 0)
    
    def get_crypto_service(self) -> Optional[Any]:
        """Get the cryptographic service for this session"""
        if self.crypto_session.key_established:
            return self.crypto_session.crypto_service
        return None
    
    def get_session_health_score(self) -> Tuple[float, List[str]]:
        """Calculate session health score (0-100) and issues"""
        score = 100.0
        issues = []
        
        # Check if compromised
        if self.is_session_compromised():
            score -= 50
            issues.append("Session compromised by eavesdropping")
        
        # Check QBER
        if self.bb84_data.qber:
            qber_ratio = self.bb84_data.qber / self.qber_threshold
            if qber_ratio > 0.8:
                score -= min(30, qber_ratio * 30)
                issues.append(f"High QBER: {self.bb84_data.qber:.3f}")
        
        # Check session age
        age_hours = (datetime.now() - self.created_at).total_seconds() / 3600
        if age_hours > 1:
            score -= min(10, age_hours * 2)
            issues.append(f"Session age: {age_hours:.1f} hours")
        
        # Check key age if established
        if self.crypto_session.key_established:
            key_age_hours = self.crypto_session.get_key_age_seconds() / 3600
            if key_age_hours > 24:
                score -= 15
                issues.append("Keys need rotation")
        
        # Check connection stability
        if self.metrics.connection_drops > 3:
            score -= 10
            issues.append(f"Unstable connections: {self.metrics.connection_drops} drops")
        
        # Check security violations
        if len(self.metrics.security_violations) > 0:
            score -= min(20, len(self.metrics.security_violations) * 5)
            issues.append(f"Security violations: {len(self.metrics.security_violations)}")
        
        # Ensure score is within bounds
        score = max(0.0, min(100.0, score))
        
        if score >= 90:
            issues.insert(0, "Excellent security")
        elif score >= 70:
            issues.insert(0, "Good security")
        elif score >= 50:
            issues.insert(0, "Moderate security concerns")
        else:
            issues.insert(0, "Serious security issues")
        
        return score, issues
    
    def export_session_summary(self) -> Dict[str, Any]:
        """Export comprehensive session summary for analysis"""
        health_score, health_issues = self.get_session_health_score()
        
        return {
            "session_info": {
                "session_id": self.session_id,
                "created_at": self.created_at.isoformat(),
                "status": self.status.value,
                "duration_seconds": (datetime.now() - self.created_at).total_seconds(),
                "participants": [user.to_dict() for user in self.users.values()]
            },
            "security_info": self.get_session_security_info(),
            "health_assessment": {
                "score": health_score,
                "issues": health_issues
            },
            "bb84_summary": self.bb84_data.get_statistics(),
            "crypto_summary": {
                "established": self.crypto_session.key_established,
                "hybrid_mode": self.crypto_session.hybrid_mode,
                "messages_encrypted": self.metrics.total_messages_sent,
                "files_encrypted": self.metrics.total_files_sent,
                "total_bytes": self.metrics.total_bytes_encrypted
            },
            "performance_metrics": self.metrics.get_performance_metrics(),
            "security_log": self.metrics.security_violations[-10:]  # Last 10 violations
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary"""
        health_score, _ = self.get_session_health_score()
        
        return {
            "session_id": self.session_id,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "users": [user.to_dict() for user in self.users.values()],
            "qber": self.bb84_data.qber,
            "eve_detected": self.bb84_data.eve_detected,
            "message_count": len(self.messages),
            "has_eve": self.has_eve(),
            "crypto_established": self.crypto_session.key_established,
            "hybrid_mode": self.crypto_session.hybrid_mode,
            "final_key_length": self.bb84_data.final_key_length,
            "session_age_seconds": (datetime.now() - self.created_at).total_seconds(),
            "health_score": health_score,
            "is_compromised": self.is_session_compromised(),
            "total_bytes_encrypted": self.metrics.total_bytes_encrypted,
            "security_violations": len(self.metrics.security_violations)
        }


# Utility functions for session management
def create_system_message(session_id: str, content: str) -> SecureMessage:
    """Create a system message (unencrypted)"""
    return SecureMessage(
        message_id=str(uuid.uuid4()),
        sender_id="system",
        message_type=MessageType.SYSTEM,
        encrypted_payload={
            'content': content,
            'crypto_type': 'none'
        },
        verified=True,
        size_bytes=len(content.encode('utf-8'))
    )


def validate_session_security(session: Session) -> List[str]:
    """Validate session security and return list of issues"""
    issues = []
    
    # Check session age
    if session.is_session_expired():
        issues.append("Session has exceeded maximum duration")
    
    # Check if session is compromised
    if session.is_session_compromised():
        issues.append("Session is compromised")
    
    # Check QBER
    if session.bb84_data.qber and session.bb84_data.qber > session.qber_threshold:
        issues.append(f"QBER ({session.bb84_data.qber:.3f}) exceeds threshold ({session.qber_threshold})")
    
    # Check key establishment
    if not session.crypto_session.key_established and session.status == SessionStatus.KEY_ESTABLISHED:
        issues.append("Session marked as key established but no cryptographic keys present")
    
    # Check message integrity
    unverified_messages = [msg for msg in session.messages if not msg.verified]
    if unverified_messages:
        issues.append(f"{len(unverified_messages)} messages failed verification")
    
    # Check key rotation needs
    if session.crypto_session.key_established and session.crypto_session.needs_key_rotation():
        issues.append("Cryptographic keys need rotation")
    
    # Check for security violations
    if len(session.metrics.security_violations) > 0:
        issues.append(f"{len(session.metrics.security_violations)} security violations recorded")
    
    return issues


def calculate_session_risk_level(session: Session) -> Tuple[str, float]:
    """Calculate risk level for session"""
    health_score, _ = session.get_session_health_score()
    
    if session.is_session_compromised():
        return "CRITICAL", 0.9
    elif health_score < 50:
        return "HIGH", 0.7
    elif health_score < 70:
        return "MEDIUM", 0.5
    elif health_score < 90:
        return "LOW", 0.3
    else:
        return "MINIMAL", 0.1


def generate_security_report(sessions: List[Session]) -> Dict[str, Any]:
    """Generate security report for multiple sessions"""
    if not sessions:
        return {
            "summary": {
                "total_sessions": 0,
                "compromised_sessions": 0,
                "compromise_rate": 0,
                "average_health_score": 0,
                "total_security_violations": 0,
                "total_eve_detections": 0
            },
            "risk_distribution": {},
            "recommendations": ["No active sessions to analyze"]
        }
    
    total_sessions = len(sessions)
    compromised_sessions = sum(1 for s in sessions if s.is_session_compromised())
    total_violations = sum(len(s.metrics.security_violations) for s in sessions)
    total_eve_detections = sum(s.metrics.eve_detection_events for s in sessions)
    
    avg_health = sum(s.get_session_health_score()[0] for s in sessions) / total_sessions
    
    risk_distribution = {}
    for session in sessions:
        risk_level, _ = calculate_session_risk_level(session)
        risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1
    
    return {
        "summary": {
            "total_sessions": total_sessions,
            "compromised_sessions": compromised_sessions,
            "compromise_rate": compromised_sessions / total_sessions,
            "average_health_score": avg_health,
            "total_security_violations": total_violations,
            "total_eve_detections": total_eve_detections
        },
        "risk_distribution": risk_distribution,
        "recommendations": _generate_security_recommendations(sessions)
    }


def _generate_security_recommendations(sessions: List[Session]) -> List[str]:
    """Generate security recommendations based on session analysis"""
    recommendations = []
    
    if not sessions:
        return ["No active sessions to analyze"]
    
    compromised_count = sum(1 for s in sessions if s.is_session_compromised())
    if compromised_count > 0:
        recommendations.append(f"Investigate {compromised_count} compromised sessions")
    
    high_qber_sessions = [s for s in sessions if s.bb84_data.qber and s.bb84_data.qber > 0.08]
    if high_qber_sessions:
        recommendations.append(f"Monitor {len(high_qber_sessions)} sessions with elevated QBER")
    
    old_sessions = [s for s in sessions if s.is_session_expired()]
    if old_sessions:
        recommendations.append(f"Terminate {len(old_sessions)} expired sessions")
    
    needs_rotation = [s for s in sessions if s.crypto_session.key_established and s.crypto_session.needs_key_rotation()]
    if needs_rotation:
        recommendations.append(f"Rotate keys for {len(needs_rotation)} sessions")
    
    # Check for patterns
    sessions_with_violations = [s for s in sessions if len(s.metrics.security_violations) > 0]
    if len(sessions_with_violations) > len(sessions) * 0.3:  # More than 30% have violations
        recommendations.append("High rate of security violations detected - review security policies")
    
    sessions_with_eve = [s for s in sessions if s.has_eve()]
    if sessions_with_eve:
        recommendations.append(f"Monitor {len(sessions_with_eve)} sessions with active eavesdroppers")
    
    # Performance recommendations
    high_traffic_sessions = [s for s in sessions if s.metrics.total_bytes_encrypted > 1024 * 1024]  # > 1MB
    if high_traffic_sessions:
        recommendations.append(f"Consider key rotation for {len(high_traffic_sessions)} high-traffic sessions")
    
    if not recommendations:
        recommendations.append("All sessions appear secure")
    
    return recommendations


def export_session_data(session: Session, include_sensitive: bool = False) -> Dict[str, Any]:
    """Export session data for analysis (with option to exclude sensitive data)"""
    export_data = session.export_session_summary()
    
    if not include_sensitive:
        # Remove sensitive cryptographic information
        if 'crypto_summary' in export_data:
            export_data['crypto_summary'] = {
                key: value for key, value in export_data['crypto_summary'].items()
                if key not in ['keys', 'secrets', 'private_data']
            }
        
        # Sanitize security log
        if 'security_log' in export_data:
            export_data['security_log'] = [
                entry.split(': ', 1)[1] if ': ' in entry else entry 
                for entry in export_data['security_log']
            ]
    
    return export_data


def create_session_backup(session: Session) -> Dict[str, Any]:
    """Create a backup of session state (excluding cryptographic keys)"""
    return {
        "session_id": session.session_id,
        "created_at": session.created_at.isoformat(),
        "status": session.status.value,
        "users": [
            {
                "user_id": user.user_id,
                "role": user.role.value,
                "joined_at": user.joined_at.isoformat()
            }
            for user in session.users.values()
        ],
        "bb84_stats": session.bb84_data.get_statistics(),
        "metrics": {
            "total_messages": session.metrics.total_messages_sent,
            "total_files": session.metrics.total_files_sent,
            "total_bytes": session.metrics.total_bytes_encrypted,
            "security_violations": len(session.metrics.security_violations),
            "eve_detections": session.metrics.eve_detection_events
        },
        "settings": {
            "qber_threshold": session.qber_threshold,
            "max_duration": session.max_session_duration,
            "max_messages": session.max_messages
        }
    }


def restore_session_from_backup(backup_data: Dict[str, Any]) -> Session:
    """Restore a session from backup data (keys must be re-established)"""
    session = Session(session_id=backup_data["session_id"])
    session.created_at = datetime.fromisoformat(backup_data["created_at"])
    session.status = SessionStatus(backup_data["status"])
    session.qber_threshold = backup_data["settings"]["qber_threshold"]
    session.max_session_duration = backup_data["settings"]["max_duration"]
    session.max_messages = backup_data["settings"]["max_messages"]
    
    # Restore users (they will need to reconnect)
    for user_data in backup_data["users"]:
        user = User(
            user_id=user_data["user_id"],
            role=UserRole(user_data["role"]),
            joined_at=datetime.fromisoformat(user_data["joined_at"]),
            connected=False  # Will need to reconnect
        )
        session.users[user.user_id] = user
    
    # Restore BB84 statistics (but not sensitive data)
    bb84_stats = backup_data["bb84_stats"]
    session.bb84_data.total_qubits = bb84_stats.get("total_qubits", 0)
    session.bb84_data.sifted_bits = bb84_stats.get("sifted_bits", 0)
    session.bb84_data.final_key_length = bb84_stats.get("final_key_length", 0)
    session.bb84_data.qber = bb84_stats.get("qber")
    session.bb84_data.eve_detected = bb84_stats.get("eve_detected", False)
    
    # Restore metrics
    metrics_data = backup_data["metrics"]
    session.metrics.total_messages_sent = metrics_data.get("total_messages", 0)
    session.metrics.total_files_sent = metrics_data.get("total_files", 0)
    session.metrics.total_bytes_encrypted = metrics_data.get("total_bytes", 0)
    session.metrics.eve_detection_events = metrics_data.get("eve_detections", 0)
    
    logger.info(f"Restored session {session.session_id} from backup (keys must be re-established)")
    return session


# Session factory functions
def create_demo_session(session_id: Optional[str] = None) -> Session:
    """Create a demo session with sample data for testing"""
    if session_id is None:
        session_id = f"demo_{secrets.token_hex(4)}"
    
    session = Session(session_id=session_id)
    
    # Add sample users
    alice = session.add_user(UserRole.ALICE)
    bob = session.add_user(UserRole.BOB)
    
    if alice and bob:
        alice.connected = True
        bob.connected = True
        session.status = SessionStatus.ACTIVE
    
    # Add some demo BB84 data
    session.bb84_data.total_qubits = 1000
    session.bb84_data.sifted_bits = 500
    session.bb84_data.qber = 0.05
    session.bb84_data.final_key_length = 32
    
    logger.info(f"Created demo session {session_id}")
    return session


def create_test_session_with_eve(session_id: Optional[str] = None) -> Session:
    """Create a test session with Eve for demonstration purposes"""
    if session_id is None:
        session_id = f"test_eve_{secrets.token_hex(4)}"
    
    session = Session(session_id=session_id)
    
    # Add all participants
    alice = session.add_user(UserRole.ALICE)
    bob = session.add_user(UserRole.BOB)
    eve = session.add_user(UserRole.EVE)
    
    if alice and bob and eve:
        alice.connected = True
        bob.connected = True
        eve.connected = True
        session.status = SessionStatus.ACTIVE
    
    # Set up for Eve detection scenario
    session.bb84_data.total_qubits = 1000
    session.bb84_data.sifted_bits = 500
    session.bb84_data.qber = 0.15  # Above threshold
    session.bb84_data.eve_detected = True
    session.status = SessionStatus.COMPROMISED
    
    # Add security violation
    session.metrics.add_security_violation("High QBER detected indicating eavesdropping")
    session.metrics.eve_detection_events = 1
    
    logger.info(f"Created test session with Eve {session_id}")
    return session


# Module-level initialization
def initialize_session_models():
    """Initialize session models module"""
    logger.info("Session models initialized with enhanced cryptography support")


# Call initialization
initialize_session_models()