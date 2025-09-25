
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import uuid


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


@dataclass
class User:
    """Represents a user in a QKD session"""
    user_id: str
    role: UserRole
    connected: bool = False
    socket_id: Optional[str] = None
    joined_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user to dictionary"""
        return {
            "user_id": self.user_id,
            "role": self.role.value,
            "connected": self.connected,
            "joined_at": self.joined_at.isoformat()
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
    
    def clear(self):
        """Clear all BB84 data"""
        self.alice_bits = None
        self.alice_bases = None
        self.bob_bases = None
        self.bob_results = None
        self.sifted_key = None
        self.test_bits_positions = None
        self.qber = None
        self.eve_detected = False


@dataclass
class EncryptedMessage:
    """Represents an encrypted message in session"""
    message_id: str
    sender_id: str
    encrypted_content: bytes
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary"""
        return {
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "encrypted_content": self.encrypted_content.hex(),
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class Session:
    """Represents a QKD session between Alice and Bob (and optionally Eve)"""
    session_id: str
    users: Dict[str, User] = field(default_factory=dict)
    status: SessionStatus = SessionStatus.CREATED
    created_at: datetime = field(default_factory=datetime.now)
    
    # BB84 related data
    bb84_data: BB84Data = field(default_factory=BB84Data)
    session_key: Optional[bytes] = None
    key_length: int = 0
    
    # Eve simulation parameters
    eve_params: Optional[Dict[str, Any]] = None
    
    # Ephemeral message storage
    messages: List[EncryptedMessage] = field(default_factory=list)
    max_messages: int = 100  # Limit message history
    
    def add_user(self, role: UserRole) -> Optional[User]:
        """Add user with specified role if not already taken"""
        # Check if role is already taken
        for user in self.users.values():
            if user.role == role:
                return None
        
        user_id = str(uuid.uuid4())
        user = User(user_id=user_id, role=role)
        self.users[user_id] = user
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
    
    def add_message(self, sender_id: str, encrypted_content: bytes):
        """Add encrypted message to session history"""
        message = EncryptedMessage(
            message_id=str(uuid.uuid4()),
            sender_id=sender_id,
            encrypted_content=encrypted_content
        )
        
        self.messages.append(message)
        
        # Keep only recent messages to prevent memory bloat
        if len(self.messages) > self.max_messages:
            self.messages = self.messages[-self.max_messages:]
    
    def clear_ephemeral_data(self):
        """Clear all ephemeral data (keys, messages, BB84 data)"""
        self.session_key = None
        self.key_length = 0
        self.messages.clear()
        self.bb84_data.clear()
        self.eve_params = None
        
        # Disconnect all users
        for user in self.users.values():
            user.connected = False
            user.socket_id = None
    
    def is_ready_for_bb84(self) -> bool:
        """Check if session has Alice and Bob to start BB84"""
        alice = self.get_user_by_role(UserRole.ALICE)
        bob = self.get_user_by_role(UserRole.BOB)
        return alice is not None and bob is not None and alice.connected and bob.connected
    
    def has_eve(self) -> bool:
        """Check if Eve is present in session"""
        eve = self.get_user_by_role(UserRole.EVE)
        return eve is not None and eve.connected
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary"""
        return {
            "session_id": self.session_id,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "users": [user.to_dict() for user in self.users.values()],
            "key_length": self.key_length,
            "qber": self.bb84_data.qber,
            "eve_detected": self.bb84_data.eve_detected,
            "message_count": len(self.messages),
            "has_eve": self.has_eve()
        }