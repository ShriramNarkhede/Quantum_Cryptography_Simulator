"""
Session Manager Service for handling QKD sessions
"""

import uuid
import logging
from typing import Dict, Optional, List
from datetime import datetime, timedelta
import threading
import time

from app.models.session import Session, User, UserRole, SessionStatus

logger = logging.getLogger(__name__)


class SessionManager:
    """Manages QKD sessions and user connections"""
    
    def __init__(self, session_timeout_minutes: int = 60):
        self.sessions: Dict[str, Session] = {}
        self.session_timeout = timedelta(minutes=session_timeout_minutes)
        self._lock = threading.RLock()
        
        # Start cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_expired_sessions, daemon=True)
        self._cleanup_thread.start()
        
        logger.info("Session Manager initialized")
    
    def create_session(self) -> Session:
        """Create a new QKD session"""
        with self._lock:
            session_id = str(uuid.uuid4())[:8]  # Short session ID for demo
            session = Session(session_id=session_id)
            self.sessions[session_id] = session
            
            logger.info(f"Created new session: {session_id}")
            return session
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID"""
        with self._lock:
            return self.sessions.get(session_id)
    
    def add_user_to_session(self, session_id: str, role: UserRole) -> Optional[User]:
        """Add user to session with specified role"""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                logger.warning(f"Attempted to add user to non-existent session: {session_id}")
                return None
            
            # Check if session is in valid state for joining
            if session.status == SessionStatus.TERMINATED:
                logger.warning(f"Attempted to join terminated session: {session_id}")
                return None
            
            user = session.add_user(role)
            if user:
                logger.info(f"Added user {user.user_id} as {role.value} to session {session_id}")
                
                # Update session status if both Alice and Bob are present
                if session.is_ready_for_bb84() and session.status == SessionStatus.CREATED:
                    session.status = SessionStatus.ACTIVE
                    logger.info(f"Session {session_id} is now active with Alice and Bob")
            else:
                logger.warning(f"Role {role.value} already taken in session {session_id}")
            
            return user
    
    def remove_user_from_session(self, session_id: str, user_id: str) -> bool:
        """Remove user from session"""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                return False
            
            if user_id in session.users:
                user = session.users[user_id]
                user.connected = False
                user.socket_id = None
                logger.info(f"User {user_id} ({user.role.value}) disconnected from session {session_id}")
                
                # Check if session should be terminated
                connected_users = session.get_connected_users()
                if len(connected_users) == 0:
                    # Mark for cleanup but don't terminate immediately
                    logger.info(f"No users connected to session {session_id}, marking for cleanup")
                
                return True
            
            return False
    
    def terminate_session(self, session_id: str) -> bool:
        """Terminate session and clear all ephemeral data"""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                logger.warning(f"Attempted to terminate non-existent session: {session_id}")
                return False
            
            # Clear all ephemeral data
            session.clear_ephemeral_data()
            session.status = SessionStatus.TERMINATED
            
            logger.info(f"Session {session_id} terminated and ephemeral data cleared")
            
            # Remove from active sessions after a short delay to allow final notifications
            threading.Timer(5.0, lambda: self._remove_session(session_id)).start()
            
            return True
    
    def _remove_session(self, session_id: str):
        """Remove session from memory (called after termination delay)"""
        with self._lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
                logger.info(f"Session {session_id} removed from memory")
    
    def get_active_sessions(self) -> List[Session]:
        """Get list of all active sessions"""
        with self._lock:
            return [
                session for session in self.sessions.values() 
                if session.status != SessionStatus.TERMINATED
            ]
    
    def get_session_stats(self) -> Dict[str, int]:
        """Get statistics about current sessions"""
        with self._lock:
            stats = {
                "total_sessions": len(self.sessions),
                "active_sessions": 0,
                "bb84_running": 0,
                "key_established": 0,
                "compromised": 0,
                "total_users": 0,
                "connected_users": 0
            }
            
            for session in self.sessions.values():
                if session.status == SessionStatus.ACTIVE:
                    stats["active_sessions"] += 1
                elif session.status == SessionStatus.BB84_RUNNING:
                    stats["bb84_running"] += 1
                elif session.status == SessionStatus.KEY_ESTABLISHED:
                    stats["key_established"] += 1
                elif session.status == SessionStatus.COMPROMISED:
                    stats["compromised"] += 1
                
                stats["total_users"] += len(session.users)
                stats["connected_users"] += len(session.get_connected_users())
            
            return stats
    
    def update_user_connection(self, session_id: str, user_id: str, socket_id: str = None, connected: bool = True):
        """Update user connection status and socket ID"""
        with self._lock:
            session = self.sessions.get(session_id)
            if not session:
                return False
            
            user = session.users.get(user_id)
            if not user:
                return False
            
            user.connected = connected
            user.socket_id = socket_id if connected else None
            
            logger.info(f"User {user_id} connection status updated: {connected}")
            return True
    
    def get_session_by_user(self, user_id: str) -> Optional[Session]:
        """Find session containing a specific user"""
        with self._lock:
            for session in self.sessions.values():
                if user_id in session.users:
                    return session
            return None
    
    def _cleanup_expired_sessions(self):
        """Background thread to clean up expired sessions"""
        while True:
            try:
                current_time = datetime.now()
                expired_sessions = []
                
                with self._lock:
                    for session_id, session in self.sessions.items():
                        # Check if session has no connected users and is old
                        if (len(session.get_connected_users()) == 0 and 
                            current_time - session.created_at > self.session_timeout):
                            expired_sessions.append(session_id)
                
                # Terminate expired sessions
                for session_id in expired_sessions:
                    logger.info(f"Auto-terminating expired session: {session_id}")
                    self.terminate_session(session_id)
                
                # Sleep for 5 minutes before next cleanup
                time.sleep(300)
                
            except Exception as e:
                logger.error(f"Error in session cleanup thread: {str(e)}")
                time.sleep(60)  # Wait 1 minute on error before retrying