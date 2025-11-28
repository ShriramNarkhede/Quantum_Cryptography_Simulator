# BB84 QKD System - Complete Component Block Diagram

This document provides a comprehensive block diagram of every individual component in the BB84 Quantum Key Distribution system.

---

## System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          FRONTEND LAYER (React/TypeScript)                   │
│                         http://localhost:5173                                │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ HTTP/WebSocket
                                    │
┌─────────────────────────────────────────────────────────────────────────────┐
│                          BACKEND LAYER (FastAPI/Python)                      │
│                         http://localhost:8000                                │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │
┌─────────────────────────────────────────────────────────────────────────────┐
│                    QUANTUM SIMULATION LAYER (Qiskit)                         │
│                    POST-QUANTUM CRYPTOGRAPHY (PQC)                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Frontend Components (React/TypeScript)

### 1.1 Main Application Component

```
┌─────────────────────────────────────────────────────────────────┐
│                         App.tsx                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ State Management:                                         │  │
│  │ - currentUser: User                                       │  │
│  │ - currentSession: Session                                 │  │
│  │ - sessionKey: Uint8Array                                  │  │
│  │ - bb84Progress: BB84Progress                              │  │
│  │ - cryptoInfo: CryptoInfo                                  │  │
│  │ - messages: SecureMessage[]                               │  │
│  │ - qberHistory: QBERDataPoint[]                            │  │
│  │ - securityViolations: SecurityViolation[]                 │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Event Handlers:                                           │  │
│  │ - handleSessionJoin()                                     │  │
│  │ - handleStartBB84()                                       │  │
│  │ - handleSendMessage()                                     │  │
│  │ - handleFileUpload()                                      │  │
│  │ - handleDecryptMessage()                                  │  │
│  │ - ensureSessionKeyReady()                                 │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ UI Rendering:                                             │  │
│  │ - Header with connection status                           │  │
│  │ - Notifications system                                    │  │
│  │ - Main interface routing                                  │  │
│  │ - Footer with statistics                                  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
```

### 1.2 UI Components

```
┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
│  SessionManager.tsx  │  │  BB84Simulator.tsx   │  │  ChatInterface.tsx   │
├──────────────────────┤  ├──────────────────────┤  ├──────────────────────┤
│ Props:               │  │ Props:               │  │ Props:               │
│ - onSessionJoin()    │  │ - progress           │  │ - messages           │
│ - serverOnline       │  │ - sessionKey         │  │ - onSendMessage()    │
├──────────────────────┤  │ - onStartBB84()      │  │ - onDecryptMessage() │
│ Features:            │  │ - userRole           │  │ - onFileUpload()     │
│ - Create session     │  │ - eveDetected        │  │ - currentUser        │
│ - Join as Alice/Bob/ │  │ - cryptoInfo         │  │ - sessionKey         │
│   Eve                │  │ - qberHistory        │  │ - disabled           │
│ - Session selection  │  ├──────────────────────┤  ├──────────────────────┤
│ - Role assignment    │  │ Features:            │  │ Features:            │
└──────────────────────┘  │ - QBER visualization │  │ - Message display    │
                          │ - Progress bars      │  │ - Encryption status  │
                          │ - Key status         │  │ - File transfer      │
                          │ - Start/Stop controls│  │ - Decrypt buttons    │
                          │ - Retry key button   │  │ - File upload UI     │
                          └──────────────────────┘  └──────────────────────┘

┌──────────────────────┐  ┌──────────────────────┐  ┌──────────────────────┐
│  EveControlPanel.tsx │  │  SecurityDashboard   │  │  CryptoMonitor.tsx   │
├──────────────────────┤  │      .tsx            │  ├──────────────────────┤
│ Props:               │  ├──────────────────────┤  │ Props:               │
│ - sessionId          │  │ Props:               │  │ - cryptoInfo         │
│ - onEveParamsChange()│  │ - cryptoInfo         │  │ - encryptionStatus   │
├──────────────────────┤  │ - qberHistory        │  │ - recommendations    │
│ Features:            │  │ - securityViolations │  ├──────────────────────┤
│ - Attack type select │  │ - sessionHealth      │  │ Features:            │
│ - Intercept-Resend   │  ├──────────────────────┤  │ - Key status display │
│ - Partial intercept  │  │ Features:            │  │ - Security metrics   │
│ - Depolarizing noise │  │ - QBER graphs        │  │ - Recommendations    │
│ - Qubit loss         │  │ - Security violations│  │ - Encryption stats   │
│ - Attack parameters  │  │ - Health score       │  │ - Key age display    │
└──────────────────────┘  │ - Risk assessment    │  └──────────────────────┘
                          └──────────────────────┘
                                    
┌──────────────────────┐
│   StatusBar.tsx      │
├──────────────────────┤
│ Props:               │
│ - currentUser        │
│ - currentSession     │
│ - bb84Progress       │
│ - eveDetected        │
│ - hasSessionKey      │
├──────────────────────┤
│ Features:            │
│ - Session status     │
│ - User role display  │
│ - BB84 progress      │
│ - Security status    │
│ - Key establishment  │
└──────────────────────┘
```

### 1.3 Service Layer

```
┌─────────────────────────────────────────────────────────────────┐
│                      apiService.ts                               │
├─────────────────────────────────────────────────────────────────┤
│ Methods:                                                         │
│ - checkServerHealth()                                            │
│ - createSession()                                                │
│ - joinSession(sessionId, role)                                   │
│ - getSessionStatus(sessionId)                                    │
│ - getSessionSecurity(sessionId)                                  │
│ - getSessionKey(sessionId)                                       │
│ - startBB84Simulation(sessionId, n_bits, test_fraction, hybrid) │
│ - sendEncryptedFile(sessionId, senderId, file)                   │
│ - downloadEncryptedFile(sessionId, messageId, userId)            │
│ - downloadRawEncryptedFile(sessionId, messageId, userId)         │
│ - terminateSession(sessionId)                                    │
│ - handleApiError(error)                                          │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ HTTP REST API
                            │
┌─────────────────────────────────────────────────────────────────┐
│                    socketService.ts                              │
├─────────────────────────────────────────────────────────────────┤
│ Methods:                                                         │
│ - connect()                                                      │
│ - disconnect()                                                   │
│ - joinSession(sessionId, userId)                                 │
│ - sendEncryptedMessage(sessionId, userId, content)               │
│ - requestMessageDecryption(sessionId, messageId, userId)         │
│ - updateEveParams(sessionId, params)                             │
│ Event Listeners:                                                 │
│ - onBB84Started(callback)                                        │
│ - onBB84Progress(callback)                                       │
│ - onBB84Complete(callback)                                       │
│ - onBB84Error(callback)                                          │
│ - onEncryptedMessageReceived(callback)                           │
│ - onMessageDecrypted(callback)                                   │
│ - onEncryptedFileReceived(callback)                              │
│ - onEveDetected(callback)                                        │
│ - onUserJoined(callback)                                         │
│ - onUserDisconnected(callback)                                   │
│ - onSessionTerminated(callback)                                  │
│ - onSecurityViolation(callback)                                  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ WebSocket (Socket.IO)
                            │
┌─────────────────────────────────────────────────────────────────┐
│                    cryptoService.ts                              │
├─────────────────────────────────────────────────────────────────┤
│ State:                                                           │
│ - sessionKey: Uint8Array | null                                  │
│ - cryptoInfo: CryptoInfo | null                                  │
│ - qberHistory: QBERDataPoint[]                                   │
│ - decryptedCache: Map<string, string>                            │
├─────────────────────────────────────────────────────────────────┤
│ Methods:                                                         │
│ - setSessionKey(key: Uint8Array)                                 │
│ - getSessionKey(): Uint8Array | null                             │
│ - updateCryptoInfo(info: CryptoInfo)                             │
│ - addQBERDataPoint(point: QBERDataPoint)                         │
│ - cacheDecryptedContent(messageId, content)                      │
│ - getCachedDecryptedContent(messageId)                           │
│ - getEncryptionStatus()                                          │
│ - getSecurityRecommendations()                                   │
│ - getSessionHealthAssessment()                                   │
│ - clear()                                                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Backend Components (FastAPI/Python)

### 2.1 Main Application

```
┌─────────────────────────────────────────────────────────────────┐
│                         main.py                                 │
├─────────────────────────────────────────────────────────────────┤
│ FastAPI App:                                                    │
│ - app = FastAPI()                                               │
│ - CORS middleware                                                │
│ - Socket.IO server (AsyncServer)                                │
│ - Socket.IO ASGI app                                            │
├─────────────────────────────────────────────────────────────────┤
│ REST API Endpoints:                                             │
│ - GET  /                          (health check)                │
│ - POST /session/create            (create session)              │
│ - POST /session/{id}/join         (join session)                │
│ - GET  /session/{id}/status       (get status)                  │
│ - GET  /session/{id}/security     (get security info)           │
│ - GET  /session/{id}/session_key  (get session key)             │
│ - POST /session/{id}/start_bb84   (start BB84)                  │
│ - POST /session/{id}/send_file    (upload file)                 │
│ - GET  /session/{id}/download_file/{msg_id}  (download file)    │
│ - GET  /session/{id}/pqc/info     (PQC info)                    │
│ - POST /session/{id}/terminate    (terminate session)           │
├─────────────────────────────────────────────────────────────────┤
│ Socket.IO Events:                                               │
│ - connect(sid, environ)                                          │
│ - disconnect(sid)                                                │
│ - join_session_socket(sid, data)                                 │
│ - send_encrypted_message(sid, data)                              │
│ - decrypt_message(sid, data)                                     │
│ - eve_control(sid, data)                                         │
├─────────────────────────────────────────────────────────────────┤
│ Background Tasks:                                               │
│ - run_bb84_simulation()  (async background task)                │
└─────────────────────────────────────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
        ▼                   ▼                   ▼
```

### 2.2 Service Layer

```
┌─────────────────────────────────────────────────────────────────┐
│                  SessionManager (session_manager.py)            │
├─────────────────────────────────────────────────────────────────┤
│ State:                                                           │
│ - sessions: Dict[str, Session]                                  │
│ - session_timeout: timedelta                                    │
│ - _lock: threading.RLock                                        │
├─────────────────────────────────────────────────────────────────┤
│ Methods:                                                         │
│ - create_session() -> Session                                   │
│ - get_session(session_id) -> Optional[Session]                  │
│ - add_user_to_session(session_id, role) -> Optional[User]       │
│ - remove_user_from_session(session_id, user_id) -> bool         │
│ - terminate_session(session_id) -> bool                         │
│ - _cleanup_expired_sessions()  (background thread)              │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ manages
                            │
┌─────────────────────────────────────────────────────────────────┐
│                    BB84Engine (bb84_engine.py)                  │
├─────────────────────────────────────────────────────────────────┤
│ State:                                                           │
│ - qber_threshold: float = 0.11                                   │
│ - simulator: AerSimulator                                       │
│ - final_key: Optional[bytes]                                    │
├─────────────────────────────────────────────────────────────────┤
│ Methods:                                                         │
│ - run_simulation(n_bits, test_fraction, eve_params, eve_module) │
│     -> AsyncGenerator[Dict[str, Any], None]                     │
│ - _generate_alice_data(n_bits) -> Tuple[List[int], List[int]]   │
│ - _prepare_qubits(bits, bases) -> List[Dict[str, Any]]          │
│ - _bob_measurement(qubits_data, n_bits) -> Tuple                │
│ - _sifting(a_bits, a_bases, b_bases, b_results) -> Tuple        │
│ - _compute_qber(a_bits, b_bits, test_fraction) -> Tuple         │
│ - _privacy_amplification(key_bits) -> bytes                     │
│ - get_final_key() -> Optional[bytes]                            │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ uses
                            │
┌─────────────────────────────────────────────────────────────────┐
│                    EveModule (eve_module.py)                    │
├─────────────────────────────────────────────────────────────────┤
│ State:                                                           │
│ - simulator: AerSimulator                                       │
│ - attack_log: List[Dict[str, Any]]                              │
├─────────────────────────────────────────────────────────────────┤
│ Methods:                                                         │
│ - apply_attack(qubits_data, eve_params) -> List[Dict]           │
│ - _intercept_resend_attack(qubits_data, params) -> List[Dict]   │
│ - _partial_intercept_attack(qubits_data, params) -> List[Dict]  │
│ - _depolarizing_attack(qubits_data, params) -> List[Dict]       │
│ - _qubit_loss_attack(qubits_data, params) -> List[Dict]         │
│ - _measure_qubit(circuit, basis) -> int                         │
│ - _prepare_new_qubit(bit, basis, original) -> Dict              │
│ - get_attack_stats() -> Dict[str, Any]                          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                  CryptoService (crypto_service.py)              │
├─────────────────────────────────────────────────────────────────┤
│ State:                                                           │
│ - derived_keys: Optional[DerivedKeys]                           │
│ - message_seq_counter: int = 0                                  │
│ - file_seq_counter: int = 0                                     │
│ - used_key_stream_offsets: List[Tuple[int, int]]                │
│ - session_id: Optional[str] = None                              │
├─────────────────────────────────────────────────────────────────┤
│ Methods:                                                         │
│ - derive_keys(master_key, session_id) -> DerivedKeys            │
│ - create_hybrid_key(bb84_key, pqc_key, session_id) -> DerivedKeys│
│ - encrypt_message_otp(plaintext) -> EncryptedMessage            │
│ - decrypt_message_otp(encrypted_msg) -> str                     │
│ - encrypt_file_xchacha20(file_data, filename) -> EncryptedFile  │
│ - decrypt_file_xchacha20(encrypted_file) -> Tuple[bytes, str]   │
│ - _generate_key_stream(length, seq_no) -> bytes                 │
│ - get_pqc_public_keys() -> Dict[str, bytes]                     │
│ - encapsulate_shared_secret(peer_public_key) -> Tuple           │
│ - decapsulate_shared_secret(ciphertext) -> bytes                │
│ - sign_message_pqc(message) -> bytes                            │
│ - verify_signature_pqc(signature, message, public_key) -> bool  │
│ - get_session_stats() -> Dict[str, Any]                         │
│ - clear_session()                                                │
└─────────────────────────────────────────────────────────────────┘
                            │
                            │ uses
                            │
┌─────────────────────────────────────────────────────────────────┐
│                   PQCService (pqc_service.py)                   │
├─────────────────────────────────────────────────────────────────┤
│ State:                                                           │
│ - use_liboqs: bool                                              │
│ - kem_available: bool                                           │
│ - sig_available: bool                                           │
├─────────────────────────────────────────────────────────────────┤
│ Methods:                                                         │
│ - generate_kyber_keypair() -> KyberKeyPair                      │
│ - encapsulate_key(public_key) -> KyberCiphertext                │
│ - decapsulate_key(ciphertext, private_key) -> bytes             │
│ - generate_dilithium_keypair() -> DilithiumKeyPair              │
│ - sign_message(message, private_key) -> bytes                   │
│ - verify_signature(signature, message, public_key) -> bool      │
│ - get_pqc_info() -> Dict[str, Any]                              │
│ - clear_keys(keypair)                                            │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 Data Models

```
┌─────────────────────────────────────────────────────────────────┐
│                    Session Model (session.py)                   │
├─────────────────────────────────────────────────────────────────┤
│ Classes:                                                         │
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ User                                                       │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - user_id: str                                            │  │
│ │ - role: UserRole (ALICE, BOB, EVE)                        │  │
│ │ - connected: bool                                         │  │
│ │ - socket_id: Optional[str]                                │  │
│ │ - joined_at: datetime                                     │  │
│ │ - last_activity: datetime                                 │  │
│ └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ Session                                                    │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - session_id: str                                         │  │
│ │ - users: Dict[str, User]                                  │  │
│ │ - status: SessionStatus                                   │  │
│ │ - created_at: datetime                                    │  │
│ │ - bb84_data: BB84Data                                     │  │
│ │ - crypto_session: CryptoSession                           │  │
│ │ - eve_params: Optional[Dict[str, Any]]                    │  │
│ │ - messages: List[SecureMessage]                           │  │
│ │ - max_messages: int = 100                                 │  │
│ │ - qber_threshold: float = 0.11                            │  │
│ │ - metrics: SessionMetrics                                 │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ Methods:                                                   │  │
│ │ - add_user(role) -> Optional[User]                        │  │
│ │ - get_user_by_role(role) -> Optional[User]                │  │
│ │ - establish_secure_session(bb84_key, pqc_key) -> bool     │  │
│ │ - add_secure_message(sender_id, content, type)            │  │
│ │ - decrypt_message(secure_msg) -> Optional[str]            │  │
│ │ - add_encrypted_file(sender_id, file_data, filename)      │  │
│ │ - decrypt_file(secure_msg) -> Optional[Tuple]             │  │
│ │ - terminate()                                              │  │
│ └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ BB84Data                                                   │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - alice_bits: Optional[List[int]]                         │  │
│ │ - alice_bases: Optional[List[int]]                        │  │
│ │ - bob_bases: Optional[List[int]]                          │  │
│ │ - bob_results: Optional[List[int]]                        │  │
│ │ - sifted_key: Optional[List[int]]                         │  │
│ │ - test_bits_positions: Optional[List[int]]                │  │
│ │ - qber: Optional[float]                                   │  │
│ │ - eve_detected: bool                                      │  │
│ │ - final_key_length: int                                   │  │
│ └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ CryptoSession                                              │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - crypto_service: Optional[CryptoService]                 │  │
│ │ - derived_keys: Optional[DerivedKeys]                     │  │
│ │ - key_established: bool                                   │  │
│ │ - hybrid_mode: bool                                       │  │
│ │ - pqc_shared_secret: Optional[bytes]                      │  │
│ │ - key_establishment_time: Optional[datetime]              │  │
│ └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ SecureMessage                                              │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - message_id: str                                         │  │
│ │ - sender_id: str                                          │  │
│ │ - message_type: MessageType                               │  │
│ │ - encrypted_payload: Dict[str, Any]                       │  │
│ │ - timestamp: datetime                                     │  │
│ │ - seq_no: Optional[int]                                   │  │
│ │ - verified: bool                                          │  │
│ │ - size_bytes: int                                         │  │
│ └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ SessionMetrics                                             │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - creation_time: datetime                                 │  │
│ │ - bb84_start_time: Optional[datetime]                     │  │
│ │ - bb84_completion_time: Optional[datetime]                │  │
│ │ - total_messages_sent: int                                │  │
│ │ - total_files_sent: int                                   │  │
│ │ - total_bytes_encrypted: int                              │  │
│ │ - peak_qber: float                                        │  │
│ │ - eve_detection_events: int                               │  │
│ │ - security_violations: List[str]                          │  │
│ └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. External Dependencies

```
┌─────────────────────────────────────────────────────────────────┐
│                    Quantum Simulation Layer                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ Qiskit                                                     │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - QuantumCircuit: Quantum circuit construction            │  │
│ │ - AerSimulator: Quantum state simulation                  │  │
│ │ - Statevector: Quantum state representation               │  │
│ │ - QuantumRegister: Quantum register management            │  │
│ │ - ClassicalRegister: Classical bit storage                │  │
│ └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│ Used by:                                                         │
│ - BB84Engine: For qubit preparation and measurement             │
│ - EveModule: For attack simulation                              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│              Post-Quantum Cryptography Libraries                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ liboqs-python (Primary)                                   │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - Kyber512: Key encapsulation mechanism (KEM)             │  │
│ │ - Dilithium2: Digital signature algorithm                 │  │
│ │ - NIST-approved implementations                           │  │
│ └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ pqcrypto (Fallback)                                       │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - Pure Python implementations                             │  │
│ │ - Kyber512 KEM                                            │  │
│ │ - Dilithium2 signatures                                   │  │
│ └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│ Used by:                                                         │
│ - PQCService: For PQC key generation and operations             │
│ - CryptoService: For hybrid key derivation                      │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                  Cryptographic Libraries                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ cryptography (Python)                                     │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - HKDF: Key derivation function                           │  │
│ │ - SHA-256: Hashing algorithm                              │  │
│ │ - ChaCha20Poly1305: AEAD encryption                       │  │
│ └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ PyNaCl (libsodium bindings)                               │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - XChaCha20-Poly1305: Extended nonce ChaCha20             │  │
│ │ - crypto_aead_xchacha20poly1305_ietf_encrypt              │  │
│ │ - crypto_aead_xchacha20poly1305_ietf_decrypt              │  │
│ └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ hashlib (Python standard library)                         │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - SHA-256: For privacy amplification                      │  │
│ │ - SHA3-256: For HMAC authentication                       │  │
│ └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│ Used by:                                                         │
│ - CryptoService: For all cryptographic operations               │
│ - BB84Engine: For privacy amplification                         │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    Web Framework & Communication                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ FastAPI                                                    │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - REST API endpoints                                       │  │
│ │ - CORS middleware                                          │  │
│ │ - Request/response handling                                │  │
│ └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ python-socketio (Socket.IO)                               │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - AsyncServer: WebSocket server                           │  │
│ │ - ASGIApp: ASGI application wrapper                       │  │
│ │ - Real-time event handling                                │  │
│ │ - Room management                                          │  │
│ └───────────────────────────────────────────────────────────┘  │
│                                                                  │
│ ┌───────────────────────────────────────────────────────────┐  │
│ │ Uvicorn                                                    │  │
│ ├───────────────────────────────────────────────────────────┤  │
│ │ - ASGI server                                              │  │
│ │ - HTTP/WebSocket server                                    │  │
│ └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Complete Data Flow Diagram

```
┌──────────────┐
│   Browser    │
│  (Frontend)  │
└──────┬───────┘
       │
       │ 1. Create Session (HTTP POST)
       ▼
┌─────────────────────────────────────┐
│  FastAPI: POST /session/create      │
│  └─> SessionManager.create_session()│
└──────┬──────────────────────────────┘
       │
       │ 2. Return session_id
       ▼
┌──────────────┐
│   Browser    │
│  (Frontend)  │
└──────┬───────┘
       │
       │ 3. Join Session (HTTP POST)
       ▼
┌─────────────────────────────────────┐
│  FastAPI: POST /session/{id}/join   │
│  └─> SessionManager.add_user_to_    │
│      session(session_id, role)      │
└──────┬──────────────────────────────┘
       │
       │ 4. Join WebSocket Room
       ▼
┌─────────────────────────────────────┐
│  Socket.IO: join_session_socket     │
│  └─> sio.enter_room(sid, room)     │
└──────┬──────────────────────────────┘
       │
       │ 5. Start BB84 (HTTP POST)
       ▼
┌─────────────────────────────────────┐
│  FastAPI: POST /session/{id}/       │
│            start_bb84               │
│  └─> asyncio.create_task(           │
│      run_bb84_simulation())         │
└──────┬──────────────────────────────┘
       │
       │ 6. BB84 Simulation
       ▼
┌─────────────────────────────────────┐
│  BB84Engine.run_simulation()        │
│  ├─> Generate Alice bits/bases      │
│  ├─> Prepare qubits (Qiskit)        │
│  ├─> [If Eve] Apply attack          │
│  ├─> Bob measurement (Qiskit)       │
│  ├─> Sifting                        │
│  ├─> QBER calculation               │
│  └─> Privacy amplification (SHA-256)│
└──────┬──────────────────────────────┘
       │
       │ 7. Emit Progress (WebSocket)
       ▼
┌─────────────────────────────────────┐
│  Socket.IO: bb84_progress events    │
│  └─> Frontend receives updates      │
└──────┬──────────────────────────────┘
       │
       │ 8. Key Establishment
       ▼
┌─────────────────────────────────────┐
│  Session.establish_secure_session() │
│  ├─> CryptoService.derive_keys()    │
│  │   └─> HKDF-SHA256                │
│  ├─> [If Hybrid] PQC key exchange   │
│  │   └─> Kyber512 KEM               │
│  └─> Store derived keys             │
└──────┬──────────────────────────────┘
       │
       │ 9. Emit Complete (WebSocket)
       ▼
┌─────────────────────────────────────┐
│  Socket.IO: bb84_complete event     │
│  └─> Frontend fetches session key   │
└──────┬──────────────────────────────┘
       │
       │ 10. Get Session Key (HTTP GET)
       ▼
┌─────────────────────────────────────┐
│  FastAPI: GET /session/{id}/        │
│            session_key              │
│  └─> Return key_file (hex string)   │
└──────┬──────────────────────────────┘
       │
       │ 11. Send Message (WebSocket)
       ▼
┌─────────────────────────────────────┐
│  Socket.IO: send_encrypted_message  │
│  └─> Session.add_secure_message()   │
│      └─> CryptoService.             │
│          encrypt_message_otp()      │
│          ├─> Generate key stream    │
│          ├─> XOR encryption         │
│          └─> HMAC-SHA3-256          │
└──────┬──────────────────────────────┘
       │
       │ 12. Broadcast Message
       ▼
┌─────────────────────────────────────┐
│  Socket.IO: encrypted_message_      │
│            received event           │
│  └─> All clients receive message    │
└──────┬──────────────────────────────┘
       │
       │ 13. Decrypt Message (WebSocket)
       ▼
┌─────────────────────────────────────┐
│  Socket.IO: decrypt_message         │
│  └─> Session.decrypt_message()      │
│      └─> CryptoService.             │
│          decrypt_message_otp()      │
│          ├─> Verify HMAC            │
│          ├─> Generate key stream    │
│          └─> XOR decryption         │
└──────┬──────────────────────────────┘
       │
       │ 14. Return Plaintext
       ▼
┌─────────────────────────────────────┐
│  Socket.IO: message_decrypted event │
│  └─> Frontend displays message      │
└─────────────────────────────────────┘
```

---

## 5. Component Interaction Matrix

| Component | Interacts With | Interaction Type | Purpose |
|-----------|---------------|------------------|---------|
| **App.tsx** | SessionManager | Component → Component | Session creation/joining |
| **App.tsx** | apiService | Component → Service | REST API calls |
| **App.tsx** | socketService | Component → Service | WebSocket communication |
| **App.tsx** | cryptoService | Component → Service | Key management |
| **SessionManager** | apiService | Component → Service | Session operations |
| **BB84Simulator** | socketService | Component → Service | BB84 events |
| **ChatInterface** | socketService | Component → Service | Message sending |
| **ChatInterface** | apiService | Component → Service | File upload/download |
| **EveControlPanel** | socketService | Component → Service | Eve attack control |
| **SecurityDashboard** | cryptoService | Component → Service | Security metrics |
| **apiService** | FastAPI Backend | Service → Backend | HTTP REST API |
| **socketService** | Socket.IO Server | Service → Backend | WebSocket events |
| **main.py** | SessionManager | Backend → Service | Session management |
| **main.py** | BB84Engine | Backend → Service | BB84 simulation |
| **main.py** | CryptoService | Backend → Service | Cryptography |
| **main.py** | EveModule | Backend → Service | Attack simulation |
| **SessionManager** | Session Model | Service → Model | Session state |
| **BB84Engine** | Qiskit | Service → Library | Quantum simulation |
| **BB84Engine** | EveModule | Service → Service | Attack application |
| **CryptoService** | PQCService | Service → Service | PQC operations |
| **CryptoService** | cryptography | Service → Library | Cryptographic primitives |
| **PQCService** | liboqs/pqcrypto | Service → Library | PQC algorithms |
| **Session Model** | CryptoService | Model → Service | Key establishment |

---

## 6. Key Storage and State Management

```
┌─────────────────────────────────────────────────────────────────┐
│                    In-Memory State Storage                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│ SessionManager.sessions: Dict[str, Session]                     │
│   └─> Session.session_id -> Session object                      │
│       ├─> Session.users: Dict[str, User]                        │
│       ├─> Session.bb84_data: BB84Data                           │
│       ├─> Session.crypto_session: CryptoSession                 │
│       │   └─> CryptoSession.derived_keys: DerivedKeys           │
│       │       ├─> key_stream_seed: bytes (32 bytes)             │
│       │       ├─> key_mac: bytes (32 bytes)                     │
│       │       ├─> key_file: bytes (32 bytes)                    │
│       │       └─> master_key: bytes (32 bytes)                  │
│       ├─> Session.messages: List[SecureMessage]                 │
│       └─> Session.metrics: SessionMetrics                       │
│                                                                  │
│ CryptoService State (per session):                              │
│   ├─> sessionKey: Uint8Array (32 bytes) - Frontend             │
│   ├─> message_seq_counter: int                                  │
│   ├─> file_seq_counter: int                                     │
│   └─> used_key_stream_offsets: List[Tuple[int, int]]           │
│                                                                  │
│ Frontend State (React):                                         │
│   ├─> currentUser: User                                         │
│   ├─> currentSession: Session                                   │
│   ├─> sessionKey: Uint8Array                                    │
│   ├─> messages: SecureMessage[]                                 │
│   ├─> qberHistory: QBERDataPoint[]                              │
│   └─> securityViolations: SecurityViolation[]                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 7. Security Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Boundary Diagram                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  CLIENT SIDE (Browser) - Less Trusted                    │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │ Frontend Components                                 │  │  │
│  │  │ - React UI Components                               │  │  │
│  │  │ - Session Key (encrypted in transit)                │  │  │
│  │  │ - Encrypted Messages (ciphertext only)              │  │  │
│  │  └────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                            │                                     │
│                    HTTPS/WSS (TLS)                               │
│                            │                                     │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  SERVER SIDE (Backend) - Trusted                         │  │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │ Session Management                                  │  │  │
│  │  │ - Session keys (in memory only)                     │  │  │
│  │  │ - User authentication                               │  │  │
│  │  │ - Access control                                    │  │  │
│  │  └────────────────────────────────────────────────────┘  │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │ Cryptographic Services                              │  │  │
│  │  │ - Key derivation (HKDF)                             │  │  │
│  │  │ - Message encryption/decryption                     │  │  │
│  │  │ - File encryption (XChaCha20-Poly1305)              │  │  │
│  │  │ - HMAC verification                                 │  │  │
│  │  └────────────────────────────────────────────────────┘  │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │ BB84 Engine                                         │  │  │
│  │  │ - Quantum state preparation                         │  │  │
│  │  │ - QBER calculation                                  │  │  │
│  │  │ - Privacy amplification                             │  │  │
│  │  │ - Final key generation                              │  │  │
│  │  └────────────────────────────────────────────────────┘  │  │
│  │  ┌────────────────────────────────────────────────────┐  │  │
│  │  │ PQC Service                                         │  │  │
│  │  │ - Kyber key generation                              │  │  │
│  │  │ - Dilithium signatures                              │  │  │
│  │  │ - Hybrid key combination                            │  │  │
│  │  └────────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Key Security Principles:                                        │
│  - Keys never leave server (except encrypted session key)        │
│  - All keys cleared on session termination                       │
│  - HMAC verification on all messages                             │
│  - QBER threshold enforcement                                    │
│  - Eve detection and session termination                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8. File Structure Overview

```
bb84-qkd-system/
├── frontend/
│   ├── src/
│   │   ├── App.tsx                    # Main application component
│   │   ├── components/
│   │   │   ├── SessionManager.tsx     # Session management UI
│   │   │   ├── BB84Simulator.tsx      # BB84 simulation UI
│   │   │   ├── ChatInterface.tsx      # Chat interface UI
│   │   │   ├── EveControlPanel.tsx    # Eve attack controls
│   │   │   ├── SecurityDashboard.tsx  # Security metrics dashboard
│   │   │   ├── CryptoMonitor.tsx      # Crypto status monitor
│   │   │   └── StatusBar.tsx          # Status bar component
│   │   ├── services/
│   │   │   ├── apiService.ts          # REST API client
│   │   │   ├── socketService.ts       # WebSocket client
│   │   │   └── cryptoService.ts       # Client-side crypto utilities
│   │   └── types/
│   │       └── index.ts               # TypeScript type definitions
│   └── package.json
│
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI application
│   │   ├── models/
│   │   │   └── session.py             # Session and user models
│   │   └── services/
│   │       ├── session_manager.py     # Session management service
│   │       ├── bb84_engine.py         # BB84 protocol engine
│   │       ├── crypto_service.py      # Cryptographic service
│   │       ├── eve_module.py          # Eve attack module
│   │       └── pqc_service.py         # Post-quantum crypto service
│   └── requirements.txt
│
└── README files
    ├── README_SYSTEM_ARCHITECTURE.md
    ├── README_SYSTEM_COMPONENTS.md
    ├── README_CRYPTO.md
    └── README_PQC.md
```

---

## Summary

This document provides a complete block diagram of all individual components in the BB84 QKD system:

1. **Frontend Components**: 8 React components + 3 service modules
2. **Backend Components**: 1 main application + 5 service modules + data models
3. **External Dependencies**: Qiskit, PQC libraries, cryptographic libraries
4. **Communication**: REST API (HTTP) + WebSocket (Socket.IO)
5. **State Management**: In-memory sessions with secure key storage
6. **Security**: Multi-layer security with key isolation and verification

Each component has well-defined responsibilities and interfaces, enabling secure quantum key distribution with post-quantum cryptography support.





















