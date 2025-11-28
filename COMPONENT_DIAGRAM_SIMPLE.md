# BB84 QKD System - Simplified Component Diagram

## Quick Reference: All Components

### Frontend (React/TypeScript)
```
App.tsx
├── SessionManager.tsx      [Session creation/joining UI]
├── BB84Simulator.tsx       [BB84 protocol visualization]
├── ChatInterface.tsx       [Encrypted messaging UI]
├── EveControlPanel.tsx     [Eve attack controls]
├── SecurityDashboard.tsx   [Security metrics dashboard]
├── CryptoMonitor.tsx       [Crypto status display]
├── StatusBar.tsx          [Status information bar]
│
├── apiService.ts          [REST API client]
├── socketService.ts       [WebSocket client]
└── cryptoService.ts       [Client-side crypto utilities]
```

### Backend (FastAPI/Python)
```
main.py (FastAPI Application)
├── REST Endpoints:
│   ├── POST /session/create
│   ├── POST /session/{id}/join
│   ├── GET  /session/{id}/status
│   ├── GET  /session/{id}/security
│   ├── GET  /session/{id}/session_key
│   ├── POST /session/{id}/start_bb84
│   ├── POST /session/{id}/send_file
│   ├── GET  /session/{id}/download_file/{msg_id}
│   └── POST /session/{id}/terminate
│
├── Socket.IO Events:
│   ├── connect
│   ├── disconnect
│   ├── join_session_socket
│   ├── send_encrypted_message
│   ├── decrypt_message
│   └── eve_control
│
└── Services:
    ├── SessionManager        [Session lifecycle management]
    ├── BB84Engine           [Quantum key distribution]
    ├── EveModule            [Eavesdropper simulation]
    ├── CryptoService        [Encryption/decryption]
    └── PQCService           [Post-quantum cryptography]
```

### Data Models
```
Session Model (session.py)
├── User                    [User with role: Alice/Bob/Eve]
├── Session                 [Session state and data]
├── BB84Data               [BB84 protocol data]
├── CryptoSession          [Cryptographic session state]
├── SecureMessage          [Encrypted message]
└── SessionMetrics         [Session performance metrics]
```

### External Libraries
```
Quantum Simulation:
└── Qiskit                 [Quantum circuit simulation]

Post-Quantum Cryptography:
├── liboqs-python          [Primary PQC library]
└── pqcrypto               [Fallback PQC library]

Cryptography:
├── cryptography           [HKDF, ChaCha20Poly1305]
├── PyNaCl                 [XChaCha20-Poly1305]
└── hashlib                [SHA-256, SHA3-256]

Web Framework:
├── FastAPI                [REST API framework]
├── python-socketio        [WebSocket server]
└── Uvicorn                [ASGI server]
```

## Component Count Summary

- **Frontend Components**: 8 React components
- **Frontend Services**: 3 service modules
- **Backend Services**: 5 service modules
- **Backend Models**: 6 data model classes
- **REST Endpoints**: 10 endpoints
- **Socket.IO Events**: 6 event handlers
- **External Libraries**: 10+ libraries

**Total Individual Components: 48+**

## Data Flow Summary

```
User Browser
    ↓
Frontend (React)
    ↓ HTTP/WebSocket
Backend (FastAPI)
    ↓
Services (SessionManager, BB84Engine, CryptoService)
    ↓
External Libraries (Qiskit, PQC, Cryptography)
    ↓
Quantum Simulation / Key Generation
    ↓
Secure Communication
```

## Key Interactions

1. **Session Creation**: Frontend → API → SessionManager → Session Model
2. **BB84 Protocol**: Frontend → API → BB84Engine → Qiskit → Key Generation
3. **Message Encryption**: Frontend → WebSocket → CryptoService → Encryption
4. **File Transfer**: Frontend → API → CryptoService → File Encryption
5. **Eve Attacks**: Frontend → WebSocket → EveModule → BB84Engine
6. **PQC Operations**: CryptoService → PQCService → liboqs/pqcrypto

For detailed diagrams, see `COMPONENT_BLOCK_DIAGRAM.md`.





















