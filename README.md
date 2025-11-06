# 🔐 Hybrid Quantum + Post-Quantum Secure Communication System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![React](https://img.shields.io/badge/React-18+-61dafb.svg)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-4.0+-3178c6.svg)](https://www.typescriptlang.org/)

### End-to-End Encrypted Message & File Exchange using BB84 Quantum Key Distribution and CRYSTALS-Kyber Post-Quantum Cryptography

---

## 📘 Overview

This project implements a **quantum-resilient communication system** that combines **BB84 Quantum Key Distribution (QKD)** and **CRYSTALS-Kyber** (a NIST-approved Post-Quantum Key Encapsulation Mechanism) to achieve **hybrid key generation**.

It uses **HKDF** to derive session keys for secure **message** and **file exchange** between two users (Alice and Bob). Messages are protected using a **deterministic one-time stream (OTP-style XOR)** with **HMAC-SHA3** authentication, and files are secured with **XChaCha20-Poly1305 AEAD** encryption.

### Key Security Features:
- ✅ **Quantum safety** - Resistant to quantum attacks
- ✅ **Tamper detection** - HMAC-SHA3 integrity verification
- ✅ **Forward secrecy** - Session-based key rotation
- ✅ **Authenticated encryption** - AEAD for files, HMAC for messages
- ✅ **Eavesdropping detection** - BB84 QBER monitoring
- ✅ **Replay protection** - Sequence numbers & timestamps

---

## 🧩 System Architecture

```
      ┌───────────────────────────────┐
      │         Key Exchange           │
      │───────────────────────────────│
      │   BB84 Quantum Key (Kqkd)     │
      │ + Kyber Post-Quantum Key (Kpqc)│
      └──────────────┬────────────────┘
                     │
                     ▼
           HKDF Derivation Phase
   ┌───────────────────────────────────────┐
   │ Derive Independent Session Keys:       │
   │   key_stream_seed → Message Encryption │
   │   key_mac        → Message Auth        │
   │   key_file       → File Encryption     │
   └──────────────────┬────────────────────┘
                      │
      ┌───────────────┼───────────────────┐
      ▼                                   ▼
Secure Message Exchange          Secure File Exchange
(OTP + HMAC-SHA3)               (XChaCha20-Poly1305 AEAD)
      │                                   │
      ▼                                   ▼
End-to-End Encrypted Chat        End-to-End Encrypted Files
```

---

## ⚙️ Workflow (Step-by-Step)

### 1️⃣ Quantum Key Distribution (BB84)
- Alice and Bob exchange qubits with random bases
- Matching bases produce identical bits → **Quantum Key (Kqkd)**
- Eavesdropping detection via Quantum Bit Error Rate (QBER)

### 2️⃣ Post-Quantum Key Exchange (Kyber)
- Kyber generates a **shared classical key (Kpqc)** using lattice-based cryptography
- Resistant to quantum attacks

### 3️⃣ Hybrid Key Creation
The final **Initial Key Material (IKM)** is:
```
IKM = Kqkd || Kpqc
```

### 4️⃣ HKDF Derivation
The hybrid key is passed through **HKDF (HMAC-SHA256)** with session ID as salt:
```
key_stream_seed = HKDF-Expand(PRK, "otp-stream")
key_mac = HKDF-Expand(PRK, "hmac-key")
key_file = HKDF-Expand(PRK, "file-key")
```

### 5️⃣ Secure Message Exchange

**Encryption:**
- Derive a unique key stream segment per message:
  ```
  key_stream = HKDF-Expand(key_stream_seed, "msg-<seq>-<session>")
  ciphertext = plaintext XOR key_stream
  ```
- Compute integrity tag:
  ```
  tag = HMAC_SHA3_256(key_mac, AAD || ciphertext)
  ```
- Send `{ciphertext, tag, seq_no, timestamp, session_id}`

**Decryption:**
- Verify tag → regenerate same key stream → XOR decrypt

✅ **Provides confidentiality + integrity**

### 6️⃣ Secure File Exchange
Uses **XChaCha20-Poly1305 AEAD**:
- Random 24-byte `nonce`
- AAD includes `session_id + file_seq + filename`
- Encrypts file content + generates authentication tag

**Encryption:**
```
ciphertext, tag = XChaCha20_Encrypt(key_file, nonce, AAD, file_bytes)
```

**Decryption:**
```
plaintext = XChaCha20_Decrypt(key_file, nonce, AAD, ciphertext, tag)
```

✅ **Ensures confidentiality, authenticity, and replay protection**

### 7️⃣ Session Management
- Session created between Alice and Bob → `session_id = S-12345`
- On high QBER or logout, all keys are **securely deleted**
- Session state and history are cleared for privacy

---

## 🧠 Example Flow

**Session:** `S-67890`  
**Message:** `"Hello Bob"`  
**File:** `report.pdf`

| Step | Action | Result |
|------|---------|--------|
| 1 | Run BB84 | Kqkd = `101101...` |
| 2 | Run Kyber | Kpqc = `a4c1e29f...` |
| 3 | Combine Keys | IKM = `Kqkd \|\| Kpqc` |
| 4 | HKDF Derivation | Derives `key_stream_seed`, `key_mac`, `key_file` |
| 5 | Message Encryption | Ciphertext = `baff70e85c3196107b`<br>Tag = `3af092be45e1...` |
| 6 | File Encryption | Nonce = random(24B)<br>AEAD Tag = valid |
| 7 | Receiver Verification | Tag matches → "Hello Bob" decrypted<br>`report.pdf` verified and restored |

---

## 🔒 Security Features

| Feature | Description |
|----------|--------------|
| **Quantum-Safe Key Exchange** | BB84 + Kyber hybrid ensures defense against classical & quantum attacks |
| **Session-Based Key Derivation** | HKDF binds all keys to session ID (prevents cross-session reuse) |
| **Unique Per-Message Encryption** | Deterministic one-time stream (no key reuse) |
| **Integrity Verification** | HMAC (SHA3-256) and AEAD ensure tamper detection |
| **Forward Secrecy** | Each session regenerates keys; old messages stay safe |
| **Replay Protection** | Sequence numbers & timestamps prevent replays |

---

## 🧮 Comparative Summary

| Component | Our System | AES-GCM | WhatsApp (Signal Protocol) |
|------------|-------------|----------|-----------------------------|
| **Key Source** | BB84 + Kyber (Hybrid) | Classical (ECDH/TLS) | Curve25519 + Ratcheting |
| **Quantum Resistance** | ✅ Yes | ❌ No | ❌ No |
| **Message Encryption** | OTP-Style XOR + HMAC | AES-256-GCM | AES-256-CBC/GCM |
| **File Encryption** | XChaCha20-Poly1305 | AES-GCM | AES-GCM |
| **Integrity Check** | HMAC (SHA3) | Built-in GCM Tag | HMAC-SHA256 |
| **Eavesdrop Detection** | ✅ BB84 | ❌ | ❌ |
| **Forward Secrecy** | ✅ | Optional | ✅ |
| **Replay Protection** | ✅ | Partial | ✅ |

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Quantum Key Simulation** | Python (BB84 Engine) |
| **Post-Quantum Crypto** | Kyber (PQC module) |
| **Key Derivation** | HKDF (HMAC-SHA256) |
| **Message Encryption** | XOR-Stream + HMAC (SHA3-256) |
| **File Encryption** | XChaCha20-Poly1305 (AEAD) |
| **Backend** | Python (FastAPI + Socket.IO) |
| **Frontend** | React.js + TypeScript |
| **Database** | Firebase / Firestore (Session, Users) |

---

## 📁 Directory Structure

```
backend/
 ├── app/
 │   ├── main.py                     # Session orchestration
 │   ├── models/session.py           # Session & message models
 │   ├── services/
 │   │   ├── bb84_engine.py          # Quantum key generation
 │   │   ├── pqc_service.py          # Kyber key encapsulation
 │   │   ├── crypto_service.py       # HKDF, HMAC, XOR, AEAD logic
 │   │   └── eve_module.py           # Eavesdrop simulation (optional)
 │   └── utils/
 │       └── helpers.py              # Helper utilities
frontend/
 ├── src/
 │   ├── components/                 # UI components
 │   ├── services/                   # Socket, crypto, API layers
 │   ├── pages/                      # Chat, File, Session UI
 │   └── main.tsx                    # Entry point
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8+
- Node.js 16+
- npm or yarn

### Backend Setup
```bash
cd backend
pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

### Frontend Setup
```bash
cd frontend
npm install
npm start
```

### Environment Variables
Create `.env` files in both backend and frontend directories with appropriate configuration.

---

## 💻 Usage Example

```python
# Derive hybrid key
hybrid_key = hkdf_extract(b"S-67890", Kqkd + Kpqc)

# Encrypt message
ciphertext = xor_encrypt("Hello Bob", key_stream_seed)
tag = hmac_sha3(key_mac, aad + ciphertext)

# Encrypt file
ciphertext, tag = xchacha20_poly1305_encrypt(key_file, nonce, aad, file_bytes)
```

### Example Use-Case Scenario:
1. Alice and Bob start a chat session using the system
2. BB84 and Kyber generate hybrid keys
3. HKDF derives message and file encryption keys
4. Alice sends "Hello Bob" → Encrypted, tagged, verified
5. Alice uploads report.pdf → Encrypted with AEAD, tag verified
6. Bob decrypts both securely
7. Session terminates, all keys erased

✅ **End-to-End confidentiality, integrity, and quantum safety achieved**

---

## 🔧 API Endpoints

### Session Management
- `POST /api/session/create` - Create new session
- `POST /api/session/join` - Join existing session
- `DELETE /api/session/{session_id}` - Terminate session

### Messaging
- `POST /api/message/send` - Send encrypted message
- `GET /api/message/history/{session_id}` - Get message history

### File Transfer
- `POST /api/file/upload` - Upload encrypted file
- `GET /api/file/download/{file_id}` - Download encrypted file

---

## 🧪 Testing

```bash
# Backend tests
cd backend
python -m pytest tests/

# Frontend tests
cd frontend
npm test
```

---

## 📚 References

- [NIST PQC Standardization: CRYSTALS-Kyber](https://csrc.nist.gov/projects/post-quantum-cryptography/selected-algorithms-2022)
- [BB84 Quantum Key Distribution Protocol](https://en.wikipedia.org/wiki/BB84)
- [RFC 5869: HKDF Key Derivation Function](https://tools.ietf.org/html/rfc5869)
- [XChaCha20-Poly1305 AEAD Spec](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha)
- [SHA-3 / Keccak Standard (FIPS 202)](https://csrc.nist.gov/publications/detail/fips/202/final)

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Developer

**Narkhede Shriram Sharad**  
B.E. Information Technology — Trinity College of Engineering & Research, Pune  
Project: Hybrid Quantum + Post-Quantum Secure Communication System

---

## ⚠️ Disclaimer

This is a research project demonstrating quantum and post-quantum cryptographic concepts. While the implementation follows security best practices, it should not be used in production environments without thorough security auditing and testing.

---

## 🔮 Future Enhancements

- [ ] Real quantum hardware integration
- [ ] Multi-party quantum key distribution
- [ ] Advanced post-quantum algorithms (Dilithium, SPHINCS+)
- [ ] Mobile application support
- [ ] Enhanced UI/UX with quantum visualization
- [ ] Performance optimization for large files
- [ ] Cross-platform compatibility improvements