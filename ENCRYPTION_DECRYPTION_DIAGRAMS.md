# BB84 QKD System - Encryption/Decryption Block Diagrams

This document provides detailed block diagrams for message and file encryption/decryption processes in the BB84 QKD system.

---

## Table of Contents

1. [Message Encryption/Decryption Flow](#1-message-encryptiondecryption-flow)
2. [File Encryption/Decryption Flow](#2-file-encryptiondecryption-flow)
3. [Key Derivation Process](#3-key-derivation-process)
4. [Security Components](#4-security-components)

---

## 1. Message Encryption/Decryption Flow

### 1.1 Message Encryption - Complete Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MESSAGE ENCRYPTION PROCESS                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐
│   Alice      │
│  (Browser)   │
└──────┬───────┘
       │
       │ 1. User types message: "Hello Bob"
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              ChatInterface.tsx                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ handleSendMessage("Hello Bob")                            │  │
│  │ - Validate session key exists                             │  │
│  │ - Create local message for immediate display              │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 2. Send via WebSocket
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              socketService.ts                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ sendEncryptedMessage(sessionId, userId, "Hello Bob")      │  │
│  │ - Emit 'send_encrypted_message' event                     │  │
│  │ - Payload: {session_id, sender_id, message_content}       │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 3. WebSocket Event (Socket.IO)
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              main.py - Socket.IO Handler                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ @sio.event                                                 │  │
│  │ async def send_encrypted_message(sid, data):              │  │
│  │   1. Validate session exists                              │  │
│  │   2. Check key_established                                │  │
│  │   3. Call session.add_secure_message()                    │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 4. Session Model
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              Session.add_secure_message()                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - Update sender activity timestamp                        │  │
│  │ - Call crypto_service.encrypt_message_otp()               │  │
│  │ - Create SecureMessage object                             │  │
│  │ - Store in session.messages[]                             │  │
│  │ - Update metrics                                          │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 5. Cryptographic Service
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│         CryptoService.encrypt_message_otp()                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 1: Convert to bytes                                  │  │
│  │   plaintext_bytes = "Hello Bob".encode('utf-8')          │  │
│  │   → b'Hello Bob'                                          │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 2: Get sequence number                               │  │
│  │   seq_no = message_seq_counter                            │  │
│  │   message_seq_counter += 1                                │  │
│  │   → seq_no = 0 (first message)                            │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 3: Generate key stream                               │  │
│  │   _generate_key_stream(length, seq_no)                    │  │
│  │   ├─> Check for key stream reuse                          │  │
│  │   ├─> Record usage: (start_offset, end_offset)            │  │
│  │   ├─> HKDF-Expand(key_stream_seed, info)                  │  │
│  │   │   info = f"msg-{seq_no}-{session_id}"                 │  │
│  │   └─> Return key_stream: bytes                            │  │
│  │   → key_stream = [0x3a, 0x7f, 0x91, ...] (10 bytes)      │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 4: OTP Encryption (XOR)                              │  │
│  │   ciphertext = plaintext_bytes ⊕ key_stream               │  │
│  │   → ciphertext = [0x42, 0x07, 0xe4, ...] (10 bytes)      │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 5: Create AAD (Additional Authenticated Data)        │  │
│  │   timestamp = int(os.times().elapsed * 1000)              │  │
│  │   aad = f"{session_id}:{seq_no}:{timestamp}".encode()     │  │
│  │   → aad = b"S-12345:0:1234567890"                         │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 6: Compute HMAC-SHA3-256                             │  │
│  │   h = hmac.new(key_mac, aad + ciphertext, sha3_256)       │  │
│  │   hmac_tag = h.digest()                                   │  │
│  │   → hmac_tag = [0x3a, 0xf0, 0x92, ...] (32 bytes)        │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 7: Create EncryptedMessage object                    │  │
│  │   return EncryptedMessage(                                │  │
│  │       ciphertext=ciphertext,                              │  │
│  │       hmac_tag=hmac_tag,                                  │  │
│  │       seq_no=seq_no,                                      │  │
│  │       timestamp=timestamp,                                │  │
│  │       session_id=session_id                               │  │
│  │   )                                                       │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 6. Return to Session Model
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              Session Model (continued)                          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - Create payload dictionary:                              │  │
│  │   payload = {                                             │  │
│  │       'ciphertext': ciphertext.hex(),                     │  │
│  │       'hmac_tag': hmac_tag.hex(),                         │  │
│  │       'seq_no': seq_no,                                   │  │
│  │       'timestamp': timestamp,                             │  │
│  │       'session_id': session_id,                           │  │
│  │       'crypto_type': 'otp_hmac_sha3'                      │  │
│  │   }                                                       │  │
│  │ - Create SecureMessage object                             │  │
│  │ - Store in session.messages[]                             │  │
│  │ - Update metrics.total_messages_sent                      │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 7. Broadcast to other participants
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              main.py - Socket.IO Broadcast                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ await sio.emit("encrypted_message_received", {            │  │
│  │     "message_id": secure_msg.message_id,                  │  │
│  │     "sender_id": sender_id,                               │  │
│  │     "encrypted_payload": payload,                         │  │
│  │     "timestamp": timestamp,                               │  │
│  │     "seq_no": seq_no,                                     │  │
│  │     "crypto_type": "otp_hmac_sha3"                        │  │
│  │ }, room=f"session_{session_id}", skip_sid=sid)            │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 8. WebSocket Event (Socket.IO)
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              Bob's Browser - socketService.ts                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ onEncryptedMessageReceived(callback)                       │  │
│  │ - Receive encrypted message event                          │  │
│  │ - Update App state with encrypted message                  │  │
│  │ - Display encrypted message in UI                          │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 9. Message stored (encrypted) in Bob's UI
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              ChatInterface.tsx (Bob's Browser)                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - Display encrypted message                               │  │
│  │ - Show "Decrypt" button                                   │  │
│  │ - Wait for user to click "Decrypt"                        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 Message Decryption - Complete Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MESSAGE DECRYPTION PROCESS                               │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐
│     Bob      │
│  (Browser)   │
└──────┬───────┘
       │
       │ 1. User clicks "Decrypt" button
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              ChatInterface.tsx                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ handleDecryptMessage(messageId)                           │  │
│  │ - Check cache first (cryptoService.getCachedDecrypted())  │  │
│  │ - If not cached, request decryption from server           │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 2. Request decryption via WebSocket
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              socketService.ts                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ requestMessageDecryption(sessionId, messageId, userId)    │  │
│  │ - Emit 'decrypt_message' event                            │  │
│  │ - Payload: {session_id, message_id, user_id}              │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 3. WebSocket Event (Socket.IO)
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              main.py - Socket.IO Handler                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ @sio.event                                                 │  │
│  │ async def decrypt_message(sid, data):                     │  │
│  │   1. Validate session exists                              │  │
│  │   2. Authorize user (not Eve)                             │  │
│  │   3. Find message by message_id                           │  │
│  │   4. Call session.decrypt_message()                       │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 4. Session Model
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              Session.decrypt_message()                          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - Validate key_established                                │  │
│  │ - Check message_type == CHAT_OTP                          │  │
│  │ - Extract encrypted_payload                               │  │
│  │ - Create EncryptedMessage object from payload             │  │
│  │ - Call crypto_service.decrypt_message_otp()               │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 5. Cryptographic Service
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│         CryptoService.decrypt_message_otp()                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 1: Reconstruct AAD                                   │  │
│  │   aad = f"{session_id}:{seq_no}:{timestamp}".encode()     │  │
│  │   → aad = b"S-12345:0:1234567890"                         │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 2: Compute expected HMAC                             │  │
│  │   h = hmac.new(key_mac, aad + ciphertext, sha3_256)       │  │
│  │   expected_hmac = h.digest()                              │  │
│  │   → expected_hmac = [0x3a, 0xf0, 0x92, ...] (32 bytes)   │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 3: Verify HMAC (constant-time comparison)            │  │
│  │   if not hmac.compare_digest(received_hmac, expected):    │  │
│  │       raise ValueError("HMAC verification failed")         │  │
│  │   → HMAC verified ✓                                        │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 4: Regenerate key stream (same as encryption)        │  │
│  │   key_stream = _generate_key_stream(length, seq_no,       │  │
│  │                                     record_usage=False)   │  │
│  │   → key_stream = [0x3a, 0x7f, 0x91, ...] (10 bytes)      │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 5: OTP Decryption (XOR)                              │  │
│  │   plaintext_bytes = ciphertext ⊕ key_stream               │  │
│  │   → plaintext_bytes = b'Hello Bob'                        │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 6: Decode to string                                  │  │
│  │   plaintext = plaintext_bytes.decode('utf-8')             │  │
│  │   → plaintext = "Hello Bob"                               │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 7: Return decrypted message                          │  │
│  │   return plaintext                                        │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 6. Return to Session Model
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              Session Model (continued)                          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - Return decrypted_content = "Hello Bob"                  │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 7. Send decrypted message to Bob
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              main.py - Socket.IO Response                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ await sio.emit("message_decrypted", {                     │  │
│  │     "message_id": message_id,                             │  │
│  │     "decrypted_content": "Hello Bob",                     │  │
│  │     "sender_id": sender_id                                │  │
│  │ }, room=sid)  # Send only to requester                    │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 8. WebSocket Event (Socket.IO)
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              Bob's Browser - socketService.ts                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ onMessageDecrypted(callback)                               │  │
│  │ - Receive decrypted message event                          │  │
│  │ - Update App state with decrypted content                  │  │
│  │ - Cache decrypted content (cryptoService)                  │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 9. Display decrypted message
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              ChatInterface.tsx (Bob's Browser)                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - Update message with decrypted_content                    │  │
│  │ - Display "Hello Bob" in chat interface                    │  │
│  │ - Hide "Decrypt" button                                    │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.3 Message Encryption/Decryption - Data Structures

```
┌─────────────────────────────────────────────────────────────────┐
│              Message Encryption Data Structures                 │
└─────────────────────────────────────────────────────────────────┘

Input:
┌─────────────────────────────────────────────────────────────────┐
│  Plaintext Message:                                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Type: str                                                  │  │
│  │ Value: "Hello Bob"                                         │  │
│  │ Length: 10 bytes (UTF-8)                                   │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  Key Stream Generation:                                         │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Input:                                                     │  │
│  │   - key_stream_seed: bytes (32 bytes)                     │  │
│  │   - seq_no: int (e.g., 0)                                 │  │
│  │   - session_id: str (e.g., "S-12345")                     │  │
│  │   - length: int (e.g., 10)                                │  │
│  │                                                            │  │
│  │ Process:                                                   │  │
│  │   info = f"msg-{seq_no}-{session_id}".encode()            │  │
│  │   key_stream = HKDF-Expand(key_stream_seed, info, length) │  │
│  │                                                            │  │
│  │ Output:                                                    │  │
│  │   key_stream: bytes (10 bytes)                            │  │
│  │   Example: [0x3a, 0x7f, 0x91, 0x2c, 0x45, ...]           │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  OTP Encryption (XOR):                                          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ plaintext_bytes: [0x48, 0x65, 0x6c, 0x6c, 0x6f, ...]     │  │
│  │ key_stream:      [0x3a, 0x7f, 0x91, 0x2c, 0x45, ...]     │  │
│  │                            XOR                             │  │
│  │ ciphertext:      [0x42, 0x07, 0xe4, 0x40, 0x2a, ...]     │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  AAD Construction:                                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ aad = f"{session_id}:{seq_no}:{timestamp}".encode()       │  │
│  │ Example: b"S-12345:0:1234567890"                          │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  HMAC-SHA3-256 Computation:                                     │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Input:                                                     │  │
│  │   - key_mac: bytes (32 bytes)                             │  │
│  │   - message: aad + ciphertext                             │  │
│  │                                                            │  │
│  │ Process:                                                   │  │
│  │   h = hmac.new(key_mac, aad + ciphertext, sha3_256)       │  │
│  │   hmac_tag = h.digest()                                   │  │
│  │                                                            │  │
│  │ Output:                                                    │  │
│  │   hmac_tag: bytes (32 bytes)                              │  │
│  │   Example: [0x3a, 0xf0, 0x92, 0xbe, 0x45, ...]           │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  EncryptedMessage Object:                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ @dataclass                                                 │  │
│  │ class EncryptedMessage:                                   │  │
│  │     ciphertext: bytes      # 10 bytes                     │  │
│  │     hmac_tag: bytes        # 32 bytes                     │  │
│  │     seq_no: int            # 0                            │  │
│  │     timestamp: int         # 1234567890                   │  │
│  │     session_id: str        # "S-12345"                    │  │
│  │     nonce: Optional[bytes] # None (not used for OTP)      │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  SecureMessage Payload (JSON):                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ {                                                          │  │
│  │     "ciphertext": "4207e4402a...",  # hex string          │  │
│  │     "hmac_tag": "3af092be45e1...",  # hex string          │  │
│  │     "seq_no": 0,                                           │  │
│  │     "timestamp": 1234567890,                               │  │
│  │     "session_id": "S-12345",                               │  │
│  │     "crypto_type": "otp_hmac_sha3"                         │  │
│  │ }                                                          │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. File Encryption/Decryption Flow

### 2.1 File Encryption - Complete Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      FILE ENCRYPTION PROCESS                                │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐
│   Alice      │
│  (Browser)   │
└──────┬───────┘
       │
       │ 1. User selects file: "report.pdf" (500 KB)
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              ChatInterface.tsx                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ handleFileUpload(file)                                    │  │
│  │ - Validate session key exists                             │  │
│  │ - Validate file size limits                               │  │
│  │ - Call apiService.sendEncryptedFile()                     │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 2. Optional: Client-side encryption (frontend)
       │    OR Server-side encryption (backend)
       │
       │ Option A: Client-side encryption
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              cryptoService.ts (Frontend)                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ encryptFileXChaCha(file, sessionKey, aad)                 │  │
│  │ - Read file as stream (64KB chunks)                       │  │
│  │ - Generate random 24-byte nonce                           │  │
│  │ - Encrypt with XChaCha20-Poly1305                         │  │
│  │ - Return {ciphertext, nonce, aad}                         │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 3. Upload encrypted file via HTTP POST
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              apiService.ts                                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ sendEncryptedFile(sessionId, userId, file)                │  │
│  │ - Create FormData with encrypted file                     │  │
│  │ - POST /session/{id}/send_file                            │  │
│  │ - Include file metadata                                   │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 4. HTTP POST Request
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              main.py - REST Endpoint                            │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ @app.post("/session/{session_id}/send_file")              │  │
│  │ async def send_encrypted_file(...):                       │  │
│  │   1. Validate session exists                              │  │
│  │   2. Check key_established                                │  │
│  │   3. Read file data                                       │  │
│  │   4. If pre-encrypted: store directly                     │  │
│  │   5. Else: call session.add_encrypted_file()              │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 5. Session Model
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              Session.add_encrypted_file()                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - Update sender activity timestamp                        │  │
│  │ - Call crypto_service.encrypt_file_xchacha20()            │  │
│  │ - Create SecureMessage object                             │  │
│  │ - Store in session.messages[]                             │  │
│  │ - Update metrics                                          │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 6. Cryptographic Service
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│         CryptoService.encrypt_file_xchacha20()                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 1: Get file sequence number                          │  │
│  │   file_seq_no = file_seq_counter                          │  │
│  │   file_seq_counter += 1                                   │  │
│  │   → file_seq_no = 0 (first file)                          │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 2: Create AAD (Additional Authenticated Data)        │  │
│  │   aad = f"{session_id}:{file_seq_no}:{filename}".encode() │  │
│  │   → aad = b"S-12345:0:report.pdf"                         │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 3: Generate random nonce                             │  │
│  │   nonce = nacl_utils.random(24)                           │  │
│  │   → nonce = [0x1a, 0x2b, 0x3c, ...] (24 bytes)           │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 4: Encrypt with XChaCha20-Poly1305                   │  │
│  │   ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(│  │
│  │       file_data,      # Plaintext file bytes              │  │
│  │       aad,            # Additional authenticated data      │  │
│  │       nonce,          # 24-byte random nonce              │  │
│  │       key_file        # 32-byte encryption key            │  │
│  │   )                                                       │  │
│  │   → ciphertext = [0x5f, 0xa1, 0xb2, ...] (500KB + 16B)   │  │
│  │   Note: Poly1305 tag is automatically appended (16 bytes) │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 5: Create EncryptedFile object                       │  │
│  │   return EncryptedFile(                                   │  │
│  │       ciphertext=ciphertext,                              │  │
│  │       nonce=nonce,                                        │  │
│  │       aad=aad,                                            │  │
│  │       filename=filename,                                  │  │
│  │       file_seq_no=file_seq_no,                            │  │
│  │       session_id=session_id                               │  │
│  │   )                                                       │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 7. Return to Session Model
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              Session Model (continued)                          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - Create payload dictionary:                              │  │
│  │   payload = {                                             │  │
│  │       'ciphertext': ciphertext.hex(),                     │  │
│  │       'nonce': nonce.hex(),                               │  │
│  │       'aad': aad.hex(),                                   │  │
│  │       'filename': filename,                               │  │
│  │       'file_seq_no': file_seq_no,                         │  │
│  │       'session_id': session_id,                           │  │
│  │       'crypto_type': 'xchacha20_poly1305',                │  │
│  │       'file_size': len(file_data)                         │  │
│  │   }                                                       │  │
│  │ - Create SecureMessage object                             │  │
│  │ - Store in session.messages[]                             │  │
│  │ - Update metrics.total_files_sent                         │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 8. Broadcast file notification
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              main.py - Socket.IO Broadcast                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ await sio.emit("encrypted_file_received", {               │  │
│  │     "message_id": secure_msg.message_id,                  │  │
│  │     "sender_id": sender_id,                               │  │
│  │     "filename": filename,                                 │  │
│  │     "file_size": file_size,                               │  │
│  │     "timestamp": timestamp                                │  │
│  │ }, room=f"session_{session_id}")                          │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 9. WebSocket Event (Socket.IO)
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              Bob's Browser - socketService.ts                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ onEncryptedFileReceived(callback)                          │  │
│  │ - Receive encrypted file notification                      │  │
│  │ - Update App state with file info                          │  │
│  │ - Display file in chat interface                           │  │
│  │ - Show "Download" button                                   │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 10. File notification stored in Bob's UI
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              ChatInterface.tsx (Bob's Browser)                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - Display file message                                    │  │
│  │ - Show filename: "report.pdf"                             │  │
│  │ - Show file size: "500 KB"                                │  │
│  │ - Show "Download" button                                  │  │
│  │ - Wait for user to click "Download"                       │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 File Decryption - Complete Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      FILE DECRYPTION PROCESS                                │
└─────────────────────────────────────────────────────────────────────────────┘

┌──────────────┐
│     Bob      │
│  (Browser)   │
└──────┬───────┘
       │
       │ 1. User clicks "Download" button
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              ChatInterface.tsx                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ handleFileDownload(messageId, encrypted=false)            │  │
│  │ - Call apiService.downloadEncryptedFile()                 │  │
│  │ - encrypted=false means download decrypted file           │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 2. Request file download via HTTP GET
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              apiService.ts                                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ downloadEncryptedFile(sessionId, messageId, userId)       │  │
│  │ - GET /session/{id}/download_file/{message_id}            │  │
│  │ - Query params: user_id=...                               │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 3. HTTP GET Request
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              main.py - REST Endpoint                            │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ @app.get("/session/{session_id}/download_file/{msg_id}")  │  │
│  │ async def download_encrypted_file(...):                   │  │
│  │   1. Validate session exists                              │  │
│  │   2. Find message by message_id                           │  │
│  │   3. Check key_established                                │  │
│  │   4. Call session.decrypt_file()                          │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 4. Session Model
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              Session.decrypt_file()                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - Validate key_established                                │  │
│  │ - Check message_type == FILE_XCHACHA20                    │  │
│  │ - Extract encrypted_payload                               │  │
│  │ - Create EncryptedFile object from payload                │  │
│  │ - Call crypto_service.decrypt_file_xchacha20()            │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 5. Cryptographic Service
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│         CryptoService.decrypt_file_xchacha20()                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 1: Extract components                                │  │
│  │   ciphertext = encrypted_file.ciphertext                  │  │
│  │   nonce = encrypted_file.nonce                            │  │
│  │   aad = encrypted_file.aad                                │  │
│  │   filename = encrypted_file.filename                      │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 2: Decrypt with XChaCha20-Poly1305                   │  │
│  │   try:                                                    │  │
│  │       plaintext = crypto_aead_xchacha20poly1305_ietf_    │  │
│  │           decrypt(                                        │  │
│  │               ciphertext,  # Encrypted file + tag         │  │
│  │               aad,         # Additional authenticated data│  │
│  │               nonce,       # 24-byte nonce                │  │
│  │               key_file     # 32-byte decryption key       │  │
│  │           )                                               │  │
│  │   except CryptoError:                                     │  │
│  │       raise ValueError("Authentication failed")           │  │
│  │   → plaintext = [0x25, 0x50, 0x44, 0x46, ...] (500 KB)   │  │
│  │   Note: Poly1305 tag is automatically verified (16 bytes) │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Step 3: Return decrypted file and filename                │  │
│  │   return (plaintext, filename)                            │  │
│  │   → (file_bytes, "report.pdf")                            │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 6. Return to Session Model
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              Session Model (continued)                          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - Return (file_data, filename)                            │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 7. Return file to client
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              main.py - HTTP Response                            │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ return {                                                   │  │
│  │     "filename": "report.pdf",                             │  │
│  │     "file_data": base64.b64encode(file_data).decode(),    │  │
│  │     "file_size": len(file_data),                          │  │
│  │     "message_id": message_id                              │  │
│  │ }                                                         │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 8. HTTP Response
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              apiService.ts (Bob's Browser)                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ downloadEncryptedFile() returns response                  │  │
│  │ - Extract file_data (base64)                              │  │
│  │ - Decode base64 to binary                                 │  │
│  │ - Create Blob from binary data                            │  │
│  └───────────────────────────────────────────────────────────┘  │
└──────┬──────────────────────────────────────────────────────────┘
       │
       │ 9. Download file
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│              ChatInterface.tsx (Bob's Browser)                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - Create download link from Blob                          │  │
│  │ - Trigger browser download                                │  │
│  │ - File saved as "report.pdf"                              │  │
│  │ - Display success notification                            │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.3 File Encryption/Decryption - Data Structures

```
┌─────────────────────────────────────────────────────────────────┐
│              File Encryption Data Structures                    │
└─────────────────────────────────────────────────────────────────┘

Input:
┌─────────────────────────────────────────────────────────────────┐
│  File Data:                                                     │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Filename: "report.pdf"                                     │  │
│  │ Size: 500 KB (512,000 bytes)                               │  │
│  │ Type: bytes                                                │  │
│  │ Content: [0x25, 0x50, 0x44, 0x46, ...] (PDF header)       │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  AAD Construction:                                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ aad = f"{session_id}:{file_seq_no}:{filename}".encode()   │  │
│  │ Example: b"S-12345:0:report.pdf"                          │  │
│  │ Purpose: Authenticated but not encrypted metadata          │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  Nonce Generation:                                              │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ nonce = nacl_utils.random(24)                             │  │
│  │ Example: [0x1a, 0x2b, 0x3c, 0x4d, ...] (24 bytes)        │  │
│  │ Purpose: Unique nonce for each file encryption            │  │
│  │ Security: Random generation prevents nonce reuse           │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  XChaCha20-Poly1305 Encryption:                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Input:                                                     │  │
│  │   - file_data: bytes (512,000 bytes)                      │  │
│  │   - aad: bytes (AAD)                                      │  │
│  │   - nonce: bytes (24 bytes)                               │  │
│  │   - key_file: bytes (32 bytes)                            │  │
│  │                                                            │  │
│  │ Process:                                                   │  │
│  │   ciphertext = crypto_aead_xchacha20poly1305_ietf_encrypt(│  │
│  │       file_data, aad, nonce, key_file                     │  │
│  │   )                                                       │  │
│  │                                                            │  │
│  │ Output:                                                    │  │
│  │   ciphertext: bytes (512,000 + 16 bytes)                  │  │
│  │   - Encrypted file: 512,000 bytes                         │  │
│  │   - Poly1305 tag: 16 bytes (appended)                     │  │
│  │   Example: [0x5f, 0xa1, 0xb2, ...] (512,016 bytes)       │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  EncryptedFile Object:                                          │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ @dataclass                                                 │  │
│  │ class EncryptedFile:                                      │  │
│  │     ciphertext: bytes      # 512,016 bytes                │  │
│  │     nonce: bytes           # 24 bytes                     │  │
│  │     aad: bytes             # AAD                          │  │
│  │     filename: str          # "report.pdf"                 │  │
│  │     file_seq_no: int       # 0                            │  │
│  │     session_id: str        # "S-12345"                    │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  SecureMessage Payload (JSON):                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ {                                                          │  │
│  │     "ciphertext": "5fa1b2c3...",  # hex string (1MB+)     │  │
│  │     "nonce": "1a2b3c4d...",       # hex string (48 chars) │  │
│  │     "aad": "532d31323334353a303a7265706f72742e706466",     │  │
│  │     "filename": "report.pdf",                              │  │
│  │     "file_seq_no": 0,                                      │  │
│  │     "session_id": "S-12345",                               │  │
│  │     "crypto_type": "xchacha20_poly1305",                   │  │
│  │     "file_size": 512000                                    │  │
│  │ }                                                          │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 3. Key Derivation Process

```
┌─────────────────────────────────────────────────────────────────┐
│                    KEY DERIVATION PROCESS                       │
└─────────────────────────────────────────────────────────────────┘

Input:
┌─────────────────────────────────────────────────────────────────┐
│  Master Key (from BB84):                                        │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ bb84_key: bytes (32 bytes)                                │  │
│  │ Example: [0x10, 0x11, 0x01, 0x10, ...] (32 bytes)        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼ (Optional: Hybrid Mode)
┌─────────────────────────────────────────────────────────────────┐
│  PQC Key (from Kyber KEM):                                      │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ pqc_key: bytes (32 bytes)                                 │  │
│  │ Example: [0xa4, 0xc1, 0xe2, 0x9f, ...] (32 bytes)        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  Combined Key (Hybrid Mode):                                    │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ if hybrid_mode:                                           │  │
│  │     combined_key = bb84_key + pqc_key                     │  │
│  │     # 64 bytes total                                      │  │
│  │ else:                                                     │  │
│  │     combined_key = bb84_key                               │  │
│  │     # 32 bytes                                            │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  HKDF Key Derivation:                                           │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Session ID: "S-12345"                                      │  │
│  │ Salt: session_id.encode('utf-8')                          │  │
│  │                                                            │  │
│  │ Key Stream Seed:                                           │  │
│  │   hkdf = HKDF(SHA256, length=32, salt=salt)               │  │
│  │   key_stream_seed = hkdf.derive(combined_key + b'otp-    │  │
│  │                                 stream')                   │  │
│  │   → 32 bytes                                              │  │
│  │                                                            │  │
│  │ HMAC Key:                                                  │  │
│  │   hkdf = HKDF(SHA256, length=32, salt=salt)               │  │
│  │   key_mac = hkdf.derive(combined_key + b'hmac-key')       │  │
│  │   → 32 bytes                                              │  │
│  │                                                            │  │
│  │ File Encryption Key:                                       │  │
│  │   hkdf = HKDF(SHA256, length=32, salt=salt)               │  │
│  │   key_file = hkdf.derive(combined_key + b'file-key')      │  │
│  │   → 32 bytes                                              │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│  DerivedKeys Object:                                            │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ @dataclass                                                 │  │
│  │ class DerivedKeys:                                        │  │
│  │     key_stream_seed: bytes  # 32 bytes (for OTP)          │  │
│  │     key_mac: bytes         # 32 bytes (for HMAC)          │  │
│  │     key_file: bytes        # 32 bytes (for file encryption)│  │
│  │     master_key: bytes      # Original combined key        │  │
│  │     pqc_kyber_keys: Optional[KyberKeyPair]                │  │
│  │     pqc_dilithium_keys: Optional[DilithiumKeyPair]        │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Security Components

### 4.1 Security Features

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY COMPONENTS                          │
└─────────────────────────────────────────────────────────────────┘

Message Security:
┌─────────────────────────────────────────────────────────────────┐
│  OTP Encryption:                                                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - One-time pad (perfect secrecy)                          │  │
│  │ - Key stream never reused                                 │  │
│  │ - Deterministic generation (same seq_no → same stream)    │  │
│  │ - Key stream reuse detection                              │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ HMAC-SHA3-256:                                            │  │
│  │ - Message authentication                                  │  │
│  │ - Integrity verification                                  │  │
│  │ - Replay protection (via timestamp in AAD)                │  │
│  │ - Constant-time comparison (timing attack prevention)     │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘

File Security:
┌─────────────────────────────────────────────────────────────────┐
│  XChaCha20-Poly1305 AEAD:                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - Authenticated encryption                                │  │
│  │ - Confidentiality (XChaCha20 stream cipher)               │  │
│  │ - Authenticity (Poly1305 MAC)                             │  │
│  │ - Random nonce (24 bytes) prevents nonce reuse            │  │
│  │ - AAD includes session_id, file_seq_no, filename          │  │
│  │ - Automatic tag verification on decryption                │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘

Key Management:
┌─────────────────────────────────────────────────────────────────┐
│  Key Derivation:                                                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ - HKDF-SHA256 for key derivation                          │  │
│  │ - Separate keys for different purposes                    │  │
│  │ - Session ID as salt                                      │  │
│  │ - Key isolation (one key per purpose)                     │  │
│  └───────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Key Storage:                                               │  │
│  │ - Keys stored in memory only                              │  │
│  │ - Keys cleared on session termination                     │  │
│  │ - Secure key zeroization                                  │  │
│  │ - No key persistence                                      │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Security Guarantees

```
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY GUARANTEES                          │
└─────────────────────────────────────────────────────────────────┘

Message Encryption:
✓ Confidentiality: OTP provides perfect secrecy
✓ Integrity: HMAC-SHA3-256 verifies message authenticity
✓ Replay Protection: Timestamp in AAD prevents replay attacks
✓ Key Stream Reuse Prevention: Detection and prevention mechanisms
✓ Timing Attack Resistance: Constant-time HMAC comparison

File Encryption:
✓ Confidentiality: XChaCha20 stream cipher encryption
✓ Authenticity: Poly1305 MAC verifies file integrity
✓ Nonce Uniqueness: Random 24-byte nonce for each file
✓ AAD Protection: Session ID, file sequence, filename in AAD
✓ Automatic Verification: Poly1305 tag verified on decryption

Key Management:
✓ Key Isolation: Separate keys for messages and files
✓ Secure Derivation: HKDF-SHA256 with session ID salt
✓ Key Zeroization: Secure key clearing on session end
✓ No Key Reuse: Key stream segments never overlap
✓ Hybrid Security: BB84 + PQC for enhanced security
```

---

## Summary

This document provides comprehensive block diagrams for:

1. **Message Encryption/Decryption**: Complete flow from user input to decrypted output, including all components, cryptographic operations, and data structures.

2. **File Encryption/Decryption**: Complete flow from file selection to file download, including client-side and server-side encryption options.

3. **Key Derivation**: Process of deriving cryptographic keys from BB84 master key using HKDF.

4. **Security Components**: Security features and guarantees provided by the encryption/decryption processes.

All diagrams show the detailed steps, data transformations, and component interactions involved in securing messages and files in the BB84 QKD system.





















