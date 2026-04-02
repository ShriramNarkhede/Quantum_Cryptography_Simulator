# 🔑 HKDF Key Derivation - Simple Explanation

## What is HKDF?

**HKDF** stands for **HMAC-based Key Derivation Function**. It's a method to take one key (like the BB84 quantum key) and safely create multiple different keys from it.

Think of it like this: You have one master key, and you need 3 different keys:
- One key for encrypting messages
- One key for verifying messages (integrity)
- One key for encrypting files

Instead of running BB84 three times (which is expensive!), HKDF lets you **derive** all three keys from the single BB84 key!

---

## 🎯 Why Do We Need HKDF?

### ❌ **Problem Without HKDF:**

If we use the same BB84 key for everything:
```
BB84 Key → Use for message encryption
BB84 Key → Use for message integrity check
BB84 Key → Use for file encryption
```

**This is DANGEROUS!** 🚨
- Reusing the same key for different purposes weakens security
- If one usage is compromised, everything is compromised
- Cryptographic operations can interfere with each other

### ✅ **Solution With HKDF:**

HKDF creates multiple **independent** keys from one source:
```
BB84 Key (32 bytes)
       ↓
   [HKDF Magic]
       ↓
├─ Message Encryption Key (32 bytes)
├─ HMAC Key (32 bytes)
└─ File Encryption Key (32 bytes)
```

Each derived key is:
- ✅ **Independent** (knowing one doesn't help you find the others)
- ✅ **Unique** (different for each purpose)
- ✅ **Unpredictable** (can't be guessed)
- ✅ **Cryptographically strong** (just as secure as the original)

---

## 🧩 How HKDF Works (Two Steps)

HKDF has **two phases**:

### **Phase 1: Extract** (Create a strong foundation)
Takes the input key and makes it uniformly random and strong

### **Phase 2: Expand** (Generate multiple keys)
Creates multiple independent output keys from the extracted key

In our project, we combine both phases in each derivation!

---

## 📋 HKDF in Our BB84 System - Step by Step

Let's see exactly how our system uses HKDF!

### **Starting Point: BB84 Quantum Key**

After BB84 completes, Alice and Bob have:
```
BB84 Key: a7f3c9d2e1b8f6a4c3d7e9f2a1b5c8d4e6f9a2b3c5d7e8f1a3b6c9d2e4f7a9b1
Length: 32 bytes (256 bits)
Session ID: "S-12345"
```

### **Goal: Derive 3 Independent Keys**

We need:
1. **Key Stream Seed** - For message encryption (OTP-style)
2. **MAC Key** - For message authentication (HMAC)
3. **File Key** - For file encryption (XChaCha20-Poly1305)

---

## 🔍 Detailed HKDF Process

### **Step 1: Derive Key Stream Seed**

**Input:**
- BB84 Key: `a7f3c9d2...a9b1` (32 bytes)
- Salt: `"S-12345"` (session ID as UTF-8 bytes)
- Info: `"otp-stream"` (purpose identifier)

**HKDF Process:**

1. **Prepare Input Material:**
   ```
   Input Key Material (IKM) = BB84_Key + "otp-stream"
   = a7f3c9d2...a9b1 + 6f74702d73747265616d
   ```

2. **HKDF-Extract (with salt):**
   ```
   PRK = HMAC-SHA256(salt="S-12345", message=IKM)
   ```
   
   HMAC-SHA256 is a keyed hash function that mixes the salt and input:
   ```
   PRK = SHA256-based mixing of session ID and IKM
   = cf8e4a2b7d3f1e9c6a2d8b4f7e3c1a9f6d2b8e4a7c3f1e9d6b2a8f4e7c3d1a9e
   ```

3. **HKDF-Expand:**
   ```
   Key_Stream_Seed = HMAC-SHA256(PRK, info="" | counter_byte)
   ```
   
   Generate 32 bytes:
   ```
   Key_Stream_Seed = 4b7e2c9f1a3d8e6b4c2f7a9e3d1b8c6f2e9a7d4c1f8b6e3a9c7d2f4e1b8a6c3d
   ```

**Output:**
```
Key_Stream_Seed: 4b7e2c9f1a3d8e6b4c2f7a9e3d1b8c6f2e9a7d4c1f8b6e3a9c7d2f4e1b8a6c3d
Purpose: Seed for generating message encryption key streams
```

---

### **Step 2: Derive MAC Key**

**Input:**
- BB84 Key: `a7f3c9d2...a9b1` (32 bytes)
- Salt: `"S-12345"` (same session ID)
- Info: `"hmac-key"` (different purpose!)

**HKDF Process:**

1. **Prepare Input Material:**
   ```
   IKM = BB84_Key + "hmac-key"
   = a7f3c9d2...a9b1 + 686d61632d6b6579
   ```
   
   Notice: Different from Step 1 because we appended "hmac-key" instead of "otp-stream"!

2. **HKDF-Extract:**
   ```
   PRK = HMAC-SHA256(salt="S-12345", message=IKM)
   = 9a3d7f2e1c8b6f4a7e3d9c1f8b2e6a4d7c1f9e3a6d2b8f4c7e1a9d3f6b2c8e4a
   ```
   
   Notice: Different PRK than Step 1!

3. **HKDF-Expand:**
   ```
   key_mac = HMAC-SHA256(PRK, info="" | counter_byte)
   = 8d3f6a2c9e1b7f4d2a8c6e3f9b1d7a4c6e2f8b3a9d1c7e4f2b8a6c3d9f1e8b4a
   ```

**Output:**
```
key_mac: 8d3f6a2c9e1b7f4d2a8c6e3f9b1d7a4c6e2f8b3a9d1c7e4f2b8a6c3d9f1e8b4a
Purpose: Key for HMAC-SHA3-256 message authentication
```

---

### **Step 3: Derive File Encryption Key**

**Input:**
- BB84 Key: `a7f3c9d2...a9b1` (32 bytes)
- Salt: `"S-12345"` (same session ID)
- Info: `"file-key"` (yet another purpose!)

**HKDF Process:**

1. **Prepare Input Material:**
   ```
   IKM = BB84_Key + "file-key"
   = a7f3c9d2...a9b1 + 66696c652d6b6579
   ```

2. **HKDF-Extract:**
   ```
   PRK = HMAC-SHA256(salt="S-12345", message=IKM)
   = 2f8b3e6a9c1d7f4e2b8a6c3f9d1e7b4a6c2f8d3e9b1a7c4f2e8b6a3c9f1d7e4a
   ```

3. **HKDF-Expand:**
   ```
   key_file = HMAC-SHA256(PRK, info="" | counter_byte)
   = 6c2f9e3a7d1b8f4c2e9a6d3f1b8c7e4a9d2f6b3c8e1a7d4f2b9c6e3a8f1d4b7c
   ```

**Output:**
```
key_file: 6c2f9e3a7d1b8f4c2e9a6d3f1b8c7e4a9d2f6b3c8e1a7d4f2b9c6e3a8f1d4b7c
Purpose: Key for XChaCha20-Poly1305 file encryption
```

---

## 📊 Summary: Three Different Keys from One BB84 Key

```
┌─────────────────────────────────────────────────────────────┐
│  BB84 Quantum Key (32 bytes)                                │
│  a7f3c9d2e1b8f6a4c3d7e9f2a1b5c8d4e6f9a2b3c5d7e8f1a3b6... │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    Session ID: S-12345
                           │
        ┌──────────────────┼──────────────────┐
        ↓                  ↓                  ↓
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│ HKDF + Salt   │  │ HKDF + Salt   │  │ HKDF + Salt   │
│ Info:         │  │ Info:         │  │ Info:         │
│ "otp-stream"  │  │ "hmac-key"    │  │ "file-key"    │
└───────┬───────┘  └───────┬───────┘  └───────┬───────┘
        ↓                  ↓                  ↓
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│ Key Stream    │  │ MAC Key       │  │ File Key      │
│ Seed          │  │               │  │               │
│ 4b7e2c9f...   │  │ 8d3f6a2c...   │  │ 6c2f9e3a...   │
└───────────────┘  └───────────────┘  └───────────────┘
        ↓                  ↓                  ↓
    Message            Message             File
   Encryption      Authentication      Encryption
  (XOR Stream)     (HMAC-SHA3)      (XChaCha20-Poly1305)
```

---

## 🔐 How Each Key is Used

### **1. Key Stream Seed → Message Encryption**

The Key Stream Seed is used to generate **unique key streams** for each message:

```python
# For message #0:
key_stream_0 = HKDF-Expand(Key_Stream_Seed, info="msg-0-S-12345")

# For message #1:
key_stream_1 = HKDF-Expand(Key_Stream_Seed, info="msg-1-S-12345")

# For message #2:
key_stream_2 = HKDF-Expand(Key_Stream_Seed, info="msg-2-S-12345")
```

Each message gets a **different key stream** (OTP-style encryption)!

**Encryption:**
```
Plaintext: "Hello Bob"
         → Bytes: 48 65 6c 6c 6f 20 42 6f 62
         
Key Stream #0: a3 d7 2f 1c 8b 6e 2d 9a 4f

Ciphertext: XOR each byte
         → eb b2 43 70 e4 4e 6f f5 2d
```

---

### **2. MAC Key → Message Authentication**

The MAC Key is used to create **HMAC tags** to ensure message integrity:

```python
# Create Additional Authenticated Data (AAD)
AAD = "S-12345:0:1642534876543"  # session:seq:timestamp

# Compute HMAC-SHA3-256
tag = HMAC-SHA3-256(key_mac, AAD + ciphertext)
    = c7f8e9d2a3b6c4f7e8a9d1b3c6f2e8d9a4b7c3f6e9d2a8b1c4f7e3d9b6a2c8f4
```

When Bob receives the message:
- He computes the same HMAC using his MAC key
- If tags match → ✅ Message is authentic and unmodified
- If tags don't match → ❌ Message was tampered with!

---

### **3. File Key → File Encryption**

The File Key is used directly with **XChaCha20-Poly1305 AEAD**:

```python
# Generate random nonce (24 bytes)
nonce = random_bytes(24)

# Create AAD for the file
AAD = "S-12345:0:report.pdf"

# Encrypt file
ciphertext = XChaCha20_Encrypt(
    key=key_file,
    nonce=nonce,
    aad=AAD,
    plaintext=file_data
)
```

XChaCha20-Poly1305 provides:
- ✅ Confidentiality (file is encrypted)
- ✅ Authenticity (detects tampering)
- ✅ Unique nonce (different for each file)

---

## 🎓 Complete Example with Real Numbers

Let's trace through a complete example!

### **Scenario:**
- Alice wants to send a message "Hi" to Bob
- Session ID: `S-67890`
- BB84 Key already established

### **Step-by-Step:**

#### **1. HKDF Derives Keys**

```
Input: BB84 Key = a7f3c9d2e1b8f6a4c3d7e9f2a1b5c8d4e6f9a2b3c5d7e8f1a3b6c9d2e4f7a9b1
Salt: "S-67890"

HKDF Derivation:
├─ Key_Stream_Seed = 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
├─ key_mac = 9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e
└─ key_file = 5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d
```

#### **2. Generate Message Key Stream**

```
Message: "Hi"
Sequence Number: 0

Key Stream = HKDF-Expand(Key_Stream_Seed, "msg-0-S-67890")
           = c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8...

Length needed: 2 bytes (for "Hi")
Key Stream (2 bytes): c3 d4
```

#### **3. Encrypt Message**

```
Plaintext: "Hi"
         = 48 69 (in hexadecimal)

Key Stream: c3 d4

Ciphertext = XOR:
         48 ⊕ c3 = 8b
         69 ⊕ d4 = bd
         
Ciphertext = 8b bd
```

#### **4. Create HMAC Tag**

```
AAD = "S-67890:0:1737395000123"

HMAC = HMAC-SHA3-256(key_mac, AAD + ciphertext)
     = HMAC-SHA3-256(
         key=9f8e7d6c5b4a3f2e...,
         msg=S-67890:0:1737395000123 + 8bbd
       )
     = 7a3f9e2d1c8b6a4f3e9d2c1b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f

Tag (32 bytes): 7a3f9e2d1c8b6a4f3e9d2c1b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f
```

#### **5. Send to Bob**

```json
{
  "ciphertext": "8bbd",
  "hmac_tag": "7a3f9e2d1c8b6a4f3e9d2c1b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f",
  "seq_no": 0,
  "timestamp": 1737395000123,
  "session_id": "S-67890"
}
```

#### **6. Bob Decrypts**

```
Bob has the same HKDF-derived keys!

1. Verify HMAC:
   - Compute expected_tag = HMAC-SHA3-256(key_mac, AAD + ciphertext)
   - Compare: expected_tag == received_tag
   - ✅ Match! Message is authentic

2. Generate same key stream:
   - Key Stream = HKDF-Expand(Key_Stream_Seed, "msg-0-S-67890")
   - = c3 d4 (same as Alice!)

3. Decrypt:
   - Ciphertext: 8b bd
   - Key Stream: c3 d4
   - Plaintext = XOR:
     8b ⊕ c3 = 48 = 'H'
     bd ⊕ d4 = 69 = 'i'
   - Result: "Hi" ✅
```

---

## 💡 Why HKDF is Critical for Security

### **1. Key Separation**

Each derived key is used for **only one purpose**:
- If message encryption key is somehow exposed, file encryption is still safe
- If MAC key leaks, messages remain confidential
- Compartmentalization limits damage from any single key compromise

### **2. Session Binding**

Using Session ID as salt ensures:
- Keys for session `S-12345` are different from `S-67890`
- Even with the same BB84 key, each session gets unique keys
- Old sessions can't be replayed in new sessions

### **3. Forward Secrecy**

When a session ends:
- All derived keys are erased
- New session generates completely new keys
- Past messages remain secure even if future keys are compromised

### **4. Cryptographic Independence**

HKDF ensures derived keys are:
- **Uncorrelated**: Knowing one derived key gives zero information about others
- **Uniform**: Each key is cryptographically random
- **One-way**: Can't reverse HKDF to find the BB84 key

---

## 🔗 HKDF in Hybrid System (BB84 + Kyber)

In our project, we also combine BB84 with post-quantum Kyber!

### **Hybrid Key Creation:**

```
┌──────────────┐     ┌──────────────┐
│  BB84 Key    │     │  Kyber Key   │
│  (32 bytes)  │     │  (32 bytes)  │
└──────┬───────┘     └──────┬───────┘
       │                    │
       └──────────┬─────────┘
                  ↓
          Concatenate Keys
          (64 bytes total)
                  ↓
       ┌──────────────────────┐
       │   HKDF-Extract        │
       │   Salt: Session ID    │
       │   Info: "hybrid"      │
       └──────────┬────────────┘
                  ↓
         Hybrid Master Key
           (32 bytes)
                  ↓
        ┌─────────┼─────────┐
        ↓         ↓         ↓
    Key Stream  MAC Key  File Key
```

This gives **double protection**:
- Even if quantum computers break one component, the other keeps you safe!

---

## 📝 Python Code Example

Here's how HKDF works in Python:

```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

# BB84 key (32 bytes)
bb84_key = bytes.fromhex('a7f3c9d2e1b8f6a4c3d7e9f2a1b5c8d4e6f9a2b3c5d7e8f1a3b6c9d2e4f7a9b1')

# Session ID
session_id = "S-12345"

# Derive Key Stream Seed
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=session_id.encode('utf-8'),
    info=b'',
)
key_stream_seed = hkdf.derive(bb84_key + b'otp-stream')
print(f"Key Stream Seed: {key_stream_seed.hex()}")

# Derive MAC Key (reset HKDF!)
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=session_id.encode('utf-8'),
    info=b'',
)
key_mac = hkdf.derive(bb84_key + b'hmac-key')
print(f"MAC Key: {key_mac.hex()}")

# Derive File Key (reset HKDF again!)
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=session_id.encode('utf-8'),
    info=b'',
)
key_file = hkdf.derive(bb84_key + b'file-key')
print(f"File Key: {key_file.hex()}")

# Now all three keys are ready to use!
```

---

## 🎯 Key Takeaways

1. **HKDF creates multiple independent keys from one BB84 key**
   - One BB84 run → Three different keys

2. **Each derived key has a specific purpose**
   - Key Stream Seed → Message encryption
   - MAC Key → Message authentication
   - File Key → File encryption

3. **Session ID acts as salt**
   - Different sessions get different keys
   - Prevents key reuse across sessions

4. **Cryptographically secure**
   - Keys are independent and unpredictable
   - Forward secrecy and key separation

5. **Works with hybrid systems**
   - Can combine BB84 + Kyber keys
   - Double quantum protection!

---

## 🔗 Related Documentation

- [BB84 Protocol Explanation](BB84.md) - How quantum key is generated
- [README.md](README.md) - Full system overview
- [RFC 5869: HKDF Specification](https://tools.ietf.org/html/rfc5869)

---

**Now you understand how HKDF expands one BB84 key into multiple secure keys!** 🎉
