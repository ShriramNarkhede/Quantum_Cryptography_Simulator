# 💬 Message Encryption & Decryption - Simple Explanation

## What is Message Encryption in Our System?

In our BB84 QKD system, **message encryption** protects the confidentiality and integrity of text messages sent between Alice and Bob. We use a **One-Time Pad (OTP) style encryption** combined with **HMAC-SHA3 authentication**.

Think of it like this:
- **Encryption** = Scrambling the message so only the intended receiver can read it
- **Authentication** = Proving the message wasn't tampered with during transmission

---

## 🎯 Why OTP-Style Encryption?

### **What is One-Time Pad (OTP)?**

OTP is the **only theoretically unbreakable encryption method**! Here's how it works:

```
Original Message:  "Hello"  = 48 65 6c 6c 6f (hex)
Random Key Stream:          = a3 d7 2f 1c 8b (hex)
                             ─────────────────
XOR them together:          = eb b2 43 70 e4 (ciphertext)
```

**Key Properties:**
- ✅ **Perfectly secure** - If the key is truly random and never reused
- ✅ **Simple operation** - Just XOR (exclusive OR) operation
- ✅ **Fast** - No complex computations needed
- ⚠️ **Critical requirement** - Each key must be used only ONCE

### **Why This is Perfect for BB84!**

BB84 gives us a quantum-secure key, and HKDF can derive unique key streams for each message!

```
BB84 Key → HKDF → Key Stream Seed → Unique key for message #0
                                  → Unique key for message #1
                                  → Unique key for message #2
                                  ... (never reuse!)
```

---

## 🔐 Message Encryption Architecture

### **Components:**

1. **Key Stream Seed** - Derived from BB84 key via HKDF
2. **Message Counter** - Ensures each message gets a unique key
3. **XOR Encryption** - OTP-style scrambling
4. **HMAC-SHA3-256** - Integrity verification tag
5. **Metadata** - Session ID, sequence number, timestamp

### **Security Layers:**

```
┌────────────────────────────────────────┐
│  Layer 1: Confidentiality (OTP/XOR)    │ ← Hides message content
├────────────────────────────────────────┤
│  Layer 2: Integrity (HMAC-SHA3)        │ ← Detects tampering
├────────────────────────────────────────┤
│  Layer 3: PQC Signature (Dilithium)    │ ← Post-quantum authentication
└────────────────────────────────────────┘
```

---

## 📋 Message Encryption - Step by Step

Let's encrypt a message from Alice to Bob!

### **Initial Setup:**

```
Session ID: S-12345
BB84 Key: a7f3c9d2e1b8f6a4c3d7e9f2a1b5c8d4e6f9a2b3c5d7e8f1a3b6c9d2e4f7a9b1
Key Stream Seed (from HKDF): 4b7e2c9f1a3d8e6b4c2f7a9e3d1b8c6f2e9a7d4c1f8b6e3a9c7d2f4e1b8a6c3d
MAC Key (from HKDF): 8d3f6a2c9e1b7f4d2a8c6e3f9b1d7a4c6e2f8b3a9d1c7e4f2b8a6c3d9f1e8b4a
Message Counter: 0 (this is the first message)
```

---

### **Step 1: Prepare the Message**

**Alice wants to send:** `"Hello Bob"`

**Convert to bytes (UTF-8):**
```
Plaintext: "Hello Bob"
Hex bytes: 48 65 6c 6c 6f 20 42 6f 62
Length: 9 bytes
```

---

### **Step 2: Generate Unique Key Stream**

For each message, we generate a unique key stream using HKDF-Expand:

**Input:**
- Key Stream Seed: `4b7e2c9f1a3d8e6b4c2f7a9e3d1b8c6f2e9a7d4c1f8b6e3a9c7d2f4e1b8a6c3d`
- Info string: `"msg-0-S-12345"` (includes sequence number and session ID)
- Length needed: 9 bytes (same as message length)

**HKDF-Expand Process:**
```
Key Stream = HMAC-SHA256(
    key = Key_Stream_Seed,
    message = "msg-0-S-12345" + counter_byte
)

Result (first 9 bytes):
Key Stream = a3 d7 2f 1c 8b 6e 2d 9a 4f
```

**Why this is secure:**
- Each message has a different sequence number → different key stream
- Even if Eve knows key stream for message #0, it doesn't help with message #1
- Key streams never repeat (as long as sequence numbers don't repeat)

---

### **Step 3: XOR Encryption**

Now we **XOR** (exclusive OR) the plaintext with the key stream:

```
Plaintext:    48 65 6c 6c 6f 20 42 6f 62
Key Stream:   a3 d7 2f 1c 8b 6e 2d 9a 4f
             ─────────────────────────────
Ciphertext:   eb b2 43 70 e4 4e 6f f5 2d
```

**How XOR works (bit-by-bit):**
```
For first byte (48 ⊕ a3):
  48 = 01001000
  a3 = 10100011
  ─────────────
  eb = 11101011  (XOR result)
```

**Properties of XOR:**
- `A ⊕ B ⊕ B = A` (XOR with same key twice gives original)
- `A ⊕ 0 = A` (XOR with 0 is no change)
- `A ⊕ A = 0` (XOR with itself gives 0)
- **Perfect for encryption/decryption with same operation!**

**Ciphertext:** `eb b2 43 70 e4 4e 6f f5 2d`

---

### **Step 4: Create Metadata (AAD)**

**AAD = Additional Authenticated Data** (authenticated but not encrypted)

```
Session ID: S-12345
Sequence Number: 0
Timestamp: 1737395000123 (milliseconds since epoch)

AAD String: "S-12345:0:1737395000123"
AAD Bytes: 53 2d 31 32 33 34 35 3a 30 3a 31 37 33 37 33 39 35 30 30 30 31 32 33
```

This metadata is included in authentication but **not encrypted** (receiver needs to know it to verify).

---

### **Step 5: Compute HMAC Tag**

We use **HMAC-SHA3-256** to create an authentication tag:

**Input:**
- Key: MAC Key = `8d3f6a2c9e1b7f4d2a8c6e3f9b1d7a4c6e2f8b3a9d1c7e4f2b8a6c3d9f1e8b4a`
- Message: AAD + Ciphertext = `"S-12345:0:1737395000123" + ebb2437...`

**HMAC-SHA3-256 Process:**

1. **Prepare keys:**
   ```
   If key > 136 bytes: key = SHA3-256(key)
   If key < 136 bytes: pad with zeros to 136 bytes
   
   ipad = 0x36 repeated 136 times
   opad = 0x5c repeated 136 times
   ```

2. **Inner hash:**
   ```
   inner = SHA3-256((key ⊕ ipad) || message)
   ```

3. **Outer hash:**
   ```
   HMAC = SHA3-256((key ⊕ opad) || inner)
   ```

**Result:**
```
HMAC Tag: c7f8e9d2a3b6c4f7e8a9d1b3c6f2e8d9a4b7c3f6e9d2a8b1c4f7e3d9b6a2c8f4
Length: 32 bytes (256 bits)
```

---

### **Step 6: Package the Encrypted Message**

Alice creates a message object with all components:

```json
{
  "ciphertext": "ebb2437...f52d",
  "hmac_tag": "c7f8e9d2a3b6c4f7e8a9d1b3c6f2e8d9a4b7c3f6e9d2a8b1c4f7e3d9b6a2c8f4",
  "seq_no": 0,
  "timestamp": 1737395000123,
  "session_id": "S-12345",

}
```

---

### **Step 7: Transmit to Bob**

Alice sends this encrypted message package over the network (can be public/insecure channel!).

```
Alice → [Internet/Network] → Bob
       (Anyone can intercept, but can't decrypt!)
```

---

## 🔓 Message Decryption - Step by Step

Bob receives the encrypted message. Let's see how he decrypts it!

### **Bob has:**
```
Session ID: S-12345
Same BB84 Key: a7f3c9d2e1b8f6a4c3d7e9f2a1b5c8d4e6f9a2b3c5d7e8f1a3b6c9d2e4f7a9b1
Same Key Stream Seed: 4b7e2c9f1a3d8e6b4c2f7a9e3d1b8c6f2e9a7d4c1f8b6e3a9c7d2f4e1b8a6c3d
Same MAC Key: 8d3f6a2c9e1b7f4d2a8c6e3f9b1d7a4c6e2f8b3a9d1c7e4f2b8a6c3d9f1e8b4a
```

**Received Message:**
```json
{
  "ciphertext": "ebb2437...f52d",
  "hmac_tag": "c7f8e9d2a3b6c4f7e8a9d1b3c6f2e8d9a4b7c3f6e9d2a8b1c4f7e3d9b6a2c8f4",
  "seq_no": 0,
  "timestamp": 1737395000123,
  "session_id": "S-12345"
}
```

---

### **Step 1: Recreate AAD**

Bob reconstructs the AAD from metadata:
```
AAD = "S-12345:0:1737395000123"
```

---

### **Step 2: Verify HMAC Tag (Authentication Check)**

**CRITICAL:** Bob verifies the message BEFORE decrypting!

**Compute expected tag:**
```
Expected_Tag = HMAC-SHA3-256(
    key = MAC_Key,
    message = AAD + ciphertext
)

Expected_Tag = c7f8e9d2a3b6c4f7e8a9d1b3c6f2e8d9a4b7c3f6e9d2a8b1c4f7e3d9b6a2c8f4
```

**Compare tags (constant-time comparison):**
```
Received_Tag:  c7f8e9d2a3b6c4f7e8a9d1b3c6f2e8d9a4b7c3f6e9d2a8b1c4f7e3d9b6a2c8f4
Expected_Tag:  c7f8e9d2a3b6c4f7e8a9d1b3c6f2e8d9a4b7c3f6e9d2a8b1c4f7e3d9b6a2c8f4
              ───────────────────────────────────────────────────────────────────
Match: ✅ YES!
```

If tags match → Message is authentic and unmodified
If tags don't match → **ABORT! Message was tampered with!**

---



### **Step 3: Regenerate Key Stream**

Bob generates the **same key stream** Alice used:

```
Key Stream = HKDF-Expand(
    key = Key_Stream_Seed,
    info = "msg-0-S-12345",
    length = 9 bytes
)

Result: a3 d7 2f 1c 8b 6e 2d 9a 4f
```

**This is identical to Alice's key stream!** (Deterministic process)

---

### **Step 4: XOR Decryption**

Bob XORs the ciphertext with the key stream:

```
Ciphertext:   eb b2 43 70 e4 4e 6f f5 2d
Key Stream:   a3 d7 2f 1c 8b 6e 2d 9a 4f
             ─────────────────────────────
Plaintext:    48 65 6c 6c 6f 20 42 6f 62
```

**Why this works:**
```
Encryption:  Plaintext ⊕ KeyStream = Ciphertext
Decryption:  Ciphertext ⊕ KeyStream = Plaintext

Because: (Plaintext ⊕ KeyStream) ⊕ KeyStream = Plaintext
         (XOR property: A ⊕ B ⊕ B = A)
```

---

### **Step 5: Convert to Text**

Convert bytes back to UTF-8 string:
```
Plaintext bytes: 48 65 6c 6c 6f 20 42 6f 62
UTF-8 decode: "Hello Bob"
```

**Success!** Bob can now read Alice's message! 🎉

---

## 🔍 Complete Example with All Steps

Let's trace through **two messages** to show key stream uniqueness!

### **Message #1: "Hi"**

#### **Encryption:**
```
Plaintext: "Hi" = 48 69
Sequence: 0
Key Stream = HKDF-Expand(seed, "msg-0-S-12345") = c3 d4
Ciphertext = 48⊕c3, 69⊕d4 = 8b bd
AAD = "S-12345:0:1737395000100"
HMAC Tag = 7a3f9e2d1c8b6a4f3e9d2c1b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f
```

#### **Decryption:**
```
Verify HMAC: ✅
Key Stream = HKDF-Expand(seed, "msg-0-S-12345") = c3 d4
Plaintext = 8b⊕c3, bd⊕d4 = 48 69 = "Hi" ✅
```

---

### **Message #2: "Bye"**

#### **Encryption:**
```
Plaintext: "Bye" = 42 79 65
Sequence: 1 (incremented!)
Key Stream = HKDF-Expand(seed, "msg-1-S-12345") = f7 a2 8d (DIFFERENT!)
Ciphertext = 42⊕f7, 79⊕a2, 65⊕8d = b5 db e8
AAD = "S-12345:1:1737395000200"
HMAC Tag = 9c2f8e3d7a1b6f4c8e2a9d3f7b1c6e8a4d2f9b3c7e1a8d4f2b9c6e3a8f1d4b7c
```

#### **Decryption:**
```
Verify HMAC: ✅
Key Stream = HKDF-Expand(seed, "msg-1-S-12345") = f7 a2 8d
Plaintext = b5⊕f7, db⊕a2, e8⊕8d = 42 79 65 = "Bye" ✅
```

**Notice:**
- Same Key Stream Seed
- Different sequence number → **Different key stream!**
- This is how we achieve OTP security with deterministic keys

---

## 🛡️ Security Features Explained

### **1. Perfect Forward Secrecy**

Each session generates new keys:
```
Session 1: BB84 → HKDF → Keys for Session 1
Session 2: BB84 → HKDF → Keys for Session 2 (DIFFERENT!)

Even if Session 2 keys are compromised, Session 1 messages stay secure!
```

---

### **2. Replay Attack Prevention**

Every message has:
- **Sequence number** - Prevents reordering
- **Timestamp** - Detects delayed replays
- **Session ID** - Prevents cross-session replays

Example attack (fails):
```
Eve intercepts message #5 and tries to replay it
↓
Bob checks sequence: Expected #6, got #5 → ❌ Reject!
Bob checks timestamp: 2 hours old → ❌ Reject!
```

---

### **3. Tamper Detection**

HMAC-SHA3 covers:
- ✅ Ciphertext
- ✅ Metadata (AAD)
- ✅ Session ID
- ✅ Sequence number
- ✅ Timestamp

Any change → HMAC verification fails!

Example:
```
Eve changes ciphertext: ebb2 → ebb3
↓
Bob computes HMAC with modified ciphertext
↓
Expected: c7f8e9d2...
Received: c7f8e9d2...
↓
Tags DON'T match → ❌ Message rejected!
```

---

### **4. Key Stream Non-Reuse**

The system tracks used key stream offsets:
```python
Message #0: Offset 0-1024 → Used ✅
Message #1: Offset 1024-2048 → Used ✅
Message #2: Offset 2048-3072 → Used ✅

If you try to encrypt two messages with same sequence:
→ ERROR: Key stream reuse detected! 🚨
```

---

### **5. Post-Quantum Authentication**

Optional Dilithium signatures provide:
- ✅ Quantum-resistant authentication
- ✅ Non-repudiation (sender can't deny)
- ✅ Public key verification

```
Alice signs with Dilithium private key
↓
Bob verifies with Dilithium public key
↓
Even quantum computer can't forge signature!
```

---

## 📊 Message Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Alice (Sender)                          │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Plaintext: "Hi"    │
                    └──────────┬──────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
        ▼                      ▼                      ▼
┌──────────────┐    ┌──────────────────┐    ┌──────────────┐
│ Generate     │    │ Get Metadata     │    │ Increment    │
│ Key Stream   │    │ - Session ID     │    │ Sequence     │
│ from HKDF    │    │ - Timestamp      │    │ Counter      │
└──────┬───────┘    └─────────┬────────┘    └──────┬───────┘
       │                      │                     │
       │            ┌─────────▼─────────┐           │
       │            │ Create AAD String │           │
       │            └─────────┬─────────┘           │
       │                      │                     │
       ▼                      │                     │
┌──────────────┐              │                     │
│ XOR Encrypt  │              │                     │
│ Plaintext    │              │                     │
└──────┬───────┘              │                     │
       │                      │                     │
       │            ┌─────────▼─────────────────────▼───┐
       └───────────▶│ Compute HMAC-SHA3-256 Tag         │
                    │ (MAC Key, AAD + Ciphertext)       │
                    └─────────┬─────────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │ Optional: Sign     │
                    │ with Dilithium     │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────────────────────┐
                    │ Package Encrypted Message:         │
                    │ - Ciphertext                       │
                    │ - HMAC Tag                         │
                    │ - Metadata (seq, time, session)    │
                    │ - PQC Signature (optional)         │
                    └─────────┬──────────────────────────┘
                              │
                   [Network Transmission]
                              │
┌─────────────────────────────▼──────────────────────────────────┐
│                         Bob (Receiver)                         │
└──────────────────────────────┬─────────────────────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │ Verify PQC Signature (opt)  │
                    └──────────┬──────────────────┘
                               │ ✅
                    ┌──────────▼──────────────────┐
                    │ Recreate AAD from Metadata  │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │ Compute Expected HMAC Tag   │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │ Compare Tags                │
                    └──────────┬──────────────────┘
                               │ ✅ Match!
                    ┌──────────▼──────────────────┐
                    │ Generate Same Key Stream    │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │ XOR Decrypt Ciphertext      │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │ Plaintext: "Hi" ✅          │
                    └─────────────────────────────┘
```

---

## 💻 Python Code Example

Here's a simplified implementation:

```python
import hmac
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

class MessageEncryption:
    def __init__(self, key_stream_seed, mac_key, session_id):
        self.key_stream_seed = key_stream_seed
        self.mac_key = mac_key
        self.session_id = session_id
        self.seq_counter = 0
    
    def generate_key_stream(self, length, seq_no):
        """Generate unique key stream for this message"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=f"msg-{seq_no}-{self.session_id}".encode('utf-8'),
        )
        return hkdf.derive(self.key_stream_seed)
    
    def encrypt_message(self, plaintext):
        """Encrypt message using OTP + HMAC"""
        # Convert to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Get sequence number
        seq_no = self.seq_counter
        self.seq_counter += 1
        
        # Generate key stream
        key_stream = self.generate_key_stream(len(plaintext_bytes), seq_no)
        
        # XOR encrypt
        ciphertext = bytes(a ^ b for a, b in zip(plaintext_bytes, key_stream))
        
        # Create AAD
        timestamp = 1737395000123  # In real code, use time.time()
        aad = f"{self.session_id}:{seq_no}:{timestamp}".encode('utf-8')
        
        # Compute HMAC
        h = hmac.new(self.mac_key, aad + ciphertext, hashlib.sha3_256)
        hmac_tag = h.digest()
        
        return {
            'ciphertext': ciphertext.hex(),
            'hmac_tag': hmac_tag.hex(),
            'seq_no': seq_no,
            'timestamp': timestamp,
            'session_id': self.session_id
        }
    
    def decrypt_message(self, encrypted_msg):
        """Decrypt and verify message"""
        # Parse hex strings
        ciphertext = bytes.fromhex(encrypted_msg['ciphertext'])
        received_tag = bytes.fromhex(encrypted_msg['hmac_tag'])
        
        # Recreate AAD
        aad = f"{encrypted_msg['session_id']}:{encrypted_msg['seq_no']}:{encrypted_msg['timestamp']}".encode('utf-8')
        
        # Verify HMAC
        expected_tag = hmac.new(self.mac_key, aad + ciphertext, hashlib.sha3_256).digest()
        
        if not hmac.compare_digest(received_tag, expected_tag):
            raise ValueError("HMAC verification failed!")
        
        # Generate same key stream
        key_stream = self.generate_key_stream(len(ciphertext), encrypted_msg['seq_no'])
        
        # XOR decrypt
        plaintext_bytes = bytes(a ^ b for a, b in zip(ciphertext, key_stream))
        
        return plaintext_bytes.decode('utf-8')


# Example usage
key_stream_seed = bytes.fromhex('4b7e2c9f1a3d8e6b4c2f7a9e3d1b8c6f2e9a7d4c1f8b6e3a9c7d2f4e1b8a6c3d')
mac_key = bytes.fromhex('8d3f6a2c9e1b7f4d2a8c6e3f9b1d7a4c6e2f8b3a9d1c7e4f2b8a6c3d9f1e8b4a')

# Alice encrypts
alice = MessageEncryption(key_stream_seed, mac_key, "S-12345")
encrypted = alice.encrypt_message("Hello Bob")
print(f"Encrypted: {encrypted}")

# Bob decrypts
bob = MessageEncryption(key_stream_seed, mac_key, "S-12345")
plaintext = bob.decrypt_message(encrypted)
print(f"Decrypted: {plaintext}")  # Output: "Hello Bob"
```

---

## ⚠️ Common Security Pitfalls (Avoided!)

### ❌ **DON'T: Reuse Key Streams**
```python
# WRONG! Same key for two messages
key = b"same_key_for_all"
cipher1 = xor(msg1, key)
cipher2 = xor(msg2, key)

# Eve can XOR the two ciphertexts:
cipher1 ⊕ cipher2 = (msg1 ⊕ key) ⊕ (msg2 ⊕ key)
                  = msg1 ⊕ msg2  (keys cancel out!)
# Now Eve can use frequency analysis to recover both messages!
```

✅ **DO: Generate Unique Key Stream per Message**
```python
# CORRECT! Different key for each message
key_stream_1 = HKDF(seed, "msg-0-session")
key_stream_2 = HKDF(seed, "msg-1-session")  # Different!
```

---

### ❌ **DON'T: Encrypt-Then-MAC**
```python
# WRONG order!
ciphertext = encrypt(plaintext)
tag = MAC(ciphertext)  # Only MAC the ciphertext
```

✅ **DO: MAC-Then-Encrypt or Encrypt-and-MAC**
```python
# CORRECT! MAC covers both AAD and ciphertext
tag = HMAC(MAC_Key, AAD + ciphertext)
```

---

### ❌ **DON'T: Skip HMAC Verification**
```python
# WRONG! Decrypt before verifying
plaintext = decrypt(ciphertext)
if verify_hmac(...):  # Too late!
    return plaintext
```

✅ **DO: Verify Before Decrypting**
```python
# CORRECT! Check authenticity first
if not verify_hmac(...):
    raise Error("Tampered message!")
plaintext = decrypt(ciphertext)
```

---

## 🎓 Key Takeaways

1. **OTP-Style Encryption** - Theoretically unbreakable when done right
   - Unique key stream per message
   - XOR operation for encryption/decryption

2. **HMAC-SHA3 Authentication** - Detects tampering
   - Computed before sending
   - Verified before decrypting

3. **Metadata Protection** - Session binding and replay prevention
   - Session ID prevents cross-session attacks
   - Sequence number prevents replays
   - Timestamp adds time-based validation

4. **Post-Quantum Ready** - Optional Dilithium signatures
   - Quantum-resistant authentication
   - Future-proof security

5. **Deterministic but Unique** - Same inputs → same outputs
   - Alice and Bob get same key streams (needed for decryption!)
   - But different messages get different key streams (security!)

---

## 🔗 Related Documentation

- [BB84.md](BB84.md) - How the quantum key is generated
- [HKDF.md](HKDF.md) - How BB84 key is expanded to multiple keys
- [README.md](README.md) - Full system overview

---

**Now you understand how messages are encrypted and decrypted in our quantum-safe system!** 🎉
