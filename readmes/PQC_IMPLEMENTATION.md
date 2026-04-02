# Post-Quantum Cryptography (PQC) Implementation

## Overview

This document describes the Post-Quantum Cryptography (PQC) implementation in the BB84 QKD system. The system now includes comprehensive PQC support using NIST-approved algorithms to provide quantum-resistant security.

## Features

### 1. **Hybrid Key Exchange**
- Combines BB84 quantum key distribution with post-quantum key encapsulation (Kyber)
- Provides defense-in-depth: quantum security from BB84 + classical post-quantum security from PQC
- Hybrid keys are derived using HKDF-SHA256

### 2. **Automatic Message Signing**
- All encrypted messages are automatically signed using Dilithium signatures
- Provides post-quantum authentication and non-repudiation
- Signatures are verified automatically during message decryption

### 3. **NIST-Approved Algorithms**

#### Key Encapsulation Mechanisms (KEM)
- **Kyber512** (NIST Level 1, 128-bit security) - Currently implemented
- **Kyber768** (NIST Level 3, 192-bit security) - Available via liboqs
- **Kyber1024** (NIST Level 5, 256-bit security) - Available via liboqs

#### Digital Signatures
- **Dilithium2** (NIST Level 2, 128-bit security) - Currently implemented
- **Dilithium3** (NIST Level 3, 192-bit security) - Available via liboqs
- **Dilithium5** (NIST Level 5, 256-bit security) - Available via liboqs
- **SPHINCS+** (Stateless hash-based signatures) - Available via liboqs

### 4. **PQC Configuration System**
- Centralized algorithm configuration
- Algorithm selection based on security requirements
- Support for multiple security levels

## Architecture

### Components

1. **PQCService** (`backend/app/services/pqc_service.py`)
   - Core PQC operations (key generation, encapsulation, signing, verification)
   - Supports liboqs-python (primary) and pqcrypto (fallback)
   - Demo mode for development/testing

2. **PQCConfigService** (`backend/app/services/pqc_config.py`)
   - Algorithm configuration and selection
   - Security level management
   - Algorithm availability tracking

3. **CryptoService Integration** (`backend/app/services/crypto_service.py`)
   - Automatic PQC signing on message encryption
   - Automatic PQC signature verification on message decryption
   - Hybrid key derivation

4. **Session Model** (`backend/app/models/session.py`)
   - PQC signature storage in message payloads
   - PQC key management per session

## Usage

### Enabling Hybrid Mode

When starting a BB84 simulation, enable hybrid mode:

```python
POST /session/{session_id}/start_bb84
{
    "n_bits": 1000,
    "test_fraction": 0.1,
    "use_hybrid": true  # Enable PQC hybrid mode
}
```

### Getting PQC Information

```python
GET /session/{session_id}/pqc/info
```

Returns:
- PQC library availability
- Algorithm information
- Key sizes
- Configuration options

### Manual PQC Operations

#### Key Exchange (Kyber)
```python
# Get public keys
GET /session/{session_id}/pqc/public_keys

# Encapsulate shared secret
POST /session/{session_id}/pqc/encapsulate
{
    "peer_kyber_public": "<hex_encoded_public_key>"
}

# Decapsulate shared secret
POST /session/{session_id}/pqc/decapsulate
{
    "ciphertext": "<hex_encoded_ciphertext>"
}
```

#### Message Signing (Dilithium)
```python
# Sign a message
POST /session/{session_id}/pqc/sign
{
    "message": "Hello, quantum world!"
}

# Verify a signature
POST /session/{session_id}/pqc/verify
{
    "signature": "<hex_encoded_signature>",
    "message": "Hello, quantum world!",
    "public_key": "<hex_encoded_public_key>"
}
```

## Security Properties

### Quantum Resistance
- All PQC algorithms are designed to resist attacks from quantum computers
- NIST-approved algorithms provide standardized security guarantees

### Defense in Depth
- Hybrid approach: BB84 (quantum) + PQC (classical post-quantum)
- Multiple layers of authentication: HMAC + PQC signatures

### Forward Secrecy
- Session keys are ephemeral
- PQC keys are generated per session
- Keys are securely cleared after session termination

## Implementation Details

### Message Encryption Flow

1. **Encryption**
   - Message encrypted with OTP (one-time pad)
   - HMAC-SHA3-256 computed for integrity
   - Dilithium signature computed for authentication
   - All components included in message payload

2. **Decryption**
   - HMAC verified first (integrity check)
   - PQC signature verified (authentication)
   - Message decrypted with OTP
   - Any verification failure raises security exception

### Key Derivation

Hybrid keys are derived using HKDF-SHA256:

```
IKM = BB84_Key || PQC_Shared_Secret
Final_Key = HKDF(IKM, salt=session_id, info='hybrid-session')
```

### Algorithm Selection

Default algorithms:
- **KEM**: Kyber512 (NIST Level 1)
- **Signature**: Dilithium2 (NIST Level 2)

Higher security levels available via configuration.

## Dependencies

### Required Libraries

1. **liboqs-python** (Primary)
   - Official Open Quantum Safe library
   - Provides all NIST-approved algorithms
   - High performance C implementations

2. **pqcrypto** (Fallback)
   - Pure Python implementations
   - Useful for development/testing
   - Slower but more portable

### Installation

```bash
pip install liboqs-python>=0.8.0
pip install pqcrypto>=0.20.1
```

Or install from requirements.txt:
```bash
pip install -r backend/requirements.txt
```

## Fallback Mode

If PQC libraries are not available, the system operates in **demo mode**:
- Uses deterministic algorithms based on SHA-256
- Provides same API but not cryptographically secure
- Logs warnings for all demo operations
- Suitable for development/testing only

## Performance Considerations

### Key Sizes
- Kyber512: Public key 800 bytes, Private key 1632 bytes, Ciphertext 768 bytes
- Dilithium2: Public key 1312 bytes, Private key 2528 bytes, Signature 2420 bytes

### Computational Overhead
- Key generation: ~10-50ms (depending on algorithm)
- Signing: ~5-20ms per message
- Verification: ~5-20ms per message
- Encapsulation/Decapsulation: ~5-15ms

## Future Enhancements

1. **Additional Algorithms**
   - SPHINCS+ implementation
   - Additional Kyber/Dilithium variants
   - Algorithm selection based on performance requirements

2. **Key Management**
   - Long-term PQC key storage
   - Key rotation policies
   - Certificate management

3. **Performance Optimization**
   - Caching of PQC keys
   - Batch signing/verification
   - Hardware acceleration support

## References

- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [Kyber Specification](https://pq-crystals.org/kyber/)
- [Dilithium Specification](https://pq-crystals.org/dilithium/)


