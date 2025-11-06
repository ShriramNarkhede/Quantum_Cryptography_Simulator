"""
Updated BB84 QKD Simulation System - Main FastAPI Application with Enhanced Cryptography
"""

from fastapi import FastAPI, HTTPException, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
import socketio
import uvicorn
from typing import Dict, List, Optional
import uuid
import logging
from datetime import datetime
import asyncio
import base64

from app.models.session import Session, User, UserRole, MessageType, create_system_message, validate_session_security
from app.services.session_manager import SessionManager
from app.services.bb84_engine import BB84Engine
from app.services.eve_module import EveModule
from app.services.crypto_service import CryptoService, create_message_payload, parse_message_payload

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="BB84 QKD Simulation API - Enhanced Cryptography",
    description="Backend API for BB84 Quantum Key Distribution Simulation with Production-Grade Cryptography",
    version="2.0.0"
)

# CORS middleware for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],  # Support both CRA and Vite
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Socket.IO server
sio = socketio.AsyncServer(
    cors_allowed_origins=["http://localhost:3000", "http://localhost:5173"],
    logger=True,
    async_mode='asgi',
    engineio_logger=True
)

# Attach Socket.IO to FastAPI
socket_app = socketio.ASGIApp(sio, app)

# Initialize services
session_manager = SessionManager()
bb84_engine = BB84Engine()
eve_module = EveModule()

# REST API Endpoints

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "message": "BB84 QKD Simulation API - Enhanced Cryptography",
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "features": ["OTP+HMAC-SHA3", "XChaCha20-Poly1305", "HKDF-SHA256", "PQC-Ready"]
    }

@app.post("/session/create")
async def create_session():
    """Create a new QKD session"""
    try:
        session = session_manager.create_session()
        logger.info(f"Created new session: {session.session_id}")
        return {
            "session_id": session.session_id,
            "created_at": session.created_at.isoformat(),
            "status": "created",
            "crypto_enabled": True
        }
    except Exception as e:
        logger.error(f"Error creating session: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create session")

@app.post("/session/{session_id}/join")
async def join_session(session_id: str, user_role: str):
    """Join an existing session with specified role"""
    try:
        if user_role not in ["alice", "bob", "eve"]:
            raise HTTPException(status_code=400, detail="Invalid user role")
        
        user_role_enum = UserRole(user_role)
        user = session_manager.add_user_to_session(session_id, user_role_enum)
        
        if not user:
            raise HTTPException(status_code=404, detail="Session not found or role already taken")
        
        logger.info(f"User {user.user_id} joined session {session_id} as {user_role}")
        return {
            "user_id": user.user_id,
            "session_id": session_id,
            "role": user_role,
            "status": "joined",
            "crypto_ready": True
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error joining session: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to join session")

@app.get("/session/{session_id}/status")
async def get_session_status(session_id: str):
    """Get current session status and participants"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Validate session security
    security_issues = validate_session_security(session)
    
    response = session.to_dict()
    response.update({
        "security_issues": security_issues,
        "crypto_info": session.get_session_security_info()
    })
    
    return response

@app.get("/session/{session_id}/security")
async def get_session_security_info(session_id: str):
    """Get detailed security information about the session"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return session.get_session_security_info()

@app.get("/session/{session_id}/session_key")
async def get_session_key(session_id: str):
    """Get the session key for encryption/decryption (for frontend use)"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if not session.crypto_session.key_established:
        raise HTTPException(status_code=400, detail="No session key available")
    
    # Get the file encryption key (32 bytes for XChaCha20)
    if not session.crypto_session.derived_keys:
        raise HTTPException(status_code=400, detail="No derived keys available")
    
    # Return the file encryption key as hex string
    file_key = session.crypto_session.derived_keys.key_file
    logger.info(f"Retrieved session key for {session_id}: length={len(file_key)} bytes")
    logger.info(f"Key hex string: {file_key.hex()}")
    logger.info(f"Key hex string length: {len(file_key.hex())}")
    
    return {
        "session_id": session_id,
        "key": file_key.hex(),
        "key_length": len(file_key),
        "crypto_established": True
    }

@app.post("/session/{session_id}/start_bb84")
async def start_bb84_simulation(session_id: str, n_bits: int = 1000, test_fraction: float = 0.1, use_hybrid: bool = False):
    """Start BB84 key generation process with optional PQC hybrid mode"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Check if Alice and Bob are present
    alice = session.get_user_by_role(UserRole.ALICE)
    bob = session.get_user_by_role(UserRole.BOB)
    
    if not alice or not bob:
        raise HTTPException(status_code=400, detail="Both Alice and Bob must be present")
    
    # Start BB84 simulation in background
    asyncio.create_task(run_bb84_simulation(session_id, n_bits, test_fraction, use_hybrid))
    
    return {
        "session_id": session_id,
        "message": "BB84 simulation started",
        "n_bits": n_bits,
        "test_fraction": test_fraction,
        "hybrid_mode": use_hybrid
    }

@app.post("/session/{session_id}/send_file")
async def send_encrypted_file(session_id: str, sender_id: str, file: UploadFile = File(...)):
    """Send encrypted file to session"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if not session.crypto_session.key_established:
        raise HTTPException(status_code=400, detail="No encryption keys available")
    
    try:
        # Read file data
        file_data = await file.read()
        
        # Check if this is an already encrypted file from frontend
        if file.filename and file.filename.endswith('.enc'):
            # This is already encrypted by frontend, store it directly
            logger.info(f"Received pre-encrypted file: {file.filename}")
            
            # Create a secure message with the encrypted data
            from app.models.session import SecureMessage, MessageType
            import uuid
            
            # Parse the encrypted file format (nonce + ciphertext)
            if len(file_data) < 24:  # XChaCha20 nonce is 24 bytes
                raise HTTPException(status_code=400, detail="Invalid encrypted file format")
            
            nonce = file_data[:24]
            ciphertext = file_data[24:]
            
            # Create payload for the encrypted file
            payload = {
                'ciphertext': ciphertext.hex(),
                'nonce': nonce.hex(),
                'aad': b'frontend_encrypted'.hex(),  # Mark as frontend encrypted
                'filename': file.filename,
                'file_seq_no': 0,  # Will be set by session
                'session_id': session_id,
                'crypto_type': 'xchacha20_poly1305',
                'file_size': len(file_data)
            }
            
            secure_msg = SecureMessage(
                message_id=str(uuid.uuid4()),
                sender_id=sender_id,
                message_type=MessageType.FILE_XCHACHA20,
                encrypted_payload=payload,
                seq_no=0,
                verified=True,
                size_bytes=len(ciphertext)
            )
            
            session.messages.append(secure_msg)
            logger.info(f"Stored pre-encrypted file: {file.filename}")
        else:
            # This is a plain file, encrypt it on the backend
            logger.info(f"Encrypting plain file: {file.filename}")
            secure_msg = session.add_encrypted_file(sender_id, file_data, file.filename or "unknown")
        
        if not secure_msg:
            raise HTTPException(status_code=500, detail="Failed to encrypt file")
        
        # Emit file message to other participants
        await sio.emit("encrypted_file_received", {
            "message_id": secure_msg.message_id,
            "sender_id": sender_id,
            "filename": file.filename,
            "file_size": len(file_data),
            "timestamp": secure_msg.timestamp.isoformat()
        }, room=f"session_{session_id}")
        
        return {
            "message_id": secure_msg.message_id,
            "status": "encrypted_and_sent",
            "filename": file.filename,
            "file_size": len(file_data)
        }
        
    except Exception as e:
        logger.error(f"Error sending encrypted file: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to send encrypted file")

@app.get("/session/{session_id}/download_file/{message_id}")
async def download_encrypted_file(session_id: str, message_id: str, user_id: str):
    """Download and decrypt file"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Find the message
    file_message = None
    for msg in session.messages:
        if msg.message_id == message_id and msg.message_type == MessageType.FILE_XCHACHA20:
            file_message = msg
            break
    
    if not file_message:
        raise HTTPException(status_code=404, detail="File message not found")
    
    try:
        # Check if session has valid crypto keys
        if not session.crypto_session.key_established:
            logger.error(f"Session {session_id} does not have established crypto keys")
            raise HTTPException(status_code=400, detail="No encryption keys available for decryption")
        
        # Decrypt file
        logger.info(f"Attempting to decrypt file {message_id} for user {user_id}")
        result = session.decrypt_file(file_message)
        if not result:
            logger.error(f"Failed to decrypt file {message_id}")
            raise HTTPException(status_code=500, detail="Failed to decrypt file")
        
        file_data, filename = result
        logger.info(f"Successfully decrypted file {message_id}: {filename} ({len(file_data)} bytes)")
        logger.info(f"Decrypted file data preview: {file_data[:50].hex() if len(file_data) > 0 else 'empty'}")
        
        # Return base64 encoded file data (for JSON transport)
        return {
            "filename": filename,
            "file_data": base64.b64encode(file_data).decode('utf-8'),
            "file_size": len(file_data),
            "message_id": message_id
        }
        
    except Exception as e:
        logger.error(f"Error downloading file: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to download file")

@app.get("/session/{session_id}/download_encrypted_file/{message_id}")
async def download_raw_encrypted_file(session_id: str, message_id: str, user_id: str):
    """Download encrypted file (raw encrypted data)"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Find the message
    file_message = None
    for msg in session.messages:
        if msg.message_id == message_id and msg.message_type == MessageType.FILE_XCHACHA20:
            file_message = msg
            break
    
    if not file_message:
        raise HTTPException(status_code=404, detail="File message not found")
    
    try:
        # Get encrypted payload
        payload = file_message.encrypted_payload
        encrypted_data = bytes.fromhex(payload['ciphertext'])
        original_filename = payload['filename']
        
        # Create encrypted filename
        encrypted_filename = f"{original_filename}.encrypted"
        
        # Return base64 encoded encrypted file data
        return {
            "filename": encrypted_filename,
            "file_data": base64.b64encode(encrypted_data).decode('utf-8'),
            "file_size": len(encrypted_data),
            "message_id": message_id,
            "original_filename": original_filename,
            "encrypted": True
        }
        
    except Exception as e:
        logger.error(f"Error downloading encrypted file: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to download encrypted file")

@app.get("/session/{session_id}/pqc/info")
async def get_pqc_info(session_id: str):
    """Get PQC capabilities and information"""
    try:
        from app.services.pqc_service import pqc_service
        pqc_info = pqc_service.get_pqc_info()
        
        return {
            "session_id": session_id,
            "pqc_info": pqc_info,
            "status": "available" if pqc_info["liboqs_available"] or pqc_info["pqcrypto_available"] else "demo_only"
        }
    except Exception as e:
        logger.error(f"Error getting PQC info: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get PQC information")

@app.get("/session/{session_id}/pqc/public_keys")
async def get_pqc_public_keys(session_id: str):
    """Get PQC public keys for key exchange"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if not session.crypto_session.key_established:
        raise HTTPException(status_code=400, detail="No cryptographic keys established")
    
    try:
        public_keys = session.crypto_session.crypto_service.get_pqc_public_keys()
        if not public_keys:
            raise HTTPException(status_code=400, detail="No PQC keys available")
        
        # Convert bytes to hex for JSON transport
        hex_keys = {}
        for key_type, key_bytes in public_keys.items():
            hex_keys[key_type] = key_bytes.hex()
        
        return {
            "session_id": session_id,
            "public_keys": hex_keys,
            "key_types": list(public_keys.keys())
        }
    except Exception as e:
        logger.error(f"Error getting PQC public keys: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get PQC public keys")

@app.post("/session/{session_id}/pqc/encapsulate")
async def encapsulate_pqc_key(session_id: str, request: dict):
    """Encapsulate a shared secret using peer's Kyber public key"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if not session.crypto_session.key_established:
        raise HTTPException(status_code=400, detail="No cryptographic keys established")
    
    try:
        peer_kyber_public_hex = request.get("peer_kyber_public")
        if not peer_kyber_public_hex:
            raise HTTPException(status_code=400, detail="peer_kyber_public required")
        
        peer_kyber_public = bytes.fromhex(peer_kyber_public_hex)
        
        result = session.crypto_session.crypto_service.encapsulate_shared_secret(peer_kyber_public)
        if not result:
            raise HTTPException(status_code=400, detail="PQC encapsulation failed")
        
        ciphertext, shared_secret = result
        
        return {
            "session_id": session_id,
            "ciphertext": ciphertext.hex(),
            "shared_secret": shared_secret.hex(),
            "algorithm": "Kyber512"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid hex data: {str(e)}")
    except Exception as e:
        logger.error(f"Error encapsulating PQC key: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to encapsulate PQC key")

@app.post("/session/{session_id}/pqc/decapsulate")
async def decapsulate_pqc_key(session_id: str, request: dict):
    """Decapsulate shared secret using our Kyber private key"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if not session.crypto_session.key_established:
        raise HTTPException(status_code=400, detail="No cryptographic keys established")
    
    try:
        ciphertext_hex = request.get("ciphertext")
        if not ciphertext_hex:
            raise HTTPException(status_code=400, detail="ciphertext required")
        
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        shared_secret = session.crypto_session.crypto_service.decapsulate_shared_secret(ciphertext)
        if not shared_secret:
            raise HTTPException(status_code=400, detail="PQC decapsulation failed")
        
        return {
            "session_id": session_id,
            "shared_secret": shared_secret.hex(),
            "algorithm": "Kyber512"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid hex data: {str(e)}")
    except Exception as e:
        logger.error(f"Error decapsulating PQC key: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to decapsulate PQC key")

@app.post("/session/{session_id}/pqc/sign")
async def sign_message_pqc(session_id: str, request: dict):
    """Sign a message using Dilithium"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if not session.crypto_session.key_established:
        raise HTTPException(status_code=400, detail="No cryptographic keys established")
    
    try:
        message = request.get("message", "").encode('utf-8')
        if not message:
            raise HTTPException(status_code=400, detail="message required")
        
        signature = session.crypto_session.crypto_service.sign_message_pqc(message)
        if not signature:
            raise HTTPException(status_code=400, detail="PQC signing failed")
        
        return {
            "session_id": session_id,
            "signature": signature.hex(),
            "message": message.decode('utf-8'),
            "algorithm": "Dilithium2"
        }
    except Exception as e:
        logger.error(f"Error signing message with PQC: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to sign message with PQC")

@app.post("/session/{session_id}/pqc/verify")
async def verify_signature_pqc(session_id: str, request: dict):
    """Verify a Dilithium signature"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    try:
        signature_hex = request.get("signature")
        message = request.get("message", "").encode('utf-8')
        public_key_hex = request.get("public_key")
        
        if not all([signature_hex, message, public_key_hex]):
            raise HTTPException(status_code=400, detail="signature, message, and public_key required")
        
        signature = bytes.fromhex(signature_hex)
        public_key = bytes.fromhex(public_key_hex)
        
        is_valid = session.crypto_session.crypto_service.verify_signature_pqc(signature, message, public_key)
        
        return {
            "session_id": session_id,
            "valid": is_valid,
            "message": message.decode('utf-8'),
            "algorithm": "Dilithium2"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid hex data: {str(e)}")
    except Exception as e:
        logger.error(f"Error verifying PQC signature: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to verify PQC signature")

@app.post("/session/{session_id}/terminate")
async def terminate_session(session_id: str):
    """Terminate session and clear all ephemeral data"""
    try:
        success = session_manager.terminate_session(session_id)
        if not success:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Emit termination event to all connected clients
        await sio.emit("session_terminated", 
                      {"session_id": session_id}, 
                      room=f"session_{session_id}")
        
        logger.info(f"Session {session_id} terminated with secure cleanup")
        return {"message": "Session terminated successfully"}
    except Exception as e:
        logger.error(f"Error terminating session: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to terminate session")

# Socket.IO Event Handlers

@sio.event
async def connect(sid, environ):
    """Handle client connection"""
    logger.info(f"Client connected: {sid}")
    await sio.emit("connected", {"message": "Connected to QKD server", "version": "2.0.0"}, room=sid)

@sio.event
async def disconnect(sid):
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {sid}")
    
    # Find and update user connection status
    for session in session_manager.sessions.values():
        for user in session.users.values():
            if user.socket_id == sid:
                user.connected = False
                user.socket_id = None
                logger.info(f"User {user.user_id} disconnected from session {session.session_id}")
                
                # Emit user disconnection to other participants
                await sio.emit("user_disconnected", 
                              {"user_id": user.user_id, "role": user.role.value},
                              room=f"session_{session.session_id}")
                break

@sio.event
async def join_session_socket(sid, data):
    """Join Socket.IO room for session"""
    try:
        session_id = data.get("session_id")
        user_id = data.get("user_id")
        
        if not session_id or not user_id:
            await sio.emit("error", {"message": "Session ID and User ID required"}, room=sid)
            return
        
        # Validate session and user
        session = session_manager.get_session(session_id)
        if not session:
            await sio.emit("error", {"message": "Session not found"}, room=sid)
            return
        
        user = session.users.get(user_id)
        if not user:
            await sio.emit("error", {"message": "User not found in session"}, room=sid)
            return
        
        # Update user socket connection
        user.socket_id = sid
        user.connected = True
        
        # Join Socket.IO room
        room_name = f"session_{session_id}"
        # Some versions of python-socketio expose enter_room as a sync API.
        # Call without await to support both signatures.
        result = sio.enter_room(sid, room_name)
        if hasattr(result, "__await__"):
            await result
        
        # Notify other participants
        await sio.emit("user_joined", 
                      {"user_id": user_id, "role": user.role.value},
                      room=room_name, skip_sid=sid)
        
        await sio.emit("joined_session", {
            "session_id": session_id,
            "user_id": user_id,
            "role": user.role.value,
            "crypto_ready": session.crypto_session.key_established
        }, room=sid)
        
        logger.info(f"User {user_id} joined Socket.IO room {room_name}")
        
    except Exception as e:
        logger.error(f"Error joining session socket: {str(e)}")
        await sio.emit("error", {"message": "Failed to join session"}, room=sid)

@sio.event
async def send_encrypted_message(sid, data):
    """Handle encrypted message transmission using OTP+HMAC"""
    try:
        session_id = data.get("session_id")
        message_content = data.get("message_content")
        sender_id = data.get("sender_id")
        
        if not all([session_id, message_content, sender_id]):
            await sio.emit("error", {"message": "Missing required fields"}, room=sid)
            return
        
        # Validate session
        session = session_manager.get_session(session_id)
        if not session or not session.crypto_session.key_established:
            await sio.emit("error", {"message": "No session key available"}, room=sid)
            return
        
        # Add encrypted message to session
        secure_msg = session.add_secure_message(sender_id, message_content, MessageType.CHAT_OTP)
        
        if not secure_msg:
            await sio.emit("error", {"message": "Failed to encrypt message"}, room=sid)
            return
        
        # Relay encrypted message to other participants
        await sio.emit("encrypted_message_received", {
            "message_id": secure_msg.message_id,
            "sender_id": sender_id,
            "encrypted_payload": secure_msg.encrypted_payload,
            "timestamp": secure_msg.timestamp.isoformat(),
            "seq_no": secure_msg.seq_no,
            "crypto_type": "otp_hmac_sha3"
        }, room=f"session_{session_id}", skip_sid=sid)
        
        logger.debug(f"Encrypted message sent from {sender_id} in session {session_id}")
        
    except Exception as e:
        logger.error(f"Error sending encrypted message: {str(e)}")
        await sio.emit("error", {"message": "Failed to send message"}, room=sid)

@sio.event
async def decrypt_message(sid, data):
    """Handle message decryption request"""
    try:
        session_id = data.get("session_id")
        message_id = data.get("message_id")
        user_id = data.get("user_id")
        
        if not session_id or not message_id or not user_id:
            await sio.emit("error", {"message": "Session ID, Message ID and User ID required"}, room=sid)
            return
        
        session = session_manager.get_session(session_id)
        if not session:
            await sio.emit("error", {"message": "Session not found"}, room=sid)
            return

        # Authorize: only Alice or Bob can decrypt, Eve is not allowed
        user = session.users.get(user_id)
        if not user:
            await sio.emit("error", {"message": "User not found in session"}, room=sid)
            return
        if user.role == UserRole.EVE:
            await sio.emit("error", {"message": "Unauthorized to decrypt message"}, room=sid)
            return
        
        # Find the message
        target_message = None
        for msg in session.messages:
            if msg.message_id == message_id:
                target_message = msg
                break
        
        if not target_message:
            await sio.emit("error", {"message": "Message not found"}, room=sid)
            return
        
        # Decrypt message
        decrypted_content = session.decrypt_message(target_message)
        
        if decrypted_content is None:
            await sio.emit("error", {"message": "Failed to decrypt message"}, room=sid)
            return
        
        await sio.emit("message_decrypted", {
            "message_id": message_id,
            "decrypted_content": decrypted_content,
            "sender_id": target_message.sender_id
        }, room=sid)
        
    except Exception as e:
        logger.error(f"Error decrypting message: {str(e)}")
        await sio.emit("error", {"message": "Failed to decrypt message"}, room=sid)

@sio.event
async def eve_control(sid, data):
    """Handle Eve attack control"""
    try:
        session_id = data.get("session_id")
        attack_type = data.get("attack_type")
        attack_params = data.get("attack_params", {})
        
        session = session_manager.get_session(session_id)
        if not session:
            await sio.emit("error", {"message": "Session not found"}, room=sid)
            return
        
        # Update Eve parameters in session
        session.eve_params = {
            "attack_type": attack_type,
            "params": attack_params
        }
        
        # Notify all participants about Eve status
        await sio.emit("eve_status_update", {
            "attack_type": attack_type,
            "params": attack_params
        }, room=f"session_{session_id}")
        
        logger.info(f"Eve attack updated in session {session_id}: {attack_type}")
        
    except Exception as e:
        logger.error(f"Error handling Eve control: {str(e)}")
        await sio.emit("error", {"message": "Failed to update Eve parameters"}, room=sid)

# Background task for BB84 simulation
async def run_bb84_simulation(session_id: str, n_bits: int, test_fraction: float, use_hybrid: bool = False):
    """Run BB84 simulation with real-time updates and enhanced cryptography"""
    try:
        session = session_manager.get_session(session_id)
        if not session:
            return
        
        room_name = f"session_{session_id}"
        
        # Emit simulation start
        await sio.emit("bb84_started", {
            "n_bits": n_bits,
            "test_fraction": test_fraction,
            "hybrid_mode": use_hybrid
        }, room=room_name)
        
        # Run BB84 simulation with Eve if present
        eve_present = session.get_user_by_role(UserRole.EVE) is not None
        eve_params = session.eve_params if eve_present else None
        
        # Generate PQC key if hybrid mode requested
        pqc_key = None
        if use_hybrid:
            # Generate real PQC shared secret using Kyber KEM
            try:
                from app.services.pqc_service import pqc_service
                
                # Generate Kyber key pair for Alice
                alice_kyber_keys = pqc_service.generate_kyber_keypair()
                
                # Bob encapsulates a shared secret using Alice's public key
                ciphertext_obj = pqc_service.encapsulate_key(alice_kyber_keys.public_key)
                pqc_key = ciphertext_obj.shared_secret
                
                # Store Alice's private key for later decapsulation (in real implementation, this would be exchanged)
                # For demo purposes, we'll use the shared secret directly
                
                await sio.emit("pqc_key_generated", {
                    "key_length": len(pqc_key),
                    "algorithm": "Kyber512",
                    "ciphertext_length": len(ciphertext_obj.ciphertext),
                    "public_key_length": len(alice_kyber_keys.public_key),
                    "private_key_length": len(alice_kyber_keys.private_key)
                }, room=room_name)
                
                logger.info(f"Generated real PQC key using Kyber512: {len(pqc_key)} bytes")
                
            except Exception as e:
                logger.error(f"Failed to generate real PQC key: {e}")
                # Fallback to demo PQC key
                import secrets
                pqc_key = secrets.token_bytes(32)
                await sio.emit("pqc_key_generated", {
                    "key_length": len(pqc_key),
                    "algorithm": "demo-kyber-like",
                    "error": str(e)
                }, room=room_name)
        
        async for progress_data in bb84_engine.run_simulation(
            n_bits, test_fraction, eve_params, eve_module if eve_present else None
        ):
            # Emit progress updates
            await sio.emit("bb84_progress", progress_data, room=room_name)
            
            # Check for QBER threshold exceeded
            if progress_data.get("qber_exceeded"):
                await sio.emit("eve_detected", {
                    "qber": progress_data.get("qber"),
                    "threshold": progress_data.get("threshold")
                }, room=room_name)
                session_manager.terminate_session(session_id)
                return
        
        # Simulation completed successfully
        bb84_key = bb84_engine.get_final_key()
        if not bb84_key:
            raise ValueError("BB84 simulation failed to produce key")
        
        # Establish secure session with derived keys
        success = session.establish_secure_session(bb84_key, pqc_key)
        
        if success:
            crypto_info = session.get_session_security_info()
            await sio.emit("bb84_complete", {
                "success": True,
                "key_length": len(bb84_key),
                "hybrid_mode": use_hybrid,
                "crypto_ready": True,
                "message": "Secure session established with derived keys",
                "crypto_info": crypto_info
            }, room=room_name)
            
            logger.info(f"BB84 simulation completed successfully for session {session_id}")
        else:
            raise ValueError("Failed to establish secure session")
        
    except Exception as e:
        logger.error(f"Error in BB84 simulation: {str(e)}")
        await sio.emit("bb84_error", {
            "error": str(e)
        }, room=f"session_{session_id}")

if __name__ == "__main__":
    uvicorn.run("app.main:socket_app", host="0.0.0.0", port=8000, reload=True)