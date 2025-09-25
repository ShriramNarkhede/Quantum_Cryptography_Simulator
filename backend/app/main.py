from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import socketio
import uvicorn
from typing import Dict, List, Optional
import uuid
import logging
from datetime import datetime
import asyncio

from app.models.session import Session, User, UserRole
from app.services.session_manager import SessionManager
from app.services.bb84_engine import BB84Engine
from app.services.eve_module import EveModule

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="BB84 QKD Simulation API",
    description="Backend API for BB84 Quantum Key Distribution Simulation",
    version="1.0.0"
)

# CORS middleware for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],  # Vite and React dev servers
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Socket.IO server (force ASGI driver to avoid aiohttp auto-selection)
sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins=["http://localhost:5173", "http://localhost:3000"],
    logger=True,
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
        "message": "BB84 QKD Simulation API",
        "status": "running",
        "timestamp": datetime.now().isoformat()
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
            "status": "created"
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
            "status": "joined"
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
    
    return {
        "session_id": session_id,
        "status": session.status.value,
        "participants": [
            {
                "user_id": user.user_id,
                "role": user.role.value,
                "connected": user.connected
            }
            for user in session.users.values()
        ],
        "created_at": session.created_at.isoformat()
    }

@app.post("/session/{session_id}/start_bb84")
async def start_bb84_simulation(session_id: str, n_bits: int = 1000, test_fraction: float = 0.1):
    """Start BB84 key generation process"""
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    # Check if Alice and Bob are present
    alice = session.get_user_by_role(UserRole.ALICE)
    bob = session.get_user_by_role(UserRole.BOB)
    
    if not alice or not bob:
        raise HTTPException(status_code=400, detail="Both Alice and Bob must be present")
    
    # Start BB84 simulation in background
    asyncio.create_task(run_bb84_simulation(session_id, n_bits, test_fraction))
    
    return {
        "session_id": session_id,
        "message": "BB84 simulation started",
        "n_bits": n_bits,
        "test_fraction": test_fraction
    }

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
        
        logger.info(f"Session {session_id} terminated")
        return {"message": "Session terminated successfully"}
    except Exception as e:
        logger.error(f"Error terminating session: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to terminate session")

# Socket.IO Event Handlers

@sio.event
async def connect(sid, environ):
    """Handle client connection"""
    logger.info(f"Client connected: {sid}")
    await sio.emit("connected", {"message": "Connected to QKD server"}, room=sid)

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
        await sio.enter_room(sid, room_name)
        
        # Notify other participants
        await sio.emit("user_joined", 
                      {"user_id": user_id, "role": user.role.value},
                      room=room_name, skip_sid=sid)
        
        await sio.emit("joined_session", {
            "session_id": session_id,
            "user_id": user_id,
            "role": user.role.value
        }, room=sid)
        
        logger.info(f"User {user_id} joined Socket.IO room {room_name}")
        
    except Exception as e:
        logger.error(f"Error joining session socket: {str(e)}")
        await sio.emit("error", {"message": "Failed to join session"}, room=sid)

@sio.event
async def send_encrypted_message(sid, data):
    """Handle encrypted message transmission"""
    try:
        session_id = data.get("session_id")
        encrypted_message = data.get("encrypted_message")
        sender_id = data.get("sender_id")
        
        if not all([session_id, encrypted_message, sender_id]):
            await sio.emit("error", {"message": "Missing required fields"}, room=sid)
            return
        
        # Validate session
        session = session_manager.get_session(session_id)
        if not session or not session.session_key:
            await sio.emit("error", {"message": "No session key available"}, room=sid)
            return
        
        # Relay encrypted message to other participants
        await sio.emit("encrypted_message_received", {
            "sender_id": sender_id,
            "encrypted_message": encrypted_message,
            "timestamp": datetime.now().isoformat()
        }, room=f"session_{session_id}", skip_sid=sid)
        
    except Exception as e:
        logger.error(f"Error sending encrypted message: {str(e)}")
        await sio.emit("error", {"message": "Failed to send message"}, room=sid)

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
        
    except Exception as e:
        logger.error(f"Error handling Eve control: {str(e)}")
        await sio.emit("error", {"message": "Failed to update Eve parameters"}, room=sid)

# Background task for BB84 simulation
async def run_bb84_simulation(session_id: str, n_bits: int, test_fraction: float):
    """Run BB84 simulation with real-time updates"""
    try:
        session = session_manager.get_session(session_id)
        if not session:
            return
        
        room_name = f"session_{session_id}"
        
        # Emit simulation start
        await sio.emit("bb84_started", {
            "n_bits": n_bits,
            "test_fraction": test_fraction
        }, room=room_name)
        
        # Run BB84 simulation with Eve if present
        eve_present = session.get_user_by_role(UserRole.EVE) is not None
        eve_params = session.eve_params if eve_present else None
        
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
        session_key = bb84_engine.get_final_key()
        session.session_key = session_key
        session.key_length = len(session_key)
        
        await sio.emit("bb84_complete", {
            "success": True,
            "key_length": len(session_key),
            "message": "Session key established"
        }, room=room_name)
        
        logger.info(f"BB84 simulation completed for session {session_id}")
        
    except Exception as e:
        logger.error(f"Error in BB84 simulation: {str(e)}")
        await sio.emit("bb84_error", {
            "error": str(e)
        }, room=f"session_{session_id}")

if __name__ == "__main__":
    uvicorn.run("app.main:socket_app", host="0.0.0.0", port=8000, reload=True)