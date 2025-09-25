/**
 * Socket.IO service for real-time communication with BB84 backend
 */

import { io, Socket } from 'socket.io-client';
import type { BB84Progress, EncryptedMessage, EveParams } from '../types/index';

class SocketService {
    private socket: Socket | null = null;
    private serverUrl: string = 'http://localhost:8000';

    connect(): Socket {
        if (!this.socket) {
            this.socket = io(this.serverUrl, {
                transports: ['websocket', 'polling'],
                timeout: 20000,
            });

            this.setupEventListeners();
        }

        return this.socket;
    }

    disconnect(): void {
        if (this.socket) {
            this.socket.disconnect();
            this.socket = null;
        }
    }

    private setupEventListeners(): void {
        if (!this.socket) return;

        this.socket.on('connect', () => {
            console.log('Connected to QKD server');
        });

        this.socket.on('disconnect', () => {
            console.log('Disconnected from QKD server');
        });

        this.socket.on('error', (error) => {
            console.error('Socket error:', error);
        });
    }

    // Session management
    joinSession(sessionId: string, userId: string): void {
        if (this.socket) {
            this.socket.emit('join_session_socket', {
                session_id: sessionId,
                user_id: userId,
            });
        }
    }

    // BB84 Progress listeners
    onBB84Progress(callback: (progress: BB84Progress) => void): void {
        if (this.socket) {
            this.socket.on('bb84_progress', callback);
        }
    }

    onBB84Complete(callback: (result: any) => void): void {
        if (this.socket) {
            this.socket.on('bb84_complete', callback);
        }
    }

    onBB84Started(callback: (data: any) => void): void {
        if (this.socket) {
            this.socket.on('bb84_started', callback);
        }
    }

    onEveDetected(callback: (data: any) => void): void {
        if (this.socket) {
            this.socket.on('eve_detected', callback);
        }
    }

    // Message handling
    sendEncryptedMessage(sessionId: string, senderId: string, encryptedMessage: string): void {
        if (this.socket) {
            this.socket.emit('send_encrypted_message', {
                session_id: sessionId,
                sender_id: senderId,
                encrypted_message: encryptedMessage,
            });
        }
    }

    onEncryptedMessageReceived(callback: (message: EncryptedMessage) => void): void {
        if (this.socket) {
            this.socket.on('encrypted_message_received', callback);
        }
    }

    // Eve control
    updateEveParams(sessionId: string, eveParams: EveParams): void {
        if (this.socket) {
            this.socket.emit('eve_control', {
                session_id: sessionId,
                attack_type: eveParams.attack_type,
                attack_params: eveParams.params,
            });
        }
    }

    onEveStatusUpdate(callback: (data: any) => void): void {
        if (this.socket) {
            this.socket.on('eve_status_update', callback);
        }
    }

    // User events
    onUserJoined(callback: (user: any) => void): void {
        if (this.socket) {
            this.socket.on('user_joined', callback);
        }
    }

    onUserDisconnected(callback: (user: any) => void): void {
        if (this.socket) {
            this.socket.on('user_disconnected', callback);
        }
    }

    onJoinedSession(callback: (data: any) => void): void {
        if (this.socket) {
            this.socket.on('joined_session', callback);
        }
    }

    // Session events
    onSessionTerminated(callback: (data: any) => void): void {
        if (this.socket) {
            this.socket.on('session_terminated', callback);
        }
    }

    // Remove listeners
    removeAllListeners(): void {
        if (this.socket) {
            this.socket.removeAllListeners();
        }
    }

    removeListener(event: string): void {
        if (this.socket) {
            this.socket.off(event);
        }
    }

    // Get socket instance
    getSocket(): Socket | null {
        return this.socket;
    }

    // Check connection status
    isConnected(): boolean {
        return this.socket?.connected || false;
    }
}

export default new SocketService();