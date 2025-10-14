/**
 * Socket.IO service for real-time communication with BB84 backend
 */

import { io, Socket } from 'socket.io-client';
import type { BB84Progress, EncryptedMessagePayload, EveParams } from '../types/index';

type IncomingEncryptedMessage = {
    message_id: string;
    sender_id: string;
    encrypted_payload: EncryptedMessagePayload;
    timestamp: string;
    seq_no: number;
    crypto_type: string;
};

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

    // Generic event subscription (passthrough)
    on<T = any>(event: string, callback: (data: T) => void): void {
        if (this.socket) {
            this.socket.on(event, callback as any);
        }
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

    onBB84Error(callback: (data: { error: string }) => void): void {
        if (this.socket) {
            this.socket.on('bb84_error', callback);
        }
    }

    onEveDetected(callback: (data: any) => void): void {
        if (this.socket) {
            this.socket.on('eve_detected', callback);
        }
    }

    // Message handling
    sendEncryptedMessage(sessionId: string, senderId: string, messageContent: string): void {
        if (this.socket) {
            this.socket.emit('send_encrypted_message', {
                session_id: sessionId,
                sender_id: senderId,
                message_content: messageContent,
            });
        }
    }

    onEncryptedMessageReceived(callback: (message: IncomingEncryptedMessage) => void): void {
        if (this.socket) {
            this.socket.on('encrypted_message_received', callback);
        }
    }

    onEncryptedFileReceived(callback: (data: { message_id: string; sender_id: string; filename: string; file_size: number; timestamp: string }) => void): void {
        if (this.socket) {
            this.socket.on('encrypted_file_received', callback);
        }
    }

    onMessageDecrypted(callback: (data: { message_id: string; decrypted_content: string; sender_id?: string }) => void): void {
        if (this.socket) {
            this.socket.on('message_decrypted', callback);
        }
    }

    requestMessageDecryption(sessionId: string, messageId: string, userId: string): void {
        if (this.socket) {
            this.socket.emit('decrypt_message', {
                session_id: sessionId,
                message_id: messageId,
                user_id: userId,
            });
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

    // Security events
    onSecurityViolation(callback: (violation: { timestamp: string; violation: string; severity?: string; session_id?: string }) => void): void {
        if (this.socket) {
            this.socket.on('security_violation', callback);
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

    // Cleanup helper: remove listeners and disconnect
    cleanup(): void {
        this.removeAllListeners();
        this.disconnect();
    }
}

export default new SocketService();