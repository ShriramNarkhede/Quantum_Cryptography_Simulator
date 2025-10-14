/**
 * Frontend Cryptography Service for BB84 QKD System
 * Handles display and UI for enhanced cryptographic operations
 */

export interface EncryptedMessagePayload {
    ciphertext: string;
    hmac_tag: string;
    seq_no: number;
    timestamp: number;
    session_id: string;
    crypto_type: 'otp_hmac_sha3';
  }
  
  export interface EncryptedFilePayload {
    ciphertext: string;
    nonce: string;
    aad: string;
    filename: string;
    file_seq_no: number;
    session_id: string;
    file_size: number;
    crypto_type: 'xchacha20_poly1305';
  }
  
  export interface CryptoInfo {
    session_id: string;
    crypto_established: boolean;
    hybrid_mode: boolean;
    qber?: number;
    qber_threshold: number;
    eve_detected: boolean;
    message_count: number;
    crypto_stats: {
      message_count: number;
      file_count: number;
      key_stream_usage: number;
      total_key_stream_bytes: number;
    };
    final_key_length: number;
    session_age_seconds: number;
  }
  
  export interface SecureMessage {
    message_id: string;
    sender_id: string;
    message_type: 'system' | 'chat_otp' | 'file_xchacha20' | 'key_exchange';
    encrypted_payload: EncryptedMessagePayload | EncryptedFilePayload | any;
    timestamp: string;
    seq_no?: number;
    verified: boolean;
    decrypted_content?: string; // Client-side cache of decrypted content
  }
  
// Import shared UI types for QBER tracking and health assessment
import type { QBERDataPoint, SessionHealthAssessment, EncryptionStatus } from '../types';

  class CryptoService {
    /**
     * Encrypt a File or Blob using XChaCha20-Poly1305 (IETF) with optional progress callback.
     * The accessKey must be 32-byte Uint8Array (secret key). Nonce is 24 bytes, randomly generated.
     */
    async encryptFileXChaCha(
      file: File | Blob,
      accessKey: Uint8Array,
      aad: string = '' ,
      onProgress?: (progress: number) => void
    ): Promise<{ ciphertext: Uint8Array; nonce: Uint8Array; aad: Uint8Array }>{
      const sodium = await import('libsodium-wrappers');
      await sodium.ready;
      const s = sodium as any;

      if (accessKey.length !== s.crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw new Error('Invalid access key length: expected 32 bytes');
      }

      const nonce = s.randombytes_buf(s.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
      const reader = (file as Blob).stream().getReader();
      const chunkSize = 64 * 1024; // 64KB
      const chunks: Uint8Array[] = [];
      const total = (file as Blob).size;
      let processed = 0;
      let concatenated = new Uint8Array(0);

      // Read entire file progressively into buffer to AEAD seal at once (simpler, keeps UI progress)
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = value as Uint8Array;
        // append to concatenated
        const tmp = new Uint8Array(concatenated.length + chunk.length);
        tmp.set(concatenated, 0);
        tmp.set(chunk, concatenated.length);
        concatenated = tmp;
        processed += chunk.length;
        if (onProgress && total > 0) onProgress(Math.min(0.99, processed / total));
      }

      const aadBytes = s.from_string(aad);
      const ciphertext = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
        concatenated,
        aadBytes,
        null,
        nonce,
        accessKey
      );
      if (onProgress) onProgress(1);
      return { ciphertext, nonce, aad: aadBytes };
    }

    /**
     * Decrypt XChaCha20-Poly1305 payload back to a Blob. Validates accessKey and AAD.
     */
    async decryptFileXChaCha(
      ciphertext: Uint8Array,
      nonce: Uint8Array,
      accessKey: Uint8Array,
      aad: Uint8Array,
    ): Promise<Uint8Array> {
      const sodium = await import('libsodium-wrappers');
      await sodium.ready;
      const s = sodium as any;

      if (accessKey.length !== s.crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        throw new Error('Invalid access key length: expected 32 bytes');
      }

      const plaintext = s.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        ciphertext,
        aad,
        nonce,
        accessKey
      );
      return plaintext;
    }
    private sessionKey: Uint8Array | null = null;
    private cryptoInfo: CryptoInfo | null = null;
    private qberHistory: QBERDataPoint[] = [];
    private decryptedCache = new Map<string, string>();
  
    /**
     * Set session key for display purposes only
     * Actual cryptography happens on the server
     */
    setSessionKey(key: Uint8Array): void {
      this.sessionKey = key;
    }
  
    /**
     * Get session key for display
     */
    getSessionKey(): Uint8Array | null {
      return this.sessionKey;
    }
  
    /**
     * QBER history management for charts/analytics
     */
    addQBERDataPoint(point: QBERDataPoint): void {
      this.qberHistory.push(point);
      if (this.qberHistory.length > 500) {
        this.qberHistory = this.qberHistory.slice(-500);
      }
    }

    getQBERHistory(): QBERDataPoint[] {
      return this.qberHistory;
    }

    /**
     * Lightweight cache for decrypted message contents
     */
    cacheDecryptedContent(messageId: string, content: string): void {
      this.decryptedCache.set(messageId, content);
    }

    getCachedDecryptedContent(messageId: string): string | undefined {
      return this.decryptedCache.get(messageId);
    }

    /**
     * Update crypto information from server
     */
    updateCryptoInfo(info: CryptoInfo): void {
      this.cryptoInfo = info;
    }
  
    /**
     * Get current crypto information
     */
    getCryptoInfo(): CryptoInfo | null {
      return this.cryptoInfo;
    }
  
    /**
     * Check if session has secure keys established
     */
    hasSecureKeys(): boolean {
      return this.cryptoInfo?.crypto_established ?? false;
    }
  
    /**
     * Check if session is using hybrid mode
     */
    isHybridMode(): boolean {
      return this.cryptoInfo?.hybrid_mode ?? false;
    }
  
    /**
     * Get encryption status for UI display
     */
    getEncryptionStatus(): EncryptionStatus {
      if (!this.hasSecureKeys()) {
        return {
          status: 'none',
          description: 'No encryption keys',
          color: 'text-red-600',
          icon: '🔓',
          details: [
            'Establish a session key via BB84 before sending messages',
            'Messages will not be encrypted without a key'
          ]
        };
      }
  
      if (this.isHybridMode()) {
        return {
          status: 'hybrid',
          description: 'BB84 + Post-Quantum Hybrid',
          color: 'text-purple-600',
          icon: '🔐',
          details: [
            'Quantum key with PQC reinforcement',
            'Resilient against quantum adversaries'
          ]
        };
      }
  
      return {
        status: 'bb84',
        description: 'BB84 Quantum Key Distribution',
        color: 'text-green-600',
        icon: '🔒',
        details: [
          'Key derived from BB84 protocol',
          'Information-theoretic security when channel uncompromised'
        ]
      };
    }
  
    /**
     * Format message payload for display
     */
    formatMessageForDisplay(message: SecureMessage): {
      type: string;
      content: string;
      cryptoDetails: string;
      isEncrypted: boolean;
    } {
      const payload = message.encrypted_payload;
  
      if (message.message_type === 'system') {
        return {
          type: 'System',
          content: payload.content || '[System message]',
          cryptoDetails: 'Unencrypted',
          isEncrypted: false
        };
      }
  
      if (message.message_type === 'chat_otp' && payload.crypto_type === 'otp_hmac_sha3') {
        return {
          type: 'Message',
          content: message.decrypted_content || '[Encrypted message - click to decrypt]',
          cryptoDetails: `OTP + HMAC-SHA3-256 (Seq: ${payload.seq_no})`,
          isEncrypted: true
        };
      }
  
      if (message.message_type === 'file_xchacha20' && payload.crypto_type === 'xchacha20_poly1305') {
        const filePayload = payload as EncryptedFilePayload;
        return {
          type: 'File',
          content: `📎 ${filePayload.filename} (${this.formatFileSize(filePayload.file_size)})`,
          cryptoDetails: `XChaCha20-Poly1305 (Seq: ${filePayload.file_seq_no})`,
          isEncrypted: true
        };
      }
  
      return {
        type: 'Unknown',
        content: '[Unknown message type]',
        cryptoDetails: 'Unknown encryption',
        isEncrypted: false
      };
    }
  
    /**
     * Format file size for display
     */
    private formatFileSize(bytes: number): string {
      if (bytes === 0) return '0 Bytes';
      const k = 1024;
      const sizes = ['Bytes', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
  
    /**
     * Get crypto statistics for display
     */
    getCryptoStats(): {
      messagesEncrypted: number;
      filesEncrypted: number;
      keyStreamUsed: string;
      sessionAge: string;
      securityLevel: string;
    } {
      if (!this.cryptoInfo) {
        return {
          messagesEncrypted: 0,
          filesEncrypted: 0,
          keyStreamUsed: '0 bytes',
          sessionAge: '0s',
          securityLevel: 'None'
        };
      }
  
      const stats = this.cryptoInfo.crypto_stats;
      const ageMinutes = Math.floor(this.cryptoInfo.session_age_seconds / 60);
      const ageSeconds = Math.floor(this.cryptoInfo.session_age_seconds % 60);
  
      return {
        messagesEncrypted: stats.message_count,
        filesEncrypted: stats.file_count,
        keyStreamUsed: this.formatFileSize(stats.total_key_stream_bytes),
        sessionAge: ageMinutes > 0 ? `${ageMinutes}m ${ageSeconds}s` : `${ageSeconds}s`,
        securityLevel: this.isHybridMode() ? 'Quantum + Post-Quantum' : 'Quantum Only'
      };
    }
  
    /**
     * Validate message integrity indicators
     */
    validateMessageIntegrity(message: SecureMessage): {
      valid: boolean;
      issues: string[];
    } {
      const issues: string[] = [];
  
      if (!message.verified) {
        issues.push('Message failed cryptographic verification');
      }
  
      if (message.message_type === 'chat_otp' && message.encrypted_payload.crypto_type === 'otp_hmac_sha3') {
        const payload = message.encrypted_payload as EncryptedMessagePayload;
        
        if (!payload.hmac_tag) {
          issues.push('Missing HMAC authentication tag');
        }
  
        if (payload.seq_no < 0) {
          issues.push('Invalid sequence number');
        }
  
        if (!payload.session_id) {
          issues.push('Missing session ID in payload');
        }
      }
  
      return {
        valid: issues.length === 0,
        issues
      };
    }
  
    /**
     * Clear all crypto data
     */
    clear(): void {
      if (this.sessionKey) {
        // Overwrite with random data before clearing
        crypto.getRandomValues(this.sessionKey);
        this.sessionKey = null;
      }
      this.cryptoInfo = null;
    }
  
    /**
     * Generate display-friendly crypto summary
     */
    getCryptoSummary(): string {
      if (!this.hasSecureKeys()) {
        return 'No secure keys established';
      }
  
      const stats = this.getCryptoStats();
      const encryptionStatus = this.getEncryptionStatus();
  
      return `${encryptionStatus.icon} ${encryptionStatus.description} | ` +
             `${stats.messagesEncrypted} messages, ${stats.filesEncrypted} files | ` +
             `${stats.keyStreamUsed} used | Age: ${stats.sessionAge}`;
    }
  
    /**
     * Get security recommendations based on current state
     */
    getSecurityRecommendations(): string[] {
      const recommendations: string[] = [];
  
      if (!this.hasSecureKeys()) {
        recommendations.push('Generate quantum keys using BB84 protocol');
        return recommendations;
      }
  
      if (!this.cryptoInfo) {
        return recommendations;
      }
  
      // Check QBER
      if (this.cryptoInfo.qber && this.cryptoInfo.qber > this.cryptoInfo.qber_threshold * 0.8) {
        recommendations.push('QBER is approaching threshold - monitor for eavesdropping');
      }
  
      if (this.cryptoInfo.eve_detected) {
        recommendations.push('Eavesdropping detected - terminate session and start fresh');
      }
  
      // Check session age
      if (this.cryptoInfo.session_age_seconds > 3600) { // 1 hour
        recommendations.push('Session is old - consider starting a new session');
      }
  
      // Check key usage
      const stats = this.cryptoInfo.crypto_stats;
      if (stats.total_key_stream_bytes > 1024 * 1024) { // 1MB
        recommendations.push('High key stream usage - monitor for key exhaustion');
      }
  
      if (!this.isHybridMode()) {
        recommendations.push('Consider enabling hybrid mode for post-quantum security');
      }
  
      if (recommendations.length === 0) {
        recommendations.push('Session security looks good');
      }
  
      return recommendations;
    }

    /**
     * Produce a simple session health assessment for dashboard
     */
    getSessionHealthAssessment(): SessionHealthAssessment {
      const issues: string[] = [];
      let score = 100;

      if (!this.cryptoInfo || !this.cryptoInfo.crypto_established) {
        issues.push('No secure session established');
        score -= 40;
      } else {
        if (this.cryptoInfo.qber !== undefined) {
          const ratio = this.cryptoInfo.qber / this.cryptoInfo.qber_threshold;
          if (ratio > 1) {
            issues.push('QBER exceeds threshold');
            score -= 40;
          } else if (ratio > 0.8) {
            issues.push('QBER approaching threshold');
            score -= 20;
          }
        }

        if (this.cryptoInfo.eve_detected) {
          issues.push('Eavesdropping detected');
          score -= 40;
        }

        if (this.cryptoInfo.session_age_seconds > 3600) {
          issues.push('Session age high');
          score -= 10;
        }
      }

      score = Math.max(0, Math.min(100, score));

      const risk_level: SessionHealthAssessment['risk_level'] =
        score < 50 ? 'HIGH' : score < 70 ? 'MEDIUM' : score < 90 ? 'LOW' : 'MINIMAL';

      const recommendations = this.getSecurityRecommendations();

      return { score, issues, risk_level, recommendations };
    }
  }
  
  export default new CryptoService();