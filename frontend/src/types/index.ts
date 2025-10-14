/**
 * Enhanced TypeScript types for BB84 QKD System with cryptography
 */

export interface User {
  user_id: string;
  role: 'alice' | 'bob' | 'eve';
  connected: boolean;
  joined_at: string;
  last_activity: string;
}

export interface Session {
  session_id: string;
  status: 'created' | 'active' | 'bb84_running' | 'key_established' | 'compromised' | 'terminated';
  created_at: string;
  participants: User[];
  health_score?: number;
  is_compromised?: boolean;
  crypto_established?: boolean;
  hybrid_mode?: boolean;
}

export interface BB84Progress {
  stage: string;
  progress: number;
  message: string;
  qber?: number;
  threshold?: number;
  qber_exceeded?: boolean;
  success?: boolean;
  final_key_length?: number;
  sifted_length?: number;
  original_length?: number;
  hybrid_mode?: boolean;
  crypto_ready?: boolean;
}

export interface CryptoInfo {
  session_id: string;
  crypto_established: boolean;
  hybrid_mode: boolean;
  key_age_seconds: number;
  needs_key_rotation: boolean;
  qber?: number;
  qber_threshold: number;
  peak_qber: number;
  eve_detected: boolean;
  eve_detection_events: number;
  message_count: number;
  crypto_stats: CryptoStats;
  bb84_stats: BB84Stats;
  final_key_length: number;
  session_age_seconds: number;
  performance_metrics: PerformanceMetrics;
  security_violations: number;
  connection_drops: number;
  total_bytes_encrypted: number;
}

export interface CryptoStats {
  session_id: string;
  message_count: number;
  file_count: number;
  key_stream_usage: number;
  has_keys: boolean;
  total_key_stream_bytes: number;
}

export interface BB84Stats {
  total_qubits: number;
  sifted_bits: number;
  final_key_length: number;
  qber?: number;
  transmission_errors: number;
  sift_efficiency: number;
  eve_detected: boolean;
}

export interface PerformanceMetrics {
  total_session_time: number;
  bb84_duration: number;
  messages_per_minute: number;
  avg_message_size: number;
  peak_qber: number;
  security_incidents: number;
}

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

export interface SecureMessage {
  message_id: string;
  sender_id: string;
  message_type: 'system' | 'chat_otp' | 'file_xchacha20' | 'key_exchange';
  encrypted_payload: EncryptedMessagePayload | EncryptedFilePayload | SystemMessagePayload;
  timestamp: string;
  seq_no?: number;
  verified: boolean;
  size_bytes: number;
  decrypted_content?: string;
}

export interface SystemMessagePayload {
  content: string;
  crypto_type: 'none';
}

export interface EveParams {
  attack_type: 'none' | 'intercept_resend' | 'partial_intercept' | 'depolarizing' | 'qubit_loss';
  params: {
    fraction?: number;
    noise_probability?: number;
    loss_probability?: number;
    basis_strategy?: 'random' | 'alice' | 'fixed';
  };
}

export interface SessionHealthAssessment {
  score: number;
  issues: string[];
  risk_level: 'MINIMAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  recommendations: string[];
}

export interface EncryptionStatus {
  status: 'none' | 'bb84' | 'hybrid';
  description: string;
  color: string;
  icon: string;
  details: string[];
}

export interface FileTransferInfo {
  message_id: string;
  filename: string;
  file_size: number;
  sender_id: string;
  timestamp: string;
  encrypted: boolean;
  download_ready: boolean;
}

export interface SecurityViolation {
  timestamp: string;
  violation: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  session_id: string;
}

export interface QBERDataPoint {
  timestamp: number;
  qber: number;
  threshold: number;
  stage: string;
}

// Socket event types
export interface SocketEvents {
  // Connection events
  connect: () => void;
  disconnect: () => void;
  joined_session: (data: { session_id: string; user_id: string; role: string; crypto_ready: boolean }) => void;

  // BB84 events
  bb84_started: (data: { n_bits: number; test_fraction: number; hybrid_mode: boolean }) => void;
  bb84_progress: (progress: BB84Progress) => void;
  bb84_complete: (data: { success: boolean; key_length: number; hybrid_mode: boolean; crypto_ready: boolean; crypto_info: CryptoInfo }) => void;
  bb84_error: (data: { error: string }) => void;

  // Crypto events
  pqc_key_generated: (data: { key_length: number; algorithm: string }) => void;

  // Message events
  encrypted_message_received: (message: {
    message_id: string;
    sender_id: string;
    encrypted_payload: EncryptedMessagePayload;
    timestamp: string;
    seq_no: number;
    crypto_type: string;
  }) => void;

  message_decrypted: (data: {
    message_id: string;
    decrypted_content: string;
    sender_id: string;
  }) => void;

  // File events
  encrypted_file_received: (data: {
    message_id: string;
    sender_id: string;
    filename: string;
    file_size: number;
    timestamp: string;
  }) => void;

  // Eve events
  eve_status_update: (data: { attack_type: string; params: any }) => void;
  eve_detected: (data: { qber: number; threshold: number }) => void;

  // User events
  user_joined: (user: { user_id: string; role: string }) => void;
  user_disconnected: (user: { user_id: string; role: string }) => void;

  // Session events
  session_terminated: (data: { session_id: string }) => void;

  // Error events
  error: (data: { message: string }) => void;
}

// API response types
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

export interface CreateSessionResponse {
  session_id: string;
  created_at: string;
  status: string;
  crypto_enabled: boolean;
}

export interface JoinSessionResponse {
  user_id: string;
  session_id: string;
  role: string;
  status: string;
  crypto_ready: boolean;
}

export interface SessionStatusResponse {
  session_id: string;
  status: string;
  participants: Array<{
    user_id: string;
    role: string;
    connected: boolean;
  }>;
  created_at: string;
  security_issues: string[];
  crypto_info: CryptoInfo;
}

export interface StartBB84Response {
  session_id: string;
  message: string;
  n_bits: number;
  test_fraction: number;
  hybrid_mode: boolean;
}

export interface FileUploadResponse {
  message_id: string;
  status: string;
  filename: string;
  file_size: number;
}

export interface FileDownloadResponse {
  filename: string;
  file_data: string; // base64 encoded
  file_size: number;
  message_id: string;
}

// UI State types
export interface AppState {
  currentUser: User | null;
  currentSession: Session | null;
  sessionKey: Uint8Array | null;
  bb84Progress: BB84Progress | null;
  cryptoInfo: CryptoInfo | null;
  isConnected: boolean;
  serverOnline: boolean;
  messages: SecureMessage[];
  eveDetected: boolean;
  qberHistory: QBERDataPoint[];
  securityViolations: SecurityViolation[];
  fileTransfers: FileTransferInfo[];
}

// Component props types
export interface ComponentProps {
  className?: string;
  children?: React.ReactNode;
}

// Theme and styling
export interface ThemeColors {
  alice: string;
  bob: string;
  eve: string;
  quantum: {
    50: string;
    500: string;
    600: string;
    700: string;
  };
  success: string;
  warning: string;
  error: string;
}

// Utility types
export type UserRole = User['role'];
export type SessionStatus = Session['status'];
export type MessageType = SecureMessage['message_type'];
export type AttackType = EveParams['attack_type'];
export type RiskLevel = SessionHealthAssessment['risk_level'];

// Form types
export interface SessionCreateForm {
  role: UserRole;
}

export interface SessionJoinForm {
  sessionId: string;
  role: UserRole;
}

export interface MessageForm {
  content: string;
}

export interface EveControlForm {
  attackType: AttackType;
  fraction: number;
  noiseProbability: number;
  lossProbability: number;
  basisStrategy: 'random' | 'alice' | 'fixed';
}

// Configuration types
export interface AppConfig {
  backend: {
    url: string;
    timeout: number;
  };
  socket: {
    url: string;
    transports: string[];
    timeout: number;
  };
  crypto: {
    defaultTestFraction: number;
    qberThreshold: number;
    enableHybridMode: boolean;
  };
  ui: {
    maxMessages: number;
    autoScrollThreshold: number;
    animationDuration: number;
  };
}

export default interface BB84Types {
  // Export all types as a namespace
  User: any,
  Session: any,
  BB84Progress: any,
  CryptoInfo: any,
  SecureMessage: any,
  EveParams: any,
  EncryptionStatus: any,
  AppState: any
}