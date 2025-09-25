export interface User {
  user_id: string;
  role: 'alice' | 'bob' | 'eve';
  connected: boolean;
  joined_at: string;
}

export interface Session {
  session_id: string;
  status: string;
  created_at: string;
  participants: User[];
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
}

export interface EncryptedMessage {
  message_id: string;
  sender_id: string;
  encrypted_content: string;
  timestamp: string;
}

export interface EveParams {
  attack_type: 'none' | 'intercept_resend' | 'partial_intercept' | 'depolarizing' | 'qubit_loss';
  params: {
    fraction?: number;
    noise_probability?: number;
    loss_probability?: number;
  };
}