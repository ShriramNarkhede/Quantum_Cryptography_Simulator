/**
 * Enhanced REST API service for BB84 QKD simulation with cryptographic features
 */

import axios,{ type AxiosInstance,type AxiosResponse, type AxiosError } from 'axios';
import type{ 
  CreateSessionResponse,
  JoinSessionResponse,
  SessionStatusResponse,
  StartBB84Response,
  FileUploadResponse,
  FileDownloadResponse,
  CryptoInfo,
  ApiResponse
} from '../types';

class ApiService {
  private api: AxiosInstance;
  private baseURL = 'http://localhost:8000';
  private requestCount = 0;
  private lastRequestTime = 0;

  constructor() {
    this.api = axios.create({
      baseURL: this.baseURL,
      timeout: 30000, // Increased timeout for crypto operations
      headers: {
        'Content-Type': 'application/json',
      },
    });

    this.setupInterceptors();
  }

  private setupInterceptors(): void {
    // Request interceptor
    this.api.interceptors.request.use(
      (config) => {
        this.requestCount++;
        this.lastRequestTime = Date.now();
        
        console.log(`[API] ${config.method?.toUpperCase()} ${config.url} (Request #${this.requestCount})`);
        
        // Add request timing
        config.metadata = { startTime: Date.now() };
        
        return config;
      },
      (err: unknown) => {
        console.error('[API] Request error:', err);
        return Promise.reject(err);
      }
    );

    // Response interceptor
    this.api.interceptors.response.use(
      (response) => {
        const duration = Date.now() - (response.config.metadata?.startTime || 0);
        console.log(`[API] ${response.status} ${response.config.url} (${duration}ms)`);
        
        return response;
      },
      (err: unknown) => {
        const isAxiosErr = axios.isAxiosError(err);
        const start = isAxiosErr ? err.config?.metadata?.startTime : 0;
        const duration = Date.now() - (start || 0);
        const status = isAxiosErr ? err.response?.status : 'ERR';
        const url = isAxiosErr ? err.config?.url : '';
        const data = isAxiosErr ? err.response?.data : err;
        console.error(`[API] ${status} ${url} (${duration}ms)`, data);
        return Promise.reject(err);
      }
    );
  }

  // Health and version check
  async healthCheck(): Promise<{
    message: string;
    status: string;
    timestamp: string;
    version: string;
    features: string[];
  }> {
    const response = await this.api.get('/');
    return response.data;
  }

  // Enhanced session management
  async createSession(): Promise<CreateSessionResponse> {
    const response = await this.api.post('/session/create');
    return response.data;
  }

  async joinSession(sessionId: string, userRole: 'alice' | 'bob' | 'eve'): Promise<JoinSessionResponse> {
    const response = await this.api.post(`/session/${sessionId}/join`, null, {
      params: { user_role: userRole },
    });
    return response.data;
  }

  async getSessionStatus(sessionId: string): Promise<SessionStatusResponse> {
    const response = await this.api.get(`/session/${sessionId}/status`);
    return response.data;
  }

  // Enhanced security information endpoint
  async getSessionSecurity(sessionId: string): Promise<CryptoInfo> {
    const response = await this.api.get(`/session/${sessionId}/security`);
    return response.data;
  }

  async getSessionKey(sessionId: string): Promise<{
    session_id: string;
    key: string;
    key_length: number;
    crypto_established: boolean;
  }> {
    const response = await this.api.get(`/session/${sessionId}/session_key`);
    return response.data;
  }

  // Enhanced BB84 simulation with hybrid mode support
  async startBB84Simulation(
    sessionId: string,
    nBits: number = 1000,
    testFraction: number = 0.1,
    useHybrid: boolean = false
  ): Promise<StartBB84Response> {
    const response = await this.api.post(`/session/${sessionId}/start_bb84`, null, {
      params: {
        n_bits: nBits,
        test_fraction: testFraction,
        use_hybrid: useHybrid,
      },
    });
    return response.data;
  }

  // Enhanced file operations with encryption
  async sendEncryptedFile(
    sessionId: string, 
    senderId: string, 
    file: File
  ): Promise<FileUploadResponse> {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await this.api.post(
      `/session/${sessionId}/send_file`,
      formData,
      {
        params: { sender_id: senderId },
        headers: {
          'Content-Type': 'multipart/form-data',
        },
        timeout: 60000, // Extended timeout for large files
      }
    );
    return response.data;
  }

  async downloadEncryptedFile(
    sessionId: string,
    messageId: string,
    userId: string
  ): Promise<FileDownloadResponse> {
    const response = await this.api.get(
      `/session/${sessionId}/download_file/${messageId}`,
      {
        params: { user_id: userId },
        timeout: 60000, // Extended timeout for large files
      }
    );
    return response.data;
  }

  async downloadRawEncryptedFile(
    sessionId: string,
    messageId: string,
    userId: string
  ): Promise<FileDownloadResponse & { encrypted: boolean; original_filename: string }> {
    const response = await this.api.get(
      `/session/${sessionId}/download_encrypted_file/${messageId}`,
      {
        params: { user_id: userId },
        timeout: 60000, // Extended timeout for large files
      }
    );
    return response.data;
  }

  // Session termination
  async terminateSession(sessionId: string): Promise<{ message: string }> {
    const response = await this.api.post(`/session/${sessionId}/terminate`);
    return response.data;
  }

  // Batch operations for efficiency
  async batchRequest<T = any>(requests: Array<{
    method: 'GET' | 'POST' | 'PUT' | 'DELETE';
    url: string;
    data?: any;
    params?: any;
  }>): Promise<T[]> {
    const promises = requests.map(req => 
      this.api.request({
        method: req.method,
        url: req.url,
        data: req.data,
        params: req.params,
      })
    );

    const responses = await Promise.allSettled(promises);
    return responses.map(result => 
      result.status === 'fulfilled' ? result.value.data : null
    );
  }

  // Session analytics and monitoring
  async getSessionAnalytics(sessionId: string): Promise<{
    session_summary: any;
    security_report: any;
    performance_metrics: any;
    crypto_stats: any;
  }> {
    const response = await this.api.get(`/session/${sessionId}/analytics`);
    return response.data;
  }

  async getSystemHealth(): Promise<{
    server_status: string;
    active_sessions: number;
    total_users: number;
    crypto_operations: number;
    system_load: number;
    uptime: number;
  }> {
    const response = await this.api.get('/system/health');
    return response.data;
  }

  async getSecurityReport(): Promise<{
    total_sessions: number;
    compromised_sessions: number;
    eve_detections: number;
    security_violations: number;
    average_qber: number;
    recommendations: string[];
  }> {
    const response = await this.api.get('/system/security-report');
    return response.data;
  }

  // Error handling and utilities
  handleApiError(error: unknown): string {
    if (axios.isAxiosError(error) && error.response) {
      // Server responded with error status
      const data = error.response.data;
      return data?.detail || data?.message || data?.error || 'Server error occurred';
    } else if (axios.isAxiosError(error) && error.request) {
      // Request made but no response received
      return 'No response from server. Please check your connection.';
    } else if (axios.isAxiosError(error) && error.code === 'ECONNABORTED') {
      // Request timeout
      return 'Request timeout. The operation took too long to complete.';
    } else {
      // Something else happened
      return (error as Error)?.message || 'An unexpected error occurred';
    }
  }

  getErrorSeverity(error: any): 'low' | 'medium' | 'high' | 'critical' {
    if (!error.response) return 'high'; // Network errors are high severity
    
    const status = error.response.status;
    if (status >= 500) return 'critical';
    if (status >= 400 && status < 500) return 'medium';
    return 'low';
  }

  // Server connectivity and health
  async checkServerHealth(): Promise<boolean> {
    try {
      const health = await this.healthCheck();
      return health.status === 'running';
    } catch (err: unknown) {
      console.error('Server health check failed:', err);
      return false;
    }
  }

  async waitForServerReady(maxAttempts: number = 10, delay: number = 1000): Promise<boolean> {
    for (let i = 0; i < maxAttempts; i++) {
      try {
        if (await this.checkServerHealth()) {
          return true;
        }
      } catch (error) {
        console.log(`Server check attempt ${i + 1}/${maxAttempts} failed`);
      }
      
      if (i < maxAttempts - 1) {
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    return false;
  }

  // Configuration and utilities
  getBaseURL(): string {
    return this.baseURL;
  }

  setBaseURL(url: string): void {
    this.baseURL = url;
    this.api.defaults.baseURL = url;
  }

  setRequestTimeout(timeout: number): void {
    this.api.defaults.timeout = timeout;
  }

  setAuthToken(token: string): void {
    this.api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }

  removeAuthToken(): void {
    delete this.api.defaults.headers.common['Authorization'];
  }

  // Request statistics
  getRequestStats(): {
    totalRequests: number;
    lastRequestTime: number;
    averageResponseTime: number;
  } {
    return {
      totalRequests: this.requestCount,
      lastRequestTime: this.lastRequestTime,
      averageResponseTime: 0, // Would need to track this
    };
  }

  // Crypto-specific API endpoints
  async getCryptoCapabilities(): Promise<{
    supported_algorithms: string[];
    key_derivation_methods: string[];
    hybrid_mode_available: boolean;
    pqc_algorithms: string[];
  }> {
    const response = await this.api.get('/crypto/capabilities');
    return response.data;
  }

  async validateCryptoConfig(config: {
    qber_threshold: number;
    test_fraction: number;
    key_length: number;
  }): Promise<{
    valid: boolean;
    warnings: string[];
    recommendations: string[];
  }> {
    const response = await this.api.post('/crypto/validate-config', config);
    return response.data;
  }

  // Session export and import (for analysis)
  async exportSessionData(sessionId: string, includeSensitive: boolean = false): Promise<{
    session_data: any;
    export_timestamp: string;
    format_version: string;
  }> {
    const response = await this.api.get(`/session/${sessionId}/export`, {
      params: { include_sensitive: includeSensitive }
    });
    return response.data;
  }

  async getSessionHistory(userId?: string, limit: number = 50): Promise<{
    sessions: Array<{
      session_id: string;
      created_at: string;
      duration: number;
      status: string;
      participants: number;
      crypto_established: boolean;
      eve_detected: boolean;
    }>;
    total_count: number;
  }> {
    const response = await this.api.get('/sessions/history', {
      params: { user_id: userId, limit }
    });
    return response.data;
  }

  // Advanced features
  async performCryptoBenchmark(sessionId: string): Promise<{
    key_derivation_time: number;
    message_encryption_rate: number;
    file_encryption_rate: number;
    bb84_simulation_time: number;
    overall_performance: 'excellent' | 'good' | 'fair' | 'poor';
  }> {
    const response = await this.api.post(`/session/${sessionId}/crypto-benchmark`);
    return response.data;
  }

  async generateSecurityAudit(sessionId: string): Promise<{
    audit_id: string;
    session_id: string;
    audit_timestamp: string;
    security_score: number;
    findings: Array<{
      severity: 'low' | 'medium' | 'high' | 'critical';
      finding: string;
      recommendation: string;
    }>;
    compliance_status: 'compliant' | 'non-compliant' | 'warning';
  }> {
    const response = await this.api.post(`/session/${sessionId}/security-audit`);
    return response.data;
  }

  // Development and debugging utilities
  async enableDebugMode(sessionId: string): Promise<{ message: string }> {
    const response = await this.api.post(`/session/${sessionId}/debug/enable`);
    return response.data;
  }

  async getDebugLogs(sessionId: string, level: 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' = 'INFO'): Promise<{
    logs: Array<{
      timestamp: string;
      level: string;
      message: string;
      module: string;
    }>;
    total_entries: number;
  }> {
    const response = await this.api.get(`/session/${sessionId}/debug/logs`, {
      params: { level }
    });
    return response.data;
  }

  // Cache management
  private cache = new Map<string, { data: any; timestamp: number; ttl: number }>();

  async getCached<T>(key: string, fetcher: () => Promise<T>, ttl: number = 60000): Promise<T> {
    const cached = this.cache.get(key);
    const now = Date.now();

    if (cached && (now - cached.timestamp) < cached.ttl) {
      return cached.data;
    }

    const data = await fetcher();
    this.cache.set(key, { data, timestamp: now, ttl });
    return data;
  }

  clearCache(): void {
    this.cache.clear();
  }

  // Request retry mechanism
  async retryRequest<T>(
    request: () => Promise<T>,
    maxRetries: number = 3,
    delay: number = 1000
  ): Promise<T> {
    let lastError: any;

    for (let i = 0; i <= maxRetries; i++) {
      try {
        return await request();
      } catch (err: unknown) {
        lastError = err;
        
        if (i === maxRetries) break;
        
        // Don't retry on client errors (4xx)
        if (axios.isAxiosError(err) && err.response?.status !== undefined && err.response.status >= 400 && err.response.status < 500) {
          break;
        }

        // Exponential backoff
        const waitTime = delay * Math.pow(2, i);
        await new Promise(resolve => setTimeout(resolve, waitTime));
      }
    }

    throw lastError;
  }

  // Connection pooling and optimization
  setMaxConcurrentRequests(max: number): void {
    // Note: axios doesn't have built-in connection pooling for browsers
    // This would need to be implemented with a request queue
    console.warn('Connection pooling not implemented for browser environment');
  }

  // Cleanup and resource management
  cleanup(): void {
    this.clearCache();
    // Cancel any pending requests
    this.api.defaults.timeout = 1; // Force quick timeout
  }

  // Static utility methods
  static formatFileSize(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  static formatDuration(seconds: number): string {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    if (hours > 0) {
      return `${hours}h ${minutes}m ${secs}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${secs}s`;
    } else {
      return `${secs}s`;
    }
  }

  static isValidSessionId(sessionId: string): boolean {
    return /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$|^[a-f0-9]{8}$/.test(sessionId);
  }
}

// Export singleton instance
export default new ApiService();