/**
 * REST API service for BB84 QKD simulation
 */

import axios, { type AxiosInstance, type AxiosResponse } from 'axios';
import type { Session } from '../types';

class ApiService {
    private api: AxiosInstance;
    private baseURL = 'http://localhost:8000';

    constructor() {
        this.api = axios.create({
            baseURL: this.baseURL,
            timeout: 10000,
            headers: {
                'Content-Type': 'application/json',
            },
        });

        // Request interceptor
        this.api.interceptors.request.use(
            (config) => {
                console.log(`API Request: ${config.method?.toUpperCase()} ${config.url}`);
                return config;
            },
            (error) => {
                return Promise.reject(error);
            }
        );

        // Response interceptor
        this.api.interceptors.response.use(
            (response) => {
                console.log(`API Response: ${response.status} ${response.config.url}`);
                return response;
            },
            (error) => {
                console.error(`API Error: ${error.response?.status} ${error.config?.url}`, error.response?.data);
                return Promise.reject(error);
            }
        );
    }

    // Health check
    async healthCheck(): Promise<any> {
        const response = await this.api.get('/');
        return response.data;
    }

    // Session management
    async createSession(): Promise<{ session_id: string; created_at: string; status: string }> {
        const response = await this.api.post('/session/create');
        return response.data;
    }

    async joinSession(sessionId: string, userRole: 'alice' | 'bob' | 'eve'): Promise<{
        user_id: string;
        session_id: string;
        role: string;
        status: string;
    }> {
        const response = await this.api.post(`/session/${sessionId}/join`, null, {
            params: { user_role: userRole },
        });
        return response.data;
    }

    async getSessionStatus(sessionId: string): Promise<{
        session_id: string;
        status: string;
        participants: Array<{
            user_id: string;
            role: string;
            connected: boolean;
        }>;
        created_at: string;
    }> {
        const response = await this.api.get(`/session/${sessionId}/status`);
        return response.data;
    }

    async startBB84Simulation(
        sessionId: string,
        nBits: number = 1000,
        testFraction: number = 0.1
    ): Promise<{
        session_id: string;
        message: string;
        n_bits: number;
        test_fraction: number;
    }> {
        const response = await this.api.post(`/session/${sessionId}/start_bb84`, null, {
            params: {
                n_bits: nBits,
                test_fraction: testFraction,
            },
        });
        return response.data;
    }

    async terminateSession(sessionId: string): Promise<{ message: string }> {
        const response = await this.api.post(`/session/${sessionId}/terminate`);
        return response.data;
    }

    // Error handling helper
    handleApiError(error: any): string {
        if (error.response) {
            // Server responded with error status
            return error.response.data?.detail || error.response.data?.message || 'Server error occurred';
        } else if (error.request) {
            // Request made but no response received
            return 'No response from server. Please check your connection.';
        } else {
            // Something else happened
            return error.message || 'An unexpected error occurred';
        }
    }

    // Utility methods
    async checkServerHealth(): Promise<boolean> {
        try {
            await this.healthCheck();
            return true;
        } catch (error) {
            console.error('Server health check failed:', error);
            return false;
        }
    }

    getBaseURL(): string {
        return this.baseURL;
    }

    // Set custom timeout for specific requests
    setRequestTimeout(timeout: number): void {
        this.api.defaults.timeout = timeout;
    }

    // Add authentication header if needed in future
    setAuthToken(token: string): void {
        this.api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
    }

    removeAuthToken(): void {
        delete this.api.defaults.headers.common['Authorization'];
    }
}

export default new ApiService();