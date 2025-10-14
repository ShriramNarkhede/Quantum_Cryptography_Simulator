// Augment Axios types to allow custom metadata on request configs
import 'axios';

declare module 'axios' {
  // Used by interceptors in Axios v1
  interface InternalAxiosRequestConfig<D = any> {
    metadata?: { startTime: number };
  }

  // Also add to public config interface for broader compatibility
  interface AxiosRequestConfig<D = any> {
    metadata?: { startTime: number };
  }
}


