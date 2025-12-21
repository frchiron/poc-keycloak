import { User } from '../domain/User';
import { AppInfo } from '../domain/AppInfo';

export interface IApiPort {
  getUserInfo(token: string): Promise<User>;
  getAppInfo(token: string): Promise<AppInfo>;
  getProtectedData(token: string): Promise<any>;
}

class ApiAdapter implements IApiPort {
  private baseUrl: string;

  constructor() {
    this.baseUrl = process.env.REACT_APP_BACKEND_URL!;
  }

  private async fetchWithAuth(endpoint: string, token: string): Promise<any> {
    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(`API request failed: ${response.statusText}`);
    }

    return response.json();
  }

  async getUserInfo(token: string): Promise<User> {
    return this.fetchWithAuth('/api/user', token);
  }

  async getAppInfo(token: string): Promise<AppInfo> {
    return this.fetchWithAuth('/api/app-info', token);
  }

  async getProtectedData(token: string): Promise<any> {
    return this.fetchWithAuth('/api/protected', token);
  }
}

export const apiAdapter = new ApiAdapter();
