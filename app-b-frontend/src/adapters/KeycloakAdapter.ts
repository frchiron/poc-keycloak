import Keycloak from 'keycloak-js';

export interface IKeycloakPort {
  init(): Promise<boolean>;
  login(): void;
  logout(): void;
  getToken(): string | undefined;
  isAuthenticated(): boolean;
  getUsername(): string | undefined;
}

class KeycloakAdapter implements IKeycloakPort {
  private keycloak: Keycloak;

  constructor() {
    this.keycloak = new Keycloak({
      url: process.env.REACT_APP_KEYCLOAK_URL,
      realm: process.env.REACT_APP_KEYCLOAK_REALM!,
      clientId: process.env.REACT_APP_KEYCLOAK_CLIENT_ID!,
    });
  }

  async init(): Promise<boolean> {
    try {
      const authenticated = await this.keycloak.init({
        onLoad: 'check-sso',
        silentCheckSsoRedirectUri: window.location.origin + '/silent-check-sso.html',
        pkceMethod: 'S256',
      });

      if (authenticated) {
        this.setupTokenRefresh();
      }

      return authenticated;
    } catch (error) {
      console.error('Keycloak initialization failed:', error);
      return false;
    }
  }

  private setupTokenRefresh(): void {
    setInterval(() => {
      this.keycloak.updateToken(70).catch(() => {
        console.error('Failed to refresh token');
      });
    }, 60000);
  }

  login(): void {
    this.keycloak.login();
  }

  logout(): void {
    this.keycloak.logout();
  }

  getToken(): string | undefined {
    return this.keycloak.token;
  }

  isAuthenticated(): boolean {
    return !!this.keycloak.authenticated;
  }

  getUsername(): string | undefined {
    return this.keycloak.tokenParsed?.preferred_username;
  }
}

export const keycloakAdapter = new KeycloakAdapter();
