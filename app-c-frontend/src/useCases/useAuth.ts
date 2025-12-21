import { useState, useEffect } from 'react';
import { keycloakAdapter } from '../adapters/KeycloakAdapter';

export const useAuth = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    keycloakAdapter.init().then((authenticated) => {
      setIsAuthenticated(authenticated);
      setIsLoading(false);
    });
  }, []);

  const login = () => keycloakAdapter.login();
  const logout = () => keycloakAdapter.logout();
  const getToken = () => keycloakAdapter.getToken();
  const getUsername = () => keycloakAdapter.getUsername();

  return {
    isAuthenticated,
    isLoading,
    login,
    logout,
    getToken,
    getUsername,
  };
};
