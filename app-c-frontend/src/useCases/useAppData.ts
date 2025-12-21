import { useState, useEffect } from 'react';
import { apiAdapter } from '../adapters/ApiAdapter';
import { User } from '../domain/User';
import { AppInfo } from '../domain/AppInfo';

export const useAppData = (token: string | undefined) => {
  const [user, setUser] = useState<User | null>(null);
  const [appInfo, setAppInfo] = useState<AppInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!token) {
      setLoading(false);
      return;
    }

    Promise.all([
      apiAdapter.getUserInfo(token),
      apiAdapter.getAppInfo(token),
    ])
      .then(([userData, appInfoData]) => {
        setUser(userData);
        setAppInfo(appInfoData);
        setError(null);
      })
      .catch((err) => {
        console.error('Failed to fetch app data:', err);
        setError(err.message);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [token]);

  return { user, appInfo, loading, error };
};
