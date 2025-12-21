import React from 'react';
import { useAuth } from './useCases/useAuth';
import { useAppData } from './useCases/useAppData';
import { Dashboard } from './ui/pages/Dashboard';
import { LoginPage } from './ui/pages/LoginPage';
import { AccessDenied } from './ui/pages/AccessDenied';

const App: React.FC = () => {
  const { isAuthenticated, isLoading, login, logout, getToken, getUsername } = useAuth();
  const { user, appInfo, loading: dataLoading, accessDenied } = useAppData(getToken());

  if (isLoading || dataLoading) {
    return (
      <div style={styles.loading}>
        <div style={styles.spinner}></div>
        <p>Loading...</p>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginPage onLogin={login} />;
  }

  if (accessDenied) {
    return <AccessDenied username={getUsername()} onLogout={logout} />;
  }

  if (!user || !appInfo) {
    return (
      <div style={styles.loading}>
        <p>Failed to load application data</p>
        <button onClick={logout}>Logout</button>
      </div>
    );
  }

  return <Dashboard user={user} appInfo={appInfo} onLogout={logout} />;
};

const styles = {
  loading: {
    display: 'flex',
    flexDirection: 'column' as const,
    justifyContent: 'center',
    alignItems: 'center',
    minHeight: '100vh',
    backgroundColor: '#ecf0f1',
  },
  spinner: {
    border: '4px solid #f3f3f3',
    borderTop: '4px solid #3498db',
    borderRadius: '50%',
    width: '40px',
    height: '40px',
    animation: 'spin 1s linear infinite',
  },
};

export default App;
