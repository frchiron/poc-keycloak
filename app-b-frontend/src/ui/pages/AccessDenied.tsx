import React from 'react';

interface AccessDeniedProps {
  username?: string;
  onLogout: () => void;
}

export const AccessDenied: React.FC<AccessDeniedProps> = ({ username, onLogout }) => {
  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <div style={styles.iconContainer}>
          <span style={styles.icon}>🚫</span>
        </div>
        <h1 style={styles.title}>Access Denied</h1>
        <p style={styles.message}>
          Sorry <strong>{username}</strong>, you don't have permission to access Application B.
        </p>
        <p style={styles.submessage}>
          Please contact your administrator to request access.
        </p>
        <div style={styles.actions}>
          <button style={styles.logoutButton} onClick={onLogout}>
            Logout
          </button>
          <button style={styles.homeButton} onClick={() => window.location.href = 'http://localhost:3001'}>
            Go to Application A
          </button>
        </div>
      </div>
    </div>
  );
};

const styles = {
  container: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    minHeight: '100vh',
    backgroundColor: '#ecf0f1',
  },
  card: {
    backgroundColor: 'white',
    padding: '3rem',
    borderRadius: '12px',
    boxShadow: '0 4px 16px rgba(0,0,0,0.1)',
    textAlign: 'center' as const,
    maxWidth: '500px',
  },
  iconContainer: {
    marginBottom: '1rem',
  },
  icon: {
    fontSize: '4rem',
  },
  title: {
    color: '#e74c3c',
    marginBottom: '1rem',
  },
  message: {
    color: '#2c3e50',
    fontSize: '1.1rem',
    marginBottom: '0.5rem',
  },
  submessage: {
    color: '#7f8c8d',
    marginBottom: '2rem',
  },
  actions: {
    display: 'flex',
    gap: '1rem',
    justifyContent: 'center',
  },
  logoutButton: {
    padding: '0.75rem 1.5rem',
    backgroundColor: '#e74c3c',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '1rem',
  },
  homeButton: {
    padding: '0.75rem 1.5rem',
    backgroundColor: '#3498db',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '1rem',
  },
};
