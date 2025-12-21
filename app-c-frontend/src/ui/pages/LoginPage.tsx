import React from 'react';

interface LoginPageProps {
  onLogin: () => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ onLogin }) => {
  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.title}>Application C</h1>
        <p style={styles.subtitle}>Supply Chain Management</p>
        <p style={styles.description}>
          Please login to access the application. You will be redirected to the SSO login page.
        </p>
        <button style={styles.loginButton} onClick={onLogin}>
          Login with SSO
        </button>
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
    backgroundColor: '#27ae60',
  },
  card: {
    backgroundColor: 'white',
    padding: '3rem',
    borderRadius: '12px',
    boxShadow: '0 4px 16px rgba(0,0,0,0.2)',
    textAlign: 'center' as const,
    maxWidth: '400px',
  },
  title: {
    color: '#2c3e50',
    marginBottom: '0.5rem',
  },
  subtitle: {
    color: '#7f8c8d',
    fontSize: '1.1rem',
    marginBottom: '1.5rem',
  },
  description: {
    color: '#95a5a6',
    marginBottom: '2rem',
  },
  loginButton: {
    width: '100%',
    padding: '1rem',
    backgroundColor: '#2ecc71',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '1rem',
    fontWeight: 'bold' as const,
  },
};
