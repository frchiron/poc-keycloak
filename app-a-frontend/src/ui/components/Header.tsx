import React from 'react';

interface HeaderProps {
  appName: string;
  username?: string;
  onLogout: () => void;
}

export const Header: React.FC<HeaderProps> = ({ appName, username, onLogout }) => {
  return (
    <header style={styles.header}>
      <h1 style={styles.title}>{appName}</h1>
      <div style={styles.userSection}>
        <span style={styles.username}>Welcome, {username}</span>
        <button style={styles.logoutButton} onClick={onLogout}>
          Logout
        </button>
      </div>
    </header>
  );
};

const styles = {
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '1rem 2rem',
    backgroundColor: '#2c3e50',
    color: 'white',
    boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
  },
  title: {
    margin: 0,
    fontSize: '1.5rem',
  },
  userSection: {
    display: 'flex',
    alignItems: 'center',
    gap: '1rem',
  },
  username: {
    fontSize: '1rem',
  },
  logoutButton: {
    padding: '0.5rem 1rem',
    backgroundColor: '#e74c3c',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '0.9rem',
  },
};
