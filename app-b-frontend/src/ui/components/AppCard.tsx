import React from 'react';

interface AppCardProps {
  appName: string;
  url: string;
  description: string;
  color: string;
}

export const AppCard: React.FC<AppCardProps> = ({ appName, url, description, color }) => {
  const handleRedirect = () => {
    window.location.href = url;
  };

  return (
    <div style={{ ...styles.card, borderLeft: `4px solid ${color}` }}>
      <h3 style={styles.cardTitle}>{appName}</h3>
      <p style={styles.cardDescription}>{description}</p>
      <button style={{ ...styles.redirectButton, backgroundColor: color }} onClick={handleRedirect}>
        Go to {appName}
      </button>
    </div>
  );
};

const styles = {
  card: {
    backgroundColor: 'white',
    padding: '1.5rem',
    borderRadius: '8px',
    boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
    minWidth: '280px',
  },
  cardTitle: {
    margin: '0 0 0.5rem 0',
    color: '#2c3e50',
  },
  cardDescription: {
    color: '#7f8c8d',
    fontSize: '0.9rem',
    marginBottom: '1rem',
  },
  redirectButton: {
    width: '100%',
    padding: '0.75rem',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '1rem',
    fontWeight: 'bold' as const,
  },
};
