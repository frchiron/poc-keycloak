import React from 'react';
import { Header } from '../components/Header';
import { AppCard } from '../components/AppCard';
import { User } from '../../domain/User';
import { AppInfo } from '../../domain/AppInfo';

interface DashboardProps {
  user: User;
  appInfo: AppInfo;
  onLogout: () => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ user, appInfo, onLogout }) => {
  return (
    <div style={styles.container}>
      <Header appName={appInfo.appName} username={user.username} onLogout={onLogout} />

      <main style={styles.main}>
        <section style={styles.section}>
          <h2 style={styles.sectionTitle}>Application Information</h2>
          <div style={styles.infoCard}>
            <p><strong>App ID:</strong> {appInfo.appId}</p>
            <p><strong>Description:</strong> {appInfo.description}</p>
          </div>
        </section>

        <section style={styles.section}>
          <h2 style={styles.sectionTitle}>User Profile</h2>
          <div style={styles.infoCard}>
            <p><strong>Username:</strong> {user.username}</p>
            <p><strong>Email:</strong> {user.email}</p>
            <p><strong>Name:</strong> {user.firstName} {user.lastName}</p>
            <p><strong>Roles:</strong> {user.roles.join(', ')}</p>
          </div>
        </section>

        <section style={styles.section}>
          <h2 style={styles.sectionTitle}>Navigate to Other Applications (SSO Enabled)</h2>
          <p style={styles.ssoDescription}>
            Click on any application below to navigate without re-authenticating.
            Your session is shared across all applications.
          </p>
          <div style={styles.appsGrid}>
            {appInfo.redirectToAppA && (
              <AppCard
                appName="Application A"
                url={appInfo.redirectToAppA}
                description="Healthcare Management System"
                color="#e74c3c"
              />
            )}
            {appInfo.redirectToAppB && (
              <AppCard
                appName="Application B"
                url={appInfo.redirectToAppB}
                description="Financial Services Platform"
                color="#3498db"
              />
            )}
          </div>
        </section>
      </main>
    </div>
  );
};

const styles = {
  container: {
    minHeight: '100vh',
    backgroundColor: '#ecf0f1',
  },
  main: {
    padding: '2rem',
    maxWidth: '1200px',
    margin: '0 auto',
  },
  section: {
    marginBottom: '2rem',
  },
  sectionTitle: {
    color: '#2c3e50',
    marginBottom: '1rem',
    fontSize: '1.5rem',
  },
  ssoDescription: {
    color: '#7f8c8d',
    marginBottom: '1rem',
    fontSize: '1rem',
  },
  infoCard: {
    backgroundColor: 'white',
    padding: '1.5rem',
    borderRadius: '8px',
    boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
  },
  appsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
    gap: '1.5rem',
  },
};
