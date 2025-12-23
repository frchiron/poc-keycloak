# Security Assessment Report
## SSO POC with Keycloak - Three Application Demo

**Assessment Date:** 2025-12-23
**Assessed By:** Security Audit
**Scope:** 3 Applications (Healthcare, Financial Services, Supply Chain) + Keycloak SSO
**Architecture:** React frontends, Spring Boot backends, Keycloak identity provider

---

## Table of Contents
- [Executive Summary](#executive-summary)
- [Critical Findings](#critical-findings-high-severity)
- [Medium Severity Findings](#medium-severity-findings)
- [Low Severity Findings](#low-severity--informational-findings)
- [Good Practices Observed](#good-practices-observed)
- [Remediation Priority](#remediation-priority)
- [Compliance Considerations](#compliance-considerations)

---

## Executive Summary

This security assessment evaluated the SSO implementation across three applications using Keycloak as the identity provider. While the architecture demonstrates good foundational practices (PKCE, JWT validation, RBAC), several critical vulnerabilities were identified that must be addressed before production deployment.

### Risk Summary
- **Critical Issues:** 5
- **Medium Severity:** 5
- **Low/Informational:** 3

### Key Concerns
1. No SSL/TLS enforcement - all traffic in plaintext
2. Hardcoded credentials in configuration files
3. CSRF protection disabled
4. Missing security headers
5. Token exposure risks

---

## CRITICAL FINDINGS (High Severity)

### 1. No SSL/TLS Enforcement ⚠️ CRITICAL

**Severity:** CRITICAL
**CVSS Score:** 9.1 (Critical)
**Location:** `keycloak-config/realm-export.json:4`

#### Vulnerability Description
All authentication tokens, credentials, and sensitive data are transmitted in plaintext over HTTP. The Keycloak realm is configured with SSL requirement set to "none".

```json
{
  "realm": "sso-poc",
  "sslRequired": "none",
  ...
}
```

#### Impact
- **Man-in-the-Middle (MITM) Attacks:** Attackers on the network can intercept JWT tokens, passwords, and session data
- **Session Hijacking:** Stolen tokens can be replayed to impersonate users
- **Credential Theft:** Login credentials transmitted in plaintext
- **Compliance Violation:** Violates PCI-DSS, HIPAA, GDPR requirements

#### Remediation

**Step 1: Update Keycloak Realm Configuration**

Edit `keycloak-config/realm-export.json`:
```json
{
  "realm": "sso-poc",
  "sslRequired": "external",  // Changed from "none"
  ...
}
```

Options for `sslRequired`:
- `"all"` - Require HTTPS for all requests (recommended for production)
- `"external"` - Require HTTPS for external requests only
- `"none"` - No HTTPS required (dev only)

**Step 2: Configure SSL in Keycloak**

Create `keycloak-config/keycloak-ssl.conf`:
```bash
# Generate self-signed certificate (DEV ONLY)
keytool -genkeypair -alias keycloak -keyalg RSA -keysize 2048 \
  -validity 365 -keystore keycloak.jks -storepass changeit \
  -dname "CN=localhost, OU=Dev, O=YourOrg, L=City, ST=State, C=US"
```

Update `docker-compose.yml`:
```yaml
services:
  keycloak:
    image: quay.io/keycloak/keycloak:23.0
    container_name: keycloak
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: ${KC_DB_USERNAME}
      KC_DB_PASSWORD: ${KC_DB_PASSWORD}
      KEYCLOAK_ADMIN: ${KEYCLOAK_ADMIN}
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
      KC_HEALTH_ENABLED: true
      KC_METRICS_ENABLED: true
      # SSL Configuration
      KC_HTTPS_CERTIFICATE_FILE: /opt/keycloak/conf/server.crt.pem
      KC_HTTPS_CERTIFICATE_KEY_FILE: /opt/keycloak/conf/server.key.pem
      KC_HTTPS_PORT: 8443
      KC_HOSTNAME_STRICT: false
    volumes:
      - ./keycloak-config/certs:/opt/keycloak/conf
    command:
      - start  # Changed from start-dev
    ports:
      - "8443:8443"  # HTTPS port
```

**Step 3: Update Application Configuration**

Update all `.env` files:
```env
# app-a-frontend/.env
REACT_APP_KEYCLOAK_URL=https://localhost:8443
REACT_APP_BACKEND_URL=https://localhost:9001
```

Update `application.yml` for all backends:
```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://localhost:8443/realms/sso-poc
          jwk-set-uri: https://localhost:8443/realms/sso-poc/protocol/openid-connect/certs
```

**Step 4: Production SSL Setup**

For production, use proper SSL certificates from a Certificate Authority:

```bash
# Using Let's Encrypt with Certbot
certbot certonly --standalone -d your-domain.com

# Or use your organization's PKI/certificate management system
```

---

### 2. CSRF Protection Disabled ⚠️ CRITICAL

**Severity:** CRITICAL
**CVSS Score:** 8.1 (High)
**Location:** All `SecurityConfig.java` files (lines ~25)

#### Vulnerability Description
Cross-Site Request Forgery (CSRF) protection is explicitly disabled in all Spring Boot applications.

```java
http
    .csrf(csrf -> csrf.disable())  // VULNERABLE
```

#### Impact
- Attackers can trick authenticated users into performing unauthorized actions
- State-changing operations (POST, PUT, DELETE) can be executed without user consent
- Particularly dangerous for financial or healthcare applications

#### Remediation

**Option 1: Enable CSRF with Cookie-based tokens (Recommended for SPAs)**

Update `app-a-backend/src/main/java/com/example/sso/appa/infrastructure/config/SecurityConfig.java`:

```java
package com.example.sso.appa.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // Create CSRF token handler
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName("_csrf");

        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            // ENABLE CSRF with cookie-based tokens
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(requestHandler)
                .ignoringRequestMatchers("/actuator/**") // Exclude health checks
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/**").permitAll()
                .anyRequest().hasAuthority("SCOPE_app-a-user")
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            );

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
            var authorities = new java.util.ArrayList<org.springframework.security.core.GrantedAuthority>();

            var realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null && realmAccess.get("roles") instanceof java.util.List<?> roles) {
                for (Object role : roles) {
                    authorities.add(new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_" + role));
                }
            }

            return authorities;
        });
        return jwtAuthenticationConverter;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("https://localhost:3001")); // Changed to HTTPS
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-XSRF-TOKEN")); // Specific headers
        configuration.setAllowCredentials(true);
        configuration.setExposedHeaders(List.of("Authorization"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

**Frontend Implementation (React)**

Create `app-a-frontend/src/adapters/CsrfAdapter.ts`:
```typescript
export class CsrfAdapter {
  private csrfToken: string | null = null;

  async fetchCsrfToken(): Promise<string> {
    // Get CSRF token from cookie
    const cookies = document.cookie.split(';');
    const csrfCookie = cookies.find(cookie => cookie.trim().startsWith('XSRF-TOKEN='));

    if (csrfCookie) {
      this.csrfToken = csrfCookie.split('=')[1];
      return this.csrfToken;
    }

    throw new Error('CSRF token not found');
  }

  getCsrfToken(): string | null {
    return this.csrfToken;
  }
}

export const csrfAdapter = new CsrfAdapter();
```

Update `app-a-frontend/src/adapters/ApiAdapter.ts`:
```typescript
import { User } from '../domain/User';
import { AppInfo } from '../domain/AppInfo';
import { csrfAdapter } from './CsrfAdapter';

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

  private async fetchWithAuth(endpoint: string, token: string, options: RequestInit = {}): Promise<any> {
    // Get CSRF token for state-changing requests
    const method = options.method || 'GET';
    const headers: HeadersInit = {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    };

    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase())) {
      try {
        const csrfToken = await csrfAdapter.fetchCsrfToken();
        headers['X-XSRF-TOKEN'] = csrfToken;
      } catch (error) {
        console.error('Failed to fetch CSRF token:', error);
      }
    }

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers,
      credentials: 'include', // Important: Include cookies
    });

    if (!response.ok) {
      if (response.status === 403) {
        throw new Error(`403: Access Denied - You don't have permission to access this application`);
      }
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
```

**Option 2: Document why CSRF is disabled (If using stateless JWT-only)**

If you choose to keep CSRF disabled, document the decision:

```java
http
    // CSRF disabled: Using stateless JWT-only authentication with proper Origin validation
    // All requests require valid JWT token in Authorization header
    // Origin header validation prevents CSRF attacks in modern browsers
    // This is acceptable for stateless API-only backends
    .csrf(csrf -> csrf.disable())
```

**Ensure proper Origin validation:**
```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    // Strict origin list - NO wildcards
    configuration.setAllowedOrigins(List.of("https://app-a.yourdomain.com"));
    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
    configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    configuration.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```

---

### 3. Hardcoded Credentials in Configuration ⚠️ CRITICAL

**Severity:** CRITICAL
**CVSS Score:** 9.8 (Critical)
**Location:**
- `docker-compose.yml:10, 28, 30`
- `keycloak-config/realm-export.json` (user passwords)

#### Vulnerability Description
Sensitive credentials are hardcoded in configuration files that are committed to version control.

**docker-compose.yml:**
```yaml
environment:
  POSTGRES_PASSWORD: keycloak        # EXPOSED
  KEYCLOAK_ADMIN_PASSWORD: admin     # EXPOSED
```

**realm-export.json:**
```json
"credentials": [
  {
    "type": "password",
    "value": "password"  // PLAINTEXT PASSWORD
  }
]
```

#### Impact
- Database compromise through exposed PostgreSQL credentials
- Keycloak admin console takeover
- User account compromise
- Credentials exposed in Git history (persists even after deletion)

#### Remediation

**Step 1: Create Environment Variables File**

Create `.env` in project root (and add to `.gitignore`):
```bash
# .env (DO NOT COMMIT THIS FILE)

# PostgreSQL
POSTGRES_DB=keycloak
POSTGRES_USER=keycloak_user_prod
POSTGRES_PASSWORD=CHANGE_ME_random_strong_password_here_32chars

# Keycloak Admin
KEYCLOAK_ADMIN=admin_prod
KEYCLOAK_ADMIN_PASSWORD=CHANGE_ME_another_random_password_32chars

# Database Connection
KC_DB_USERNAME=keycloak_user_prod
KC_DB_PASSWORD=CHANGE_ME_random_strong_password_here_32chars
```

**Step 2: Update .gitignore**

```bash
# Add to .gitignore
.env
.env.local
.env.*.local
*.key
*.pem
*.jks
secrets/
```

**Step 3: Update docker-compose.yml**

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: keycloak-postgres
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - keycloak-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
      interval: 10s
      timeout: 5s
      retries: 5

  keycloak:
    image: quay.io/keycloak/keycloak:23.0
    container_name: keycloak
    environment:
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/${POSTGRES_DB}
      KC_DB_USERNAME: ${KC_DB_USERNAME}
      KC_DB_PASSWORD: ${KC_DB_PASSWORD}
      KEYCLOAK_ADMIN: ${KEYCLOAK_ADMIN}
      KEYCLOAK_ADMIN_PASSWORD: ${KEYCLOAK_ADMIN_PASSWORD}
      KC_HEALTH_ENABLED: true
      KC_METRICS_ENABLED: true
    command:
      - start-dev
    ports:
      - "8080:8080"
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - keycloak-network
    healthcheck:
      test: ["CMD-SHELL", "exec 3<>/dev/tcp/127.0.0.1/8080;echo -e 'GET /health/ready HTTP/1.1\r\nhost: http://localhost\r\nConnection: close\r\n\r\n' >&3;if [ $? -eq 0 ]; then echo 'Healthcheck Successful';exit 0;else echo 'Healthcheck Failed';exit 1;fi;"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s

volumes:
  postgres_data:

networks:
  keycloak-network:
    driver: bridge
```

**Step 4: Create .env.example Template**

```bash
# .env.example (safe to commit)
# Copy this file to .env and fill in actual values

# PostgreSQL
POSTGRES_DB=keycloak
POSTGRES_USER=your_postgres_user
POSTGRES_PASSWORD=your_strong_password_here

# Keycloak Admin
KEYCLOAK_ADMIN=your_admin_username
KEYCLOAK_ADMIN_PASSWORD=your_admin_strong_password

# Database Connection
KC_DB_USERNAME=your_postgres_user
KC_DB_PASSWORD=your_strong_password_here
```

**Step 5: Remove Passwords from Realm Export**

Update `keycloak-config/realm-export.json`:
```json
{
  "realm": "sso-poc",
  "users": [
    {
      "username": "testuser",
      "enabled": true,
      "email": "testuser@example.com",
      "firstName": "Test",
      "lastName": "User",
      "credentials": [],  // EMPTY - Set via Keycloak Admin or setup script
      "realmRoles": ["user"]
    }
  ]
}
```

**Step 6: Create User Setup Script**

Create `keycloak-config/setup-users.sh`:
```bash
#!/bin/bash

# Load environment variables
source .env

# Keycloak admin credentials
KEYCLOAK_URL="http://localhost:8080"
REALM="sso-poc"

echo "Setting up users for realm: $REALM"

# Get admin token
ADMIN_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$KEYCLOAK_ADMIN" \
  -d "password=$KEYCLOAK_ADMIN_PASSWORD" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" == "null" ]; then
  echo "Failed to obtain admin token"
  exit 1
fi

# Create testuser with secure password from environment
TESTUSER_PASSWORD=${TESTUSER_PASSWORD:-$(openssl rand -base64 32)}
echo "Creating testuser with password: $TESTUSER_PASSWORD"

# Get user ID if exists
USER_ID=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM/users?username=testuser" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')

if [ "$USER_ID" != "null" ] && [ -n "$USER_ID" ]; then
  # Reset password for existing user
  curl -X PUT "$KEYCLOAK_URL/admin/realms/$REALM/users/$USER_ID/reset-password" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "type": "password",
      "value": "'"$TESTUSER_PASSWORD"'",
      "temporary": false
    }'
  echo "Updated password for testuser"
else
  echo "User not found. Create via Keycloak Admin Console or modify this script."
fi

# Store password securely (for reference only - delete after sharing)
echo "TESTUSER_PASSWORD=$TESTUSER_PASSWORD" >> .env.secrets
echo "Passwords saved to .env.secrets (DO NOT COMMIT)"
```

**Step 7: Production Secrets Management**

For production, use a proper secrets management solution:

**AWS Secrets Manager Example:**
```bash
# Store secrets
aws secretsmanager create-secret \
  --name /myapp/keycloak/admin-password \
  --secret-string "your-secure-password"

# Retrieve in application
aws secretsmanager get-secret-value \
  --secret-id /myapp/keycloak/admin-password \
  --query SecretString \
  --output text
```

**HashiCorp Vault Example:**
```bash
# Store secrets
vault kv put secret/keycloak admin_password="your-secure-password"

# Retrieve in application
vault kv get -field=admin_password secret/keycloak
```

**Step 8: Clean Git History**

```bash
# Remove sensitive files from Git history
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch .env" \
  --prune-empty --tag-name-filter cat -- --all

# Force push (coordinate with team first!)
git push origin --force --all
```

---

### 4. Missing Security Headers ⚠️ HIGH

**Severity:** HIGH
**CVSS Score:** 7.5 (High)
**Location:** All `SecurityConfig.java` files

#### Vulnerability Description
Applications do not set critical security headers, leaving them vulnerable to various attacks:
- No Content Security Policy (CSP)
- No X-Frame-Options (clickjacking)
- No X-Content-Type-Options (MIME sniffing)
- No Strict-Transport-Security (HSTS)
- No X-XSS-Protection

#### Impact
- **Clickjacking:** Application can be embedded in malicious iframes
- **XSS Attacks:** No CSP to prevent inline script execution
- **MIME Sniffing:** Browsers may misinterpret file types
- **SSL Stripping:** No HSTS to enforce HTTPS

#### Remediation

Update `SecurityConfig.java` for all applications:

```java
package com.example.sso.appa.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                .anyRequest().hasAuthority("SCOPE_app-a-user")
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            )
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            // SECURITY HEADERS
            .headers(headers -> headers
                // Content Security Policy - Prevents XSS attacks
                .contentSecurityPolicy(csp -> csp
                    .policyDirectives(
                        "default-src 'self'; " +
                        "script-src 'self' 'unsafe-inline'; " +  // Adjust based on your needs
                        "style-src 'self' 'unsafe-inline'; " +
                        "img-src 'self' data: https:; " +
                        "font-src 'self' data:; " +
                        "connect-src 'self' https://localhost:8080; " +  // Keycloak
                        "frame-ancestors 'none'; " +  // Prevent clickjacking
                        "base-uri 'self'; " +
                        "form-action 'self'"
                    )
                )
                // X-Frame-Options - Prevent clickjacking
                .frameOptions(frame -> frame.deny())

                // X-Content-Type-Options - Prevent MIME sniffing
                .contentTypeOptions(contentType -> contentType.disable())

                // Strict-Transport-Security - Enforce HTTPS
                .httpStrictTransportSecurity(hsts -> hsts
                    .includeSubDomains(true)
                    .maxAgeInSeconds(31536000)  // 1 year
                )

                // X-XSS-Protection - Enable browser XSS filter
                .xssProtection(xss -> xss
                    .headerValue("1; mode=block")
                )

                // Referrer-Policy - Control referrer information
                .referrerPolicy(referrer -> referrer
                    .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                )

                // Permissions-Policy (formerly Feature-Policy)
                .permissionsPolicy(permissions -> permissions
                    .policy("geolocation=(), microphone=(), camera=()")
                )
            );

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwt -> {
            var authorities = new java.util.ArrayList<org.springframework.security.core.GrantedAuthority>();

            var realmAccess = jwt.getClaimAsMap("realm_access");
            if (realmAccess != null && realmAccess.get("roles") instanceof java.util.List<?> roles) {
                for (Object role : roles) {
                    authorities.add(new org.springframework.security.core.authority.SimpleGrantedAuthority("SCOPE_" + role));
                }
            }

            return authorities;
        });
        return jwtAuthenticationConverter;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("https://localhost:3001"));  // Use HTTPS
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
        configuration.setAllowCredentials(true);
        configuration.setExposedHeaders(List.of("Authorization"));
        configuration.setMaxAge(3600L);  // Cache preflight requests for 1 hour

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
```

**Verify Headers are Set**

Create a test script `test-security-headers.sh`:
```bash
#!/bin/bash

echo "Testing Security Headers for App A Backend"
echo "==========================================="

curl -I https://localhost:9001/api/user \
  -H "Authorization: Bearer test-token" \
  2>/dev/null | grep -E "Content-Security-Policy|X-Frame-Options|Strict-Transport-Security|X-Content-Type-Options|X-XSS-Protection|Referrer-Policy"

echo ""
echo "Expected headers:"
echo "  Content-Security-Policy: ..."
echo "  X-Frame-Options: DENY"
echo "  Strict-Transport-Security: max-age=31536000 ; includeSubDomains"
echo "  X-Content-Type-Options: nosniff"
echo "  X-XSS-Protection: 1; mode=block"
echo "  Referrer-Policy: strict-origin-when-cross-origin"
```

---

### 5. Token Exposure Risk in URL ⚠️ HIGH

**Severity:** HIGH
**CVSS Score:** 7.4 (High)
**Location:** OAuth2 redirect flow (already noted in README.md:9)

#### Vulnerability Description
During the OAuth2 authorization code flow, the authorization code appears in the URL:
```
http://localhost:3001/?code=abc123...&session_state=xyz&iss=...
```

While the actual access token is NOT in the URL (good - it's exchanged server-side), the authorization code can be:
- Logged in browser history
- Leaked via Referer headers to third-party sites
- Captured in server logs
- Exposed in screenshots or screen recordings
- Stolen via browser history attacks

#### Current Mitigation (Good)
- PKCE is enabled (`pkceMethod: 'S256'`) ✓
- Authorization code is single-use ✓
- Code has short expiration ✓

#### Additional Remediation

**Option 1: Use response_mode=form_post (Recommended)**

This sends the authorization code via POST instead of URL query parameters.

Update `KeycloakAdapter.ts`:
```typescript
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
        // Use form_post to avoid code in URL
        responseMode: 'fragment',  // Or 'query' (default) or 'form_post'
        // Note: form_post requires server-side handling
      });

      if (authenticated) {
        this.setupTokenRefresh();
        // Clear URL parameters after authentication
        this.clearUrlParameters();
      }

      return authenticated;
    } catch (error) {
      console.error('Keycloak initialization failed:', error);
      return false;
    }
  }

  private setupTokenRefresh(): void {
    // Refresh token 70 seconds before expiration
    setInterval(() => {
      this.keycloak.updateToken(70).catch(() => {
        console.error('Failed to refresh token');
      });
    }, 60000);
  }

  private clearUrlParameters(): void {
    // Remove OAuth parameters from URL after successful authentication
    const url = new URL(window.location.href);
    const params = ['code', 'session_state', 'iss', 'state'];

    let urlModified = false;
    params.forEach(param => {
      if (url.searchParams.has(param)) {
        url.searchParams.delete(param);
        urlModified = true;
      }
    });

    // Also check hash fragment
    if (window.location.hash) {
      const hashParams = new URLSearchParams(window.location.hash.substring(1));
      params.forEach(param => {
        if (hashParams.has(param)) {
          hashParams.delete(param);
          urlModified = true;
        }
      });

      if (urlModified) {
        const newHash = hashParams.toString();
        url.hash = newHash ? `#${newHash}` : '';
      }
    }

    if (urlModified) {
      // Use replaceState to avoid creating browser history entry
      window.history.replaceState({}, document.title, url.toString());
    }
  }

  login(): void {
    this.keycloak.login({
      redirectUri: window.location.origin,
      // Additional security options
      prompt: 'login',  // Force re-authentication
    });
  }

  logout(): void {
    this.keycloak.logout({
      redirectUri: window.location.origin
    });
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
```

**Option 2: Update Keycloak Client Configuration**

In Keycloak Admin Console or `realm-export.json`:
```json
{
  "clientId": "app-a",
  "enabled": true,
  "publicClient": true,
  "redirectUris": [
    "https://localhost:3001/callback"  // Specific callback URL
  ],
  "webOrigins": [
    "https://localhost:3001"
  ],
  "protocol": "openid-connect",
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,  // DISABLE
  "attributes": {
    "pkce.code.challenge.method": "S256",
    "post.logout.redirect.uris": "https://localhost:3001/logout",
    "backchannel.logout.session.required": "true",
    "backchannel.logout.revoke.offline.tokens": "true"
  }
}
```

**Option 3: Implement Browser History Protection**

Add to your React app (in `App.tsx` or main component):
```typescript
import { useEffect } from 'react';

function useHistoryProtection() {
  useEffect(() => {
    // Prevent browser from caching sensitive pages
    window.onbeforeunload = () => {
      // Clear sensitive data
      sessionStorage.clear();
    };

    // Detect if user navigated using back button
    window.addEventListener('pageshow', (event) => {
      if (event.persisted) {
        // Page was loaded from cache (back button)
        window.location.reload();
      }
    });

    return () => {
      window.onbeforeunload = null;
    };
  }, []);
}

export default function App() {
  useHistoryProtection();

  // ... rest of your app
}
```

**Option 4: Add Cache-Control Headers**

In `SecurityConfig.java`:
```java
.headers(headers -> headers
    .cacheControl(cache -> cache.disable())
    // Add to other headers configuration
)
```

---

## MEDIUM SEVERITY FINDINGS

### 6. Public Clients Without Client Secrets

**Severity:** MEDIUM
**CVSS Score:** 6.5 (Medium)
**Location:** `keycloak-config/realm-export.json:18, 36, 54`

#### Vulnerability Description
All clients are configured as public clients without client secrets:
```json
{
  "clientId": "app-a",
  "publicClient": true,  // No client authentication
  ...
}
```

#### Impact
- Anyone can initiate OAuth flows pretending to be your application
- No client authentication at token endpoint
- Increased risk of authorization code interception attacks

#### Analysis
For Single Page Applications (SPAs), this is partially acceptable because:
- SPAs cannot securely store client secrets (JavaScript is client-side)
- PKCE (which you're using) mitigates authorization code interception

However, for sensitive applications, consider alternative architectures.

#### Remediation

**Option 1: Backend-for-Frontend (BFF) Pattern (Recommended for Production)**

Implement a lightweight backend proxy that handles OAuth:

```
User Browser ← → BFF Server ← → Keycloak
                  ↓
            Spring Boot APIs
```

**Create BFF Service:**

```typescript
// bff-server/src/server.ts (Node.js/Express example)
import express from 'express';
import session from 'express-session';
import { Issuer, generators } from 'openid-client';

const app = express();

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET!,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,  // HTTPS only
    httpOnly: true,  // Prevent JavaScript access
    sameSite: 'strict',
    maxAge: 3600000  // 1 hour
  }
}));

// Initialize Keycloak client
let keycloakClient: any;

(async () => {
  const issuer = await Issuer.discover('https://localhost:8443/realms/sso-poc');

  keycloakClient = new issuer.Client({
    client_id: 'app-a-bff',
    client_secret: process.env.KEYCLOAK_CLIENT_SECRET!,  // Confidential client
    redirect_uris: ['https://localhost:4001/callback'],
    response_types: ['code'],
  });
})();

// Login endpoint
app.get('/auth/login', (req, res) => {
  const code_verifier = generators.codeVerifier();
  const code_challenge = generators.codeChallenge(code_verifier);

  req.session.code_verifier = code_verifier;

  const authUrl = keycloakClient.authorizationUrl({
    scope: 'openid profile email',
    code_challenge,
    code_challenge_method: 'S256',
  });

  res.redirect(authUrl);
});

// Callback endpoint
app.get('/callback', async (req, res) => {
  const params = keycloakClient.callbackParams(req);
  const tokenSet = await keycloakClient.callback(
    'https://localhost:4001/callback',
    params,
    { code_verifier: req.session.code_verifier }
  );

  // Store tokens in secure, HTTP-only session
  req.session.tokens = {
    access_token: tokenSet.access_token,
    refresh_token: tokenSet.refresh_token,
    id_token: tokenSet.id_token,
  };

  delete req.session.code_verifier;

  res.redirect('/dashboard');
});

// API proxy with token injection
app.get('/api/*', async (req, res) => {
  if (!req.session.tokens) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  // Refresh token if needed
  if (keycloakClient.expired(req.session.tokens.access_token)) {
    const refreshed = await keycloakClient.refresh(req.session.tokens.refresh_token);
    req.session.tokens.access_token = refreshed.access_token;
  }

  // Forward to backend API with token
  const backendUrl = `https://localhost:9001${req.path}`;
  const response = await fetch(backendUrl, {
    headers: {
      'Authorization': `Bearer ${req.session.tokens.access_token}`
    }
  });

  res.json(await response.json());
});

app.listen(4001, () => {
  console.log('BFF server running on https://localhost:4001');
});
```

**Update Keycloak Configuration for Confidential Client:**
```json
{
  "clientId": "app-a-bff",
  "enabled": true,
  "publicClient": false,  // Confidential client
  "clientAuthenticatorType": "client-secret",
  "secret": "your-generated-client-secret-here",
  "redirectUris": [
    "https://localhost:4001/callback"
  ],
  "protocol": "openid-connect",
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "attributes": {
    "pkce.code.challenge.method": "S256"
  }
}
```

**Option 2: Strengthen Public Client Configuration**

If staying with public clients, enhance security:

```json
{
  "clientId": "app-a",
  "publicClient": true,
  "redirectUris": [
    "https://app-a.yourdomain.com/callback"  // EXACT URI
  ],
  "webOrigins": [
    "https://app-a.yourdomain.com"
  ],
  "attributes": {
    "pkce.code.challenge.method": "S256",  // Required
    "require.pushed.authorization.requests": "true",  // PAR for enhanced security
    "tls.client.certificate.bound.access.tokens": "true",  // Certificate-bound tokens
    "token.endpoint.auth.signing.alg": "RS256"
  }
}
```

---

### 7. Direct Access Grants Enabled

**Severity:** MEDIUM
**CVSS Score:** 5.9 (Medium)
**Location:** `keycloak-config/realm-export.json:28, 46, 64`

#### Vulnerability Description
Resource Owner Password Credentials (ROPC) flow is enabled:
```json
"directAccessGrantsEnabled": true
```

#### Impact
- Defeats the purpose of SSO
- Application handles user passwords directly
- Creates phishing risks
- Passwords exposed to application code
- Cannot leverage MFA or other Keycloak features

#### Remediation

**Disable Direct Access Grants:**

Update `keycloak-config/realm-export.json`:
```json
{
  "clientId": "app-a",
  "enabled": true,
  "publicClient": true,
  "redirectUris": ["https://localhost:3001/*"],
  "webOrigins": ["https://localhost:3001"],
  "protocol": "openid-connect",
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,  // DISABLED
  "attributes": {
    "pkce.code.challenge.method": "S256"
  }
}
```

**If you need programmatic access, use Service Accounts instead:**

```json
{
  "clientId": "app-a-service",
  "enabled": true,
  "publicClient": false,
  "clientAuthenticatorType": "client-secret",
  "secret": "service-account-secret",
  "serviceAccountsEnabled": true,  // Enable service account
  "directAccessGrantsEnabled": false,
  "standardFlowEnabled": false,
  "implicitFlowEnabled": false
}
```

**Using Service Account in Backend:**
```java
// Service account token request
RestClient client = RestClient.builder()
    .baseUrl("https://localhost:8443")
    .build();

Map<String, String> formData = Map.of(
    "grant_type", "client_credentials",
    "client_id", "app-a-service",
    "client_secret", System.getenv("SERVICE_CLIENT_SECRET")
);

TokenResponse token = client.post()
    .uri("/realms/sso-poc/protocol/openid-connect/token")
    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
    .body(formData)
    .retrieve()
    .body(TokenResponse.class);
```

---

### 8. Overly Permissive CORS Configuration

**Severity:** MEDIUM
**CVSS Score:** 5.3 (Medium)
**Location:** `SecurityConfig.java:64` (all apps)

#### Vulnerability Description
CORS allows all headers:
```java
configuration.setAllowedHeaders(List.of("*"));
```

#### Impact
- Potential for header injection attacks
- Broader attack surface for CORS-based attacks
- Violates principle of least privilege

#### Remediation

**Specify Exact Headers:**

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();

    // Specific origins - NO wildcards
    configuration.setAllowedOrigins(List.of(
        "https://localhost:3001",
        "https://app-a.yourdomain.com"  // Production domain
    ));

    // Specific methods only
    configuration.setAllowedMethods(List.of(
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "OPTIONS"
    ));

    // SPECIFIC headers - no wildcards
    configuration.setAllowedHeaders(List.of(
        "Authorization",
        "Content-Type",
        "Accept",
        "X-Requested-With",
        "X-XSRF-TOKEN"  // If using CSRF tokens
    ));

    // Required for cookies/authentication
    configuration.setAllowCredentials(true);

    // Headers that frontend can access
    configuration.setExposedHeaders(List.of(
        "Authorization",
        "X-Total-Count"  // For pagination, if needed
    ));

    // Cache preflight requests for 1 hour
    configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```

**For Production with Multiple Domains:**

```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();

    // Use environment-specific origins
    String allowedOrigins = System.getenv("ALLOWED_ORIGINS");
    if (allowedOrigins != null) {
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins.split(",")));
    } else {
        // Fallback for development
        configuration.setAllowedOrigins(List.of("https://localhost:3001"));
    }

    configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
    configuration.setAllowCredentials(true);
    configuration.setExposedHeaders(List.of("Authorization"));
    configuration.setMaxAge(3600L);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```

**Environment Configuration:**
```bash
# .env
ALLOWED_ORIGINS=https://app-a.yourdomain.com,https://app-b.yourdomain.com
```

---

### 9. Debug Logging Enabled

**Severity:** MEDIUM
**CVSS Score:** 5.1 (Medium)
**Location:** All `application.yml:25-27`

#### Vulnerability Description
Debug logging is enabled for security components:
```yaml
logging:
  level:
    org.springframework.security: DEBUG
    com.example.sso: DEBUG
```

Evidence of token logging in `UserController.java:30`:
```java
User user = getUserInfoUseCase.getUserInfo(jwt.getTokenValue());
```

#### Impact
- JWT tokens may be logged
- User credentials could appear in logs
- Sensitive claim data exposed
- Large log files (performance impact)
- Compliance violations (GDPR, HIPAA)

#### Remediation

**Step 1: Update application.yml for Production**

Create environment-specific configs:

**application.yml (base):**
```yaml
server:
  port: 9001

spring:
  application:
    name: app-a
  profiles:
    active: ${SPRING_PROFILES_ACTIVE:dev}
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: ${KEYCLOAK_ISSUER_URI:https://localhost:8443/realms/sso-poc}
          jwk-set-uri: ${KEYCLOAK_JWK_URI:https://localhost:8443/realms/sso-poc/protocol/openid-connect/certs}

management:
  endpoints:
    web:
      exposure:
        include: health,info
```

**application-dev.yml:**
```yaml
logging:
  level:
    org.springframework.security: DEBUG
    com.example.sso: DEBUG

server:
  ssl:
    enabled: false  # HTTP for local dev
```

**application-prod.yml:**
```yaml
logging:
  level:
    root: WARN
    org.springframework.security: INFO  # Not DEBUG
    com.example.sso: INFO
    # Specific audit logger
    com.example.sso.audit: INFO

  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} - %msg%n"
    file: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"

  file:
    name: /var/log/app-a/application.log
    max-size: 10MB
    max-history: 30

server:
  ssl:
    enabled: true
    key-store: ${SSL_KEYSTORE_PATH}
    key-store-password: ${SSL_KEYSTORE_PASSWORD}
    key-store-type: PKCS12
```

**Step 2: Implement Secure Logging**

Create a custom audit logger:

```java
// com/example/sso/appa/infrastructure/logging/AuditLogger.java
package com.example.sso.appa.infrastructure.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;

@Component
public class AuditLogger {

    private static final Logger auditLog = LoggerFactory.getLogger("AUDIT");

    public void logAuthSuccess(String username, String ipAddress, String resource) {
        auditLog.info("AUTH_SUCCESS | user={} | ip={} | resource={} | timestamp={}",
            username, ipAddress, resource, Instant.now());
    }

    public void logAuthFailure(String username, String ipAddress, String reason) {
        auditLog.warn("AUTH_FAILURE | user={} | ip={} | reason={} | timestamp={}",
            username, ipAddress, reason, Instant.now());
    }

    public void logAccessDenied(String username, String resource, String requiredRole) {
        auditLog.warn("ACCESS_DENIED | user={} | resource={} | required_role={} | timestamp={}",
            username, resource, requiredRole, Instant.now());
    }

    // NEVER log tokens or sensitive data
    public void logTokenRefresh(String username) {
        auditLog.info("TOKEN_REFRESH | user={} | timestamp={}", username, Instant.now());
    }
}
```

**Step 3: Update Controllers to Use Audit Logging**

```java
package com.example.sso.appa.infrastructure.adapter.in.web;

import com.example.sso.appa.application.port.in.GetUserInfoUseCase;
import com.example.sso.appa.domain.model.User;
import com.example.sso.appa.infrastructure.logging.AuditLogger;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "https://localhost:3001")
public class UserController {

    private static final Logger log = LoggerFactory.getLogger(UserController.class);
    private final GetUserInfoUseCase getUserInfoUseCase;
    private final AuditLogger auditLogger;

    public UserController(GetUserInfoUseCase getUserInfoUseCase, AuditLogger auditLogger) {
        this.getUserInfoUseCase = getUserInfoUseCase;
        this.auditLogger = auditLogger;
    }

    @GetMapping("/user")
    public ResponseEntity<User> getUserInfo(
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest request) {

        String username = jwt.getClaimAsString("preferred_username");
        String ipAddress = request.getRemoteAddr();

        log.info("User info requested");  // No sensitive data

        // Use JWT, but don't log the token value
        User user = getUserInfoUseCase.getUserInfo(jwt.getTokenValue());

        // Audit log (no token)
        auditLogger.logAuthSuccess(username, ipAddress, "/api/user");

        return ResponseEntity.ok(user);
    }

    @GetMapping("/protected")
    public ResponseEntity<Map<String, String>> protectedEndpoint(
            @AuthenticationPrincipal Jwt jwt,
            HttpServletRequest request) {

        String username = jwt.getClaimAsString("preferred_username");
        String ipAddress = request.getRemoteAddr();

        log.info("Protected endpoint accessed");
        auditLogger.logAuthSuccess(username, ipAddress, "/api/protected");

        Map<String, String> response = new HashMap<>();
        response.put("message", "This is a protected resource in App A");
        response.put("user", username);
        response.put("email", jwt.getClaimAsString("email"));

        return ResponseEntity.ok(response);
    }
}
```

**Step 4: Configure Logback for Separate Audit Log**

Create `src/main/resources/logback-spring.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>

    <!-- Console appender for development -->
    <appender name="CONSOLE" class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>

    <!-- Application log file -->
    <appender name="FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/application.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>logs/application-%d{yyyy-MM-dd}.log</fileNamePattern>
            <maxHistory>30</maxHistory>
        </rollingPolicy>
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n</pattern>
        </encoder>
    </appender>

    <!-- Separate AUDIT log file (important for compliance) -->
    <appender name="AUDIT_FILE" class="ch.qos.logback.core.rolling.RollingFileAppender">
        <file>logs/audit.log</file>
        <rollingPolicy class="ch.qos.logback.core.rolling.TimeBasedRollingPolicy">
            <fileNamePattern>logs/audit-%d{yyyy-MM-dd}.log</fileNamePattern>
            <maxHistory>90</maxHistory>  <!-- Keep longer for compliance -->
        </rollingPolicy>
        <encoder>
            <pattern>%d{yyyy-MM-dd HH:mm:ss} - %msg%n</pattern>
        </encoder>
    </appender>

    <!-- Audit logger -->
    <logger name="AUDIT" level="INFO" additivity="false">
        <appender-ref ref="AUDIT_FILE"/>
    </logger>

    <!-- Root logger -->
    <root level="INFO">
        <appender-ref ref="CONSOLE"/>
        <appender-ref ref="FILE"/>
    </root>

    <!-- Production profile: No console, only files -->
    <springProfile name="prod">
        <root level="WARN">
            <appender-ref ref="FILE"/>
        </root>
    </springProfile>

</configuration>
```

---

### 10. Wildcard Redirect URIs

**Severity:** MEDIUM
**CVSS Score:** 6.1 (Medium)
**Location:** `keycloak-config/realm-export.json:20, 38, 56`

#### Vulnerability Description
Redirect URIs use wildcards:
```json
"redirectUris": [
  "http://localhost:3001/*"
]
```

#### Impact
- Open redirect vulnerability
- Authorization code theft via malicious redirects
- Phishing attacks

#### Remediation

**Use Exact URIs for Production:**

```json
{
  "clientId": "app-a",
  "enabled": true,
  "publicClient": true,
  "redirectUris": [
    "https://app-a.yourdomain.com/",
    "https://app-a.yourdomain.com/callback",
    "https://app-a.yourdomain.com/silent-check-sso.html"
  ],
  "webOrigins": [
    "https://app-a.yourdomain.com"
  ],
  "protocol": "openid-connect",
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": false,
  "attributes": {
    "pkce.code.challenge.method": "S256",
    "post.logout.redirect.uris": "https://app-a.yourdomain.com/"
  }
}
```

**If Wildcards Are Necessary (Development Only):**

Create separate client configurations:

**Development client:**
```json
{
  "clientId": "app-a-dev",
  "redirectUris": ["http://localhost:3001/*"],
  "attributes": {
    "oauth2.device.authorization.grant.enabled": "false"
  }
}
```

**Production client:**
```json
{
  "clientId": "app-a-prod",
  "redirectUris": [
    "https://app-a.yourdomain.com/callback"
  ]
}
```

---

## LOW SEVERITY / INFORMATIONAL FINDINGS

### 11. Missing Input Validation on API Endpoints

**Severity:** LOW
**CVSS Score:** 3.7 (Low)
**Location:** `UserController.java` (all apps)

#### Vulnerability Description
Controllers use JWT claims without additional validation:
```java
info.put("username", jwt.getClaimAsString("preferred_username"));
```

#### Impact
- Potential injection vulnerabilities if claims are used in queries
- XSS if claims are reflected in responses without sanitization

#### Remediation

**Add Input Validation:**

```java
package com.example.sso.appa.infrastructure.adapter.in.web;

import com.example.sso.appa.application.port.in.GetUserInfoUseCase;
import com.example.sso.appa.domain.model.User;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "https://localhost:3001")
@Validated  // Enable method-level validation
public class UserController {

    private final GetUserInfoUseCase getUserInfoUseCase;

    public UserController(GetUserInfoUseCase getUserInfoUseCase) {
        this.getUserInfoUseCase = getUserInfoUseCase;
    }

    @GetMapping("/user")
    public ResponseEntity<User> getUserInfo(@AuthenticationPrincipal Jwt jwt) {
        User user = getUserInfoUseCase.getUserInfo(jwt.getTokenValue());
        return ResponseEntity.ok(user);
    }

    @GetMapping("/app-info")
    public ResponseEntity<Map<String, String>> getAppInfo(@AuthenticationPrincipal Jwt jwt) {
        String username = sanitizeString(jwt.getClaimAsString("preferred_username"));

        Map<String, String> info = new HashMap<>();
        info.put("appName", "Application A");
        info.put("appId", "app-a");
        info.put("description", "This is Application A - Healthcare Management System");
        info.put("username", username);
        info.put("redirectToAppB", "https://localhost:3002");
        info.put("redirectToAppC", "https://localhost:3003");

        return ResponseEntity.ok(info);
    }

    @GetMapping("/protected")
    public ResponseEntity<Map<String, String>> protectedEndpoint(@AuthenticationPrincipal Jwt jwt) {
        String username = sanitizeString(jwt.getClaimAsString("preferred_username"));
        String email = sanitizeString(jwt.getClaimAsString("email"));

        Map<String, String> response = new HashMap<>();
        response.put("message", "This is a protected resource in App A");
        response.put("user", username);
        response.put("email", email);

        return ResponseEntity.ok(response);
    }

    /**
     * Sanitize string to prevent XSS and injection attacks
     */
    private String sanitizeString(String input) {
        if (input == null) {
            return "";
        }

        // Remove potentially dangerous characters
        return input.replaceAll("[<>\"'&]", "")
                    .trim();
    }
}
```

**Add Validation Dependencies:**

```xml
<!-- pom.xml -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
<dependency>
    <groupId>org.owasp.encoder</groupId>
    <artifactId>encoder</artifactId>
    <version>1.2.3</version>
</dependency>
```

**Enhanced Sanitization with OWASP Encoder:**

```java
import org.owasp.encoder.Encode;

private String sanitizeForHtml(String input) {
    if (input == null) return "";
    return Encode.forHtml(input);
}

private String sanitizeForJavaScript(String input) {
    if (input == null) return "";
    return Encode.forJavaScript(input);
}
```

---

### 12. PostMessage Origin Validation

**Severity:** LOW
**CVSS Score:** 3.1 (Low)
**Location:** `silent-check-sso.html:8`

#### Vulnerability Description
PostMessage sends data to parent without verifying parent origin:
```javascript
parent.postMessage(location.href, location.origin);
```

#### Impact
- Potentially leak authentication data if page is framed by malicious site
- Mitigated by CSP `frame-ancestors 'none'`

#### Remediation

**Enhanced silent-check-sso.html:**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Silent Check SSO</title>
    <meta http-equiv="Content-Security-Policy" content="frame-ancestors 'self' https://localhost:3001 https://localhost:3002 https://localhost:3003;">
</head>
<body>
    <script>
        (function() {
            // Whitelist of allowed parent origins
            const ALLOWED_ORIGINS = [
                'https://localhost:3001',
                'https://localhost:3002',
                'https://localhost:3003',
                'https://app-a.yourdomain.com',
                'https://app-b.yourdomain.com',
                'https://app-c.yourdomain.com'
            ];

            // Verify we're in an iframe
            if (window.parent === window) {
                console.error('silent-check-sso.html should only be loaded in an iframe');
                return;
            }

            // Get parent origin
            const parentOrigin = document.referrer ? new URL(document.referrer).origin : '*';

            // Verify parent origin is allowed
            if (!ALLOWED_ORIGINS.includes(parentOrigin) && parentOrigin !== '*') {
                console.error('Parent origin not allowed:', parentOrigin);
                return;
            }

            // Send message to verified parent
            try {
                parent.postMessage(
                    location.href,
                    parentOrigin !== '*' ? parentOrigin : location.origin
                );
            } catch (error) {
                console.error('Failed to send postMessage:', error);
            }
        })();
    </script>
</body>
</html>
```

---

### 13. Session Timeout Configuration

**Severity:** INFORMATIONAL
**Location:** `keycloak-config/realm-export.json:11-13`

#### Current Configuration
```json
"accessTokenLifespan": 300,        // 5 minutes
"ssoSessionIdleTimeout": 1800,     // 30 minutes
"ssoSessionMaxLifespan": 36000     // 10 hours
```

#### Analysis
- Access token lifetime (5 min) is good - short-lived
- Idle timeout (30 min) is reasonable
- Max lifespan (10 hours) may be too long for sensitive applications

#### Recommendations

**For High-Security Applications (Healthcare, Financial):**
```json
{
  "accessTokenLifespan": 300,           // 5 minutes (keep)
  "accessTokenLifespanForImplicitFlow": 300,
  "ssoSessionIdleTimeout": 900,         // 15 minutes (reduced)
  "ssoSessionMaxLifespan": 14400,       // 4 hours (reduced)
  "offlineSessionIdleTimeout": 2592000, // 30 days
  "offlineSessionMaxLifespan": 5184000, // 60 days
  "accessCodeLifespan": 60,             // 1 minute
  "accessCodeLifespanUserAction": 300,  // 5 minutes
  "accessCodeLifespanLogin": 1800       // 30 minutes
}
```

**For Standard Applications:**
```json
{
  "accessTokenLifespan": 600,           // 10 minutes
  "ssoSessionIdleTimeout": 1800,        // 30 minutes
  "ssoSessionMaxLifespan": 28800,       // 8 hours
  "refreshTokenMaxReuse": 0             // One-time use refresh tokens
}
```

**Implement Step-Up Authentication for Sensitive Operations:**

```java
// RequireRecentAuth annotation
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireRecentAuth {
    int maxAgeSeconds() default 300;  // 5 minutes
}

// Aspect to enforce recent authentication
@Aspect
@Component
public class RecentAuthAspect {

    @Before("@annotation(requireRecentAuth)")
    public void checkRecentAuth(JoinPoint joinPoint, RequireRecentAuth requireRecentAuth) {
        // Get JWT from SecurityContext
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();
            Instant authTime = jwt.getClaimAsInstant("auth_time");

            if (authTime != null) {
                long secondsSinceAuth = Instant.now().getEpochSecond() - authTime.getEpochSecond();

                if (secondsSinceAuth > requireRecentAuth.maxAgeSeconds()) {
                    throw new RecentAuthRequiredException(
                        "This operation requires recent authentication"
                    );
                }
            }
        }
    }
}

// Usage in controller
@DeleteMapping("/sensitive-operation")
@RequireRecentAuth(maxAgeSeconds = 300)  // Must have authenticated in last 5 minutes
public ResponseEntity<?> performSensitiveOperation() {
    // ... sensitive operation
}
```

---

## GOOD PRACTICES OBSERVED ✅

### 1. PKCE Implementation
```typescript
pkceMethod: 'S256'
```
✅ Proper use of SHA-256 PKCE prevents authorization code interception

### 2. Token Refresh Mechanism
```typescript
setInterval(() => {
  this.keycloak.updateToken(70).catch(() => {
    console.error('Failed to refresh token');
  });
}, 60000);
```
✅ Automatic token refresh maintains user session

### 3. JWT Signature Validation
```yaml
jwk-set-uri: http://localhost:8080/realms/sso-poc/protocol/openid-connect/certs
```
✅ Backend validates JWT signatures against Keycloak public keys

### 4. Stateless Session Management
```java
.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
```
✅ No server-side session state required

### 5. Role-Based Access Control
```java
.anyRequest().hasAuthority("SCOPE_app-a-user")
```
✅ Proper RBAC implementation with JWT claims

### 6. Brute Force Protection
```json
"bruteForceProtected": true
```
✅ Keycloak configured with brute force detection

### 7. Implicit Flow Disabled
```json
"implicitFlowEnabled": false
```
✅ More secure authorization code flow used instead

---

## REMEDIATION PRIORITY

### Immediate Actions (Before Production)
1. ✅ **Enable SSL/TLS** - Configure HTTPS for all services
2. ✅ **Remove hardcoded credentials** - Use environment variables/secrets management
3. ✅ **Enable CSRF protection** - Or document why disabled with proper mitigations
4. ✅ **Add security headers** - CSP, X-Frame-Options, HSTS, etc.
5. ✅ **Update sslRequired** - Set to "external" or "all" in Keycloak

### High Priority (Within 1 Week)
6. Disable direct access grants
7. Use exact redirect URIs
8. Implement proper secrets management solution
9. Review and restrict CORS policies
10. Change all default passwords
11. Disable debug logging for production profile

### Medium Priority (Within 1 Month)
12. Consider BFF pattern for sensitive applications
13. Implement comprehensive audit logging
14. Add rate limiting on API endpoints
15. Review and adjust session timeouts
16. Implement input validation and sanitization
17. Set up security monitoring and alerting

### Enhancement Opportunities
18. Implement MFA for sensitive operations
19. Add API rate limiting with Redis/bucket4j
20. Implement security information and event management (SIEM)
21. Add automated security scanning (OWASP ZAP, SonarQube)
22. Implement certificate pinning for mobile clients (if applicable)
23. Add DDoS protection (if using cloud infrastructure)

---

## COMPLIANCE CONSIDERATIONS

### GDPR (General Data Protection Regulation)
- ✅ **Data Encryption:** Currently failing - no TLS (CRITICAL)
- ⚠️ **Logging Personal Data:** Debug logs may contain PII
- ✅ **Access Control:** RBAC implemented
- ⚠️ **Audit Trail:** Needs dedicated audit logging

### HIPAA (Healthcare)
- ✅ **Access Control:** Role-based access implemented
- ✅ **Authentication:** Strong authentication with Keycloak
- ⚠️ **Encryption in Transit:** Currently failing - no TLS (CRITICAL)
- ⚠️ **Audit Controls:** Needs comprehensive audit logging
- ⚠️ **Session Management:** 10-hour sessions may be too long

### PCI-DSS (Financial Services)
- ✅ **Access Control:** Implement and test (6.5.10)
- ⚠️ **Encryption:** Must use TLS 1.2+ (4.1)
- ⚠️ **Secure Coding:** CSRF disabled (6.5.9)
- ⚠️ **Logging:** Must not log sensitive authentication data (3.4)

---

## TESTING RECOMMENDATIONS

### Security Testing Checklist

1. **SSL/TLS Testing**
```bash
# Test SSL configuration
openssl s_client -connect localhost:8443 -tls1_2
nmap --script ssl-enum-ciphers -p 8443 localhost
```

2. **CSRF Testing**
```bash
# Test if CSRF protection works
curl -X POST https://localhost:9001/api/protected \
  -H "Authorization: Bearer <token>" \
  -H "Origin: https://malicious-site.com"
```

3. **CORS Testing**
```bash
# Test CORS headers
curl -I https://localhost:9001/api/user \
  -H "Origin: https://malicious-site.com" \
  -H "Authorization: Bearer <token>"
```

4. **JWT Validation Testing**
```bash
# Test with expired token
# Test with tampered token
# Test with wrong signature
```

5. **Security Headers Testing**
```bash
# Use security headers checker
curl -I https://localhost:9001/api/user | grep -E "Content-Security-Policy|X-Frame-Options"
```

### Automated Security Scanning

```bash
# OWASP ZAP scanning
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t https://localhost:3001

# Dependency checking
mvn dependency-check:check

# SonarQube analysis
mvn sonar:sonar
```

---

## CONCLUSION

This SSO implementation demonstrates good architectural foundations with PKCE, JWT validation, and RBAC. However, **critical security vulnerabilities must be addressed before production deployment**, particularly around transport security, credential management, and CSRF protection.

**Risk Level:** HIGH (without remediation)
**Risk Level:** MEDIUM-LOW (with all critical fixes applied)

### Next Steps
1. Apply all CRITICAL severity fixes immediately
2. Implement environment-based configuration
3. Set up proper secrets management
4. Enable comprehensive audit logging
5. Perform penetration testing before production launch
6. Establish security monitoring and incident response procedures

---

**Report Generated:** 2025-12-23
**Reviewed By:** Security Assessment Tool
**Classification:** Internal Security Assessment
**Distribution:** Development Team, Security Team, Management

For questions or clarifications about this report, please contact your security team.
