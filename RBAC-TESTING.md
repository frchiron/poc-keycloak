# Role-Based Access Control (RBAC) Testing Guide

## Overview

This POC now implements role-based access control where different users have access to different applications based on their assigned roles.

## Roles Structure

| Role | Description | Applications Access |
|------|-------------|---------------------|
| `app-a-user` | Access to Application A | Healthcare Management System |
| `app-b-user` | Access to Application B | Financial Services Platform |
| `app-c-user` | Access to Application C | Supply Chain Management |

## Test Users

### 1. Bob (Limited Access)
- **Username**: `bob`
- **Password**: `bob123`
- **Roles**: `app-a-user`
- **Access**:
  - ✅ Application A (Healthcare)
  - ❌ Application B (Financial) - **ACCESS DENIED**
  - ❌ Application C (Supply Chain) - **ACCESS DENIED**

### 2. Testuser (Full Access)
- **Username**: `testuser`
- **Password**: `password`
- **Roles**: `app-a-user`, `app-b-user`, `app-c-user`
- **Access**:
  - ✅ Application A
  - ✅ Application B
  - ✅ Application C

### 3. Admin (Full Access)
- **Username**: `admin`
- **Password**: `admin`
- **Roles**: `admin`, `user` (legacy roles, needs update for app-specific access)
- **Note**: May need app-specific roles assigned

## Testing Scenarios

### Scenario 1: Bob Accesses Application A (Success)

1. Open http://localhost:3001
2. Click "Login with SSO"
3. Enter credentials: `bob` / `bob123`
4. ✅ **Expected**: Bob successfully logs in and sees App A dashboard

### Scenario 2: Bob Tries to Access Application B (Denied)

#### Method 1: Direct Navigation
1. Login to App A as Bob
2. Try to navigate to http://localhost:3002
3. ❌ **Expected**: "Access Denied" page showing:
   - 🚫 Icon
   - Message: "Sorry **bob**, you don't have permission to access Application B"
   - Options to Logout or Go to Application A

#### Method 2: Using Navigation Buttons
1. Login to App A as Bob
2. Click "Go to Application B" button
3. ❌ **Expected**: Same "Access Denied" page

### Scenario 3: Bob Tries to Access Application C (Denied)

1. Login to App A as Bob
2. Try to navigate to http://localhost:3003
3. ❌ **Expected**: "Access Denied" page for Application C

### Scenario 4: Testuser Has Full Access

1. Open http://localhost:3001
2. Login as: `testuser` / `password`
3. ✅ Navigate to App B - **Success**
4. ✅ Navigate to App C - **Success**
5. ✅ Navigate back to App A - **Success**

## How RBAC Works

### Backend Authorization

Each backend enforces role-based access:

```java
// App A requires app-a-user role
.anyRequest().hasAuthority("SCOPE_app-a-user")

// App B requires app-b-user role
.anyRequest().hasAuthority("SCOPE_app-b-user")

// App C requires app-c-user role
.anyRequest().hasAuthority("SCOPE_app-c-user")
```

### JWT Token Claims

When a user logs in, their JWT token contains roles in the `realm_access.roles` claim:

```json
{
  "realm_access": {
    "roles": ["app-a-user", "app-b-user", "app-c-user"]
  }
}
```

### Role Extraction

The `JwtAuthenticationConverter` extracts roles from the token and converts them to Spring Security authorities with the `SCOPE_` prefix.

### Frontend Handling

Frontends detect 403 Forbidden responses and display a user-friendly "Access Denied" page instead of errors.

## Adding More Users

To create additional users with specific roles:

```bash
# 1. Get admin token
ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin&grant_type=password&client_id=admin-cli" \
  | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

# 2. Create user
curl -X POST "http://localhost:8080/admin/realms/sso-poc/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "enabled": true,
    "email": "alice@example.com",
    "credentials": [{"type": "password", "value": "alice123", "temporary": false}]
  }'

# 3. Get user ID
ALICE_ID=$(curl -s "http://localhost:8080/admin/realms/sso-poc/users?username=alice" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | grep -o '"id":"[^"]*' | head -1 | cut -d'"' -f4)

# 4. Get role ID
ROLE_ID=$(curl -s "http://localhost:8080/admin/realms/sso-poc/roles/app-b-user" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | grep -o '"id":"[^"]*' | cut -d'"' -f4)

# 5. Assign role
curl -X POST "http://localhost:8080/admin/realms/sso-poc/users/$ALICE_ID/role-mappings/realm" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "[{\"id\": \"$ROLE_ID\", \"name\": \"app-b-user\"}]"
```

## Troubleshooting

### Bob can access Application B
- Verify Bob's roles in Keycloak Admin Console
- Check backend logs for authorization errors
- Ensure backends have been restarted after configuration changes

### Access Denied page not showing
- Check browser console for errors
- Verify frontend code has been updated
- Clear browser cache and reload

### JWT token doesn't contain roles
- Check Keycloak client configuration
- Verify realm roles are assigned to user
- Check JWT token in browser developer tools (Application → Local Storage)

## Architecture

```
User Login → Keycloak assigns roles → JWT contains roles
     ↓
Frontend requests API → Backend validates JWT → Checks required role
     ↓
Role Match? → ✅ Allow access | ❌ Return 403 Forbidden
     ↓
Frontend: 403 detected → Display AccessDenied page
```

## Security Best Practices

1. **Principle of Least Privilege**: Users only get roles they need
2. **Token-Based**: Stateless authentication, roles in JWT
3. **Backend Enforcement**: Authorization is enforced at the API level
4. **User-Friendly**: Clear error messages for access denied scenarios
5. **Audit Trail**: All access attempts logged in backend

## Next Steps

To extend RBAC further:

1. **Fine-grained permissions**: Add endpoint-level authorization
2. **Role hierarchy**: Create admin roles with access to all apps
3. **Dynamic roles**: Allow role assignment via UI
4. **Audit logging**: Track all authorization decisions
5. **Custom claims**: Add additional user metadata to tokens
