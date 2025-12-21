#!/bin/bash

echo "Setting up RBAC..."

# Get admin token
ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | grep -o '"access_token":"[^"]*' | cut -d'"' -f4)

echo "1. Creating application-specific roles..."

# Create app-a-user role
curl -s -X POST "http://localhost:8080/admin/realms/sso-poc/roles" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "app-a-user", "description": "Access to Application A"}' \
  -w "App A role: %{http_code}\n"

# Create app-b-user role
curl -s -X POST "http://localhost:8080/admin/realms/sso-poc/roles" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "app-b-user", "description": "Access to Application B"}' \
  -w "App B role: %{http_code}\n"

# Create app-c-user role
curl -s -X POST "http://localhost:8080/admin/realms/sso-poc/roles" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "app-c-user", "description": "Access to Application C"}' \
  -w "App C role: %{http_code}\n"

echo "2. Creating user Bob..."

# Create Bob user
curl -s -X POST "http://localhost:8080/admin/realms/sso-poc/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "bob",
    "enabled": true,
    "email": "bob@example.com",
    "firstName": "Bob",
    "lastName": "Smith",
    "credentials": [{
      "type": "password",
      "value": "bob123",
      "temporary": false
    }]
  }' \
  -w "Bob user: %{http_code}\n"

# Get Bob's user ID
sleep 1
BOB_ID=$(curl -s "http://localhost:8080/admin/realms/sso-poc/users?username=bob" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | grep -o '"id":"[^"]*' | head -1 | cut -d'"' -f4)

echo "Bob's ID: $BOB_ID"

# Get role IDs
APP_A_ROLE=$(curl -s "http://localhost:8080/admin/realms/sso-poc/roles/app-a-user" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | grep -o '"id":"[^"]*' | cut -d'"' -f4)

echo "3. Assigning app-a-user role to Bob..."

# Assign app-a-user role to Bob
curl -s -X POST "http://localhost:8080/admin/realms/sso-poc/users/$BOB_ID/role-mappings/realm" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "[{\"id\": \"$APP_A_ROLE\", \"name\": \"app-a-user\"}]" \
  -w "Assign role: %{http_code}\n"

echo "4. Updating existing users with all app roles..."

# Get testuser ID
TESTUSER_ID=$(curl -s "http://localhost:8080/admin/realms/sso-poc/users?username=testuser" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | grep -o '"id":"[^"]*' | head -1 | cut -d'"' -f4)

# Get all role IDs
APP_B_ROLE=$(curl -s "http://localhost:8080/admin/realms/sso-poc/roles/app-b-user" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | grep -o '"id":"[^"]*' | cut -d'"' -f4)

APP_C_ROLE=$(curl -s "http://localhost:8080/admin/realms/sso-poc/roles/app-c-user" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | grep -o '"id":"[^"]*' | cut -d'"' -f4)

# Assign all app roles to testuser
curl -s -X POST "http://localhost:8080/admin/realms/sso-poc/users/$TESTUSER_ID/role-mappings/realm" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "[
    {\"id\": \"$APP_A_ROLE\", \"name\": \"app-a-user\"},
    {\"id\": \"$APP_B_ROLE\", \"name\": \"app-b-user\"},
    {\"id\": \"$APP_C_ROLE\", \"name\": \"app-c-user\"}
  ]" \
  -w "Assign all roles to testuser: %{http_code}\n"

echo ""
echo "RBAC Setup Complete!"
echo "===================="
echo "Roles created: app-a-user, app-b-user, app-c-user"
echo "User Bob: username=bob, password=bob123 (access to App A only)"
echo "User testuser: has access to all applications"
