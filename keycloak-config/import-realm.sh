#!/bin/bash

echo "Waiting for Keycloak to be ready..."
until curl -sf http://localhost:8080/health/ready > /dev/null; do
  echo "Keycloak is not ready yet. Waiting..."
  sleep 5
done

echo "Keycloak is ready! Importing realm..."

# Get admin token
ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8080/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')

# Import realm
curl -X POST "http://localhost:8080/admin/realms" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d @/keycloak-config/realm-export.json

echo "Realm import completed!"
