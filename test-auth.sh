#!/bin/bash

echo "Testing authentication for testuser..."
curl -s -X POST "http://localhost:8080/realms/sso-poc/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser" \
  -d "password=password" \
  -d "grant_type=password" \
  -d "client_id=app-a" | jq '.'

echo ""
echo "Testing authentication for bob..."
curl -s -X POST "http://localhost:8080/realms/sso-poc/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=bob" \
  -d "password=bob123" \
  -d "grant_type=password" \
  -d "client_id=app-a" | jq '.'
