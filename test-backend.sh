#!/bin/bash

echo "Getting access token for testuser..."
TOKEN=$(curl -s -X POST "http://localhost:8080/realms/sso-poc/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser" \
  -d "password=password" \
  -d "grant_type=password" \
  -d "client_id=app-a" | jq -r '.access_token')

echo "Token received: ${TOKEN:0:50}..."
echo ""

echo "Testing /api/user endpoint..."
curl -s -X GET "http://localhost:9001/api/user" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" | jq '.'

echo ""
echo "Testing /api/app-info endpoint..."
curl -s -X GET "http://localhost:9001/api/app-info" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" | jq '.'
