#!/bin/bash

echo "=========================================="
echo "Stopping SSO POC - All Applications"
echo "=========================================="
echo ""

# Stop frontends
echo "1. Stopping React frontends..."
pkill -f "react-scripts start" || echo "   No React processes found"
echo ""

# Stop backends
echo "2. Stopping Spring Boot backends..."
pkill -f "spring-boot:run" || echo "   No Spring Boot processes found"
echo ""

# Stop Keycloak
echo "3. Stopping Keycloak..."
docker compose down
echo ""

echo "=========================================="
echo "All applications stopped!"
echo "=========================================="
echo ""
echo "To restart, run: ./start-all.sh"
echo "=========================================="
