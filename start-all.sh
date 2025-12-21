#!/bin/bash

echo "=========================================="
echo "Starting SSO POC - All Applications"
echo "=========================================="
echo ""

# Start Keycloak
echo "1. Starting Keycloak..."
docker compose up -d

echo "   Waiting for Keycloak to be ready..."
sleep 15

# Check if Keycloak is ready
until curl -sf http://localhost:8080/health/ready > /dev/null; do
  echo "   Keycloak is not ready yet. Waiting..."
  sleep 5
done

echo "   Keycloak is ready!"
echo ""

# Import realm
echo "2. Importing Keycloak realm configuration..."
if command -v jq &> /dev/null; then
  chmod +x keycloak-config/import-realm.sh
  ./keycloak-config/import-realm.sh
else
  echo "   Warning: jq is not installed. Please import realm manually."
  echo "   Visit http://localhost:8080 and import keycloak-config/realm-export.json"
fi
echo ""

# Start backends
echo "3. Starting Spring Boot backends..."
echo "   Note: This will take a few minutes..."

cd app-a-backend
echo "   Building and starting App A backend..."
mvn clean install -q && mvn spring-boot:run > ../logs/app-a-backend.log 2>&1 &
APP_A_PID=$!
cd ..

cd app-b-backend
echo "   Building and starting App B backend..."
mvn clean install -q && mvn spring-boot:run > ../logs/app-b-backend.log 2>&1 &
APP_B_PID=$!
cd ..

cd app-c-backend
echo "   Building and starting App C backend..."
mvn clean install -q && mvn spring-boot:run > ../logs/app-c-backend.log 2>&1 &
APP_C_PID=$!
cd ..

echo "   Backends are starting in background..."
echo "   Check logs in the 'logs' directory for details"
echo ""

# Start frontends
echo "4. Starting React frontends..."

cd app-a-frontend
if [ ! -d "node_modules" ]; then
  echo "   Installing dependencies for App A frontend..."
  npm install -q
fi
echo "   Starting App A frontend..."
npm start > ../logs/app-a-frontend.log 2>&1 &
cd ..

cd app-b-frontend
if [ ! -d "node_modules" ]; then
  echo "   Installing dependencies for App B frontend..."
  npm install -q
fi
echo "   Starting App B frontend..."
npm start > ../logs/app-b-frontend.log 2>&1 &
cd ..

cd app-c-frontend
if [ ! -d "node_modules" ]; then
  echo "   Installing dependencies for App C frontend..."
  npm install -q
fi
echo "   Starting App C frontend..."
npm start > ../logs/app-c-frontend.log 2>&1 &
cd ..

echo ""
echo "=========================================="
echo "All applications are starting!"
echo "=========================================="
echo ""
echo "Access URLs:"
echo "  - Keycloak Admin:  http://localhost:8080 (admin/admin)"
echo "  - Application A:   http://localhost:3001"
echo "  - Application B:   http://localhost:3002"
echo "  - Application C:   http://localhost:3003"
echo ""
echo "Test Credentials:"
echo "  - Username: testuser"
echo "  - Password: password"
echo ""
echo "Logs are available in the 'logs' directory"
echo ""
echo "To stop all applications, run: ./stop-all.sh"
echo "=========================================="
