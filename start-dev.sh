#!/bin/bash
# Development script for LibreChat with HTTPS bypass for Keycloak

echo "🚀 Starting LibreChat in development mode with SSL bypass..."
echo "⚠️  WARNING: This disables SSL verification - ONLY for development!"

# Disable SSL verification for development
export NODE_TLS_REJECT_UNAUTHORIZED=0

# Start LibreChat
npm run backend:dev