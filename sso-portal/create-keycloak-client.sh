#!/bin/bash

# Create SSO Portal client in Keycloak
# This client will be PUBLIC since it's a browser-based SPA

echo "Creating SSO Portal client in Keycloak..."

# Get admin token
TOKEN=$(curl -s -X POST \
  "https://dev.bizneuron.local/auth/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  --insecure | jq -r '.access_token')

if [ -z "$TOKEN" ]; then
    echo "Failed to get admin token"
    exit 1
fi

# Create the SSO Portal client
curl -X POST \
  "https://dev.bizneuron.local/auth/admin/realms/bizneuron/clients" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  --insecure \
  -d '{
    "clientId": "sso-portal",
    "name": "SSO Portal",
    "description": "Single Sign-On Portal for all BizNeuron applications",
    "rootUrl": "https://dev.bizneuron.local",
    "baseUrl": "/sso-portal",
    "adminUrl": "",
    "enabled": true,
    "publicClient": true,
    "standardFlowEnabled": true,
    "implicitFlowEnabled": false,
    "directAccessGrantsEnabled": false,
    "redirectUris": [
      "https://dev.bizneuron.local/sso-portal/*",
      "https://dev.bizneuron.local/*"
    ],
    "webOrigins": [
      "https://dev.bizneuron.local"
    ],
    "protocol": "openid-connect",
    "attributes": {
      "pkce.code.challenge.method": "S256",
      "post.logout.redirect.uris": "+",
      "display.on.consent.screen": "false",
      "oauth2.device.authorization.grant.enabled": "false",
      "backchannel.logout.session.required": "true",
      "backchannel.logout.revoke.offline.tokens": "false"
    },
    "authenticationFlowBindingOverrides": {},
    "fullScopeAllowed": true,
    "nodeReRegistrationTimeout": -1,
    "defaultClientScopes": [
      "web-origins",
      "acr",
      "roles",
      "profile",
      "email"
    ],
    "optionalClientScopes": [
      "address",
      "phone",
      "offline_access",
      "microprofile-jwt"
    ]
  }'

echo ""
echo "SSO Portal client created successfully!"
echo ""
echo "Configuration:"
echo "- Client ID: sso-portal"
echo "- Type: Public (browser-based)"
echo "- Redirect URIs: https://dev.bizneuron.local/sso-portal/*"
echo "- PKCE enabled for security"
echo ""
echo "Next steps:"
echo "1. Add nginx configuration to serve /sso-portal"
echo "2. Test the SSO Portal at https://dev.bizneuron.local/sso-portal/"