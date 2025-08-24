/**
 * Token Exchange Manager for LibreChat Custom Endpoints
 * 
 * Simplified version that extracts OIDC tokens from session and passes them
 * directly to our API without complex Token Exchange flow.
 * 
 * Required environment variables:
 * - ENABLE_TOKEN_EXCHANGE_FOR_CUSTOM=true - Enable token passing for custom endpoints
 * - OPENID_REUSE_TOKENS=true - Required for OIDC token reuse
 * - OPENID_ISSUER - OIDC issuer URL for session key extraction
 */

class TokenExchangeManager {
  constructor() {
    // Configuration from environment
    this.enabled = process.env.ENABLE_TOKEN_EXCHANGE_FOR_CUSTOM === 'true';
    this.openidReuseEnabled = process.env.OPENID_REUSE_TOKENS === 'true';
    this.openidIssuer = process.env.OPENID_ISSUER;
    
    // Keycloak configuration for token refresh
    this.keycloakUrl = process.env.KEYCLOAK_URL || 'http://keycloak:8080';
    this.keycloakRealm = process.env.KEYCLOAK_REALM || 'bizneuron';
    this.clientId = process.env.OPENID_CLIENT_ID;
    this.clientSecret = process.env.OPENID_CLIENT_SECRET;
    
    // Token cache (Map with expiration)
    this.tokenCache = new Map();
    
    if (this.enabled) {
      console.info('[TokenExchangeManager] Token exchange enabled for custom endpoints');
      
      if (!this.openidReuseEnabled) {
        console.warn('[TokenExchangeManager] OPENID_REUSE_TOKENS is not enabled, token exchange will not work');
      }
      
      if (!this.openidIssuer) {
        console.warn('[TokenExchangeManager] OPENID_ISSUER not configured, token extraction may fail');
      }
      
      if (!this.clientId || !this.clientSecret) {
        console.warn('[TokenExchangeManager] Missing OPENID_CLIENT_ID or OPENID_CLIENT_SECRET for token refresh');
      }
    }
  }

  /**
   * Check if token exchange is enabled and properly configured
   * @returns {boolean} True if token exchange is enabled
   */
  isEnabled() {
    return this.enabled && this.openidReuseEnabled;
  }

  /**
   * Extract user access token from request
   * LibreChat stores OIDC tokens in cookies when OPENID_REUSE_TOKENS is true
   * @param {Object} req - Express request object
   * @returns {Object} Object with accessToken and refreshToken
   */
  extractUserTokens(req) {
    console.debug('[TokenExchangeManager] Extracting user tokens from request');
    
    // Debug: log what's in req.user
    if (req.user) {
      const userKeys = Object.keys(req.user);
      console.debug('[TokenExchangeManager] req.user exists, keys:', JSON.stringify(userKeys));
      console.debug('[TokenExchangeManager] req.user.provider:', req.user.provider);
      console.debug('[TokenExchangeManager] req.user._id:', req.user._id);
      console.debug('[TokenExchangeManager] req.user.id:', req.user.id);
      
      // Check if user is a Mongoose document
      if (req.user.toObject) {
        const plainUser = req.user.toObject();
        console.debug('[TokenExchangeManager] Plain user keys:', JSON.stringify(Object.keys(plainUser)));
      }
    }
    
    // Strategy 1: Check if user object has tokenset (from passport authentication)
    if (req.user && req.user.tokenset) {
      console.debug('[TokenExchangeManager] Found tokenset in req.user');
      return this.extractTokensFromSession(req.user.tokenset);
    }
    
    // Strategy 2: Try to extract from cookies (when OPENID_REUSE_TOKENS is enabled)
    if (req.cookies) {
      console.debug('[TokenExchangeManager] Available cookies:', JSON.stringify(Object.keys(req.cookies)));
      
      // LibreChat stores refresh token in cookies
      const refreshToken = req.cookies.refreshToken;
      const tokenProvider = req.cookies.token_provider;
      
      console.debug('[TokenExchangeManager] refreshToken present:', !!refreshToken);
      console.debug('[TokenExchangeManager] token_provider:', tokenProvider);
      
      if (refreshToken && tokenProvider === 'openid') {
        console.debug('[TokenExchangeManager] Found OIDC refresh token in cookies, will exchange for access token');
        // Return refresh token, it will be exchanged for access token in getApiTokenForRequest
        return { accessToken: null, refreshToken };
      }
      
      // Check for other token formats
      const token = req.cookies.token;
      if (token && this.looksLikeJWT(token)) {
        console.debug('[TokenExchangeManager] Found JWT token in cookies');
        return { accessToken: token, refreshToken };
      }
    }
    
    // Strategy 3: Check session (fallback for compatibility)
    if (req.session && this.openidIssuer) {
      console.debug('[TokenExchangeManager] Session keys:', Object.keys(req.session));
      
      let issuerHost;
      try {
        const issuerUrl = new URL(this.openidIssuer);
        issuerHost = issuerUrl.host;
        console.debug('[TokenExchangeManager] Looking for tokens under issuer host:', issuerHost);
      } catch (e) {
        console.error('[TokenExchangeManager] Invalid OPENID_ISSUER URL:', this.openidIssuer, e);
        return { accessToken: null, refreshToken: null };
      }
      
      const oidcSession = req.session[issuerHost];
      if (oidcSession) {
        console.debug('[TokenExchangeManager] Found OIDC session');
        return this.extractTokensFromSession(oidcSession);
      }
    }
    
    console.debug('[TokenExchangeManager] No tokens found in request');
    return { accessToken: null, refreshToken: null };
  }
  
  /**
   * Check if a string looks like a JWT
   * @private
   */
  looksLikeJWT(token) {
    if (!token || typeof token !== 'string') {
      return false;
    }
    
    // JWTs have 3 parts separated by dots
    const parts = token.split('.');
    if (parts.length !== 3) {
      return false;
    }
    
    // API keys typically have prefixes
    const apiKeyPrefixes = ['sk-', 'pk-', 'api-', 'key-', 'org_'];
    for (const prefix of apiKeyPrefixes) {
      if (token.toLowerCase().startsWith(prefix)) {
        return false;
      }
    }
    
    // Check if parts are base64-like
    const base64Regex = /^[A-Za-z0-9_-]+$/;
    return parts.every(part => base64Regex.test(part));
  }

  /**
   * Extract tokens from OIDC session object
   * @private
   */
  extractTokensFromSession(oidcSession) {
    let accessToken = null;
    let refreshToken = null;
    
    // Debug: log the structure of oidcSession
    console.debug('[TokenExchangeManager] OIDC session structure:', JSON.stringify(Object.keys(oidcSession || {})));
    
    // If oidcSession is actually a tokenset object itself
    if (oidcSession && oidcSession.access_token) {
      accessToken = oidcSession.access_token;
      refreshToken = oidcSession.refresh_token;
      console.debug('[TokenExchangeManager] Found tokens directly in OIDC session object');
    }
    // Tokens might be in nested tokenset object
    else if (oidcSession && oidcSession.tokenset) {
      console.debug('[TokenExchangeManager] Found tokenset property, keys:', JSON.stringify(Object.keys(oidcSession.tokenset)));
      accessToken = oidcSession.tokenset.access_token;
      refreshToken = oidcSession.tokenset.refresh_token;
      
      // Check token expiration
      const expiresAt = oidcSession.tokenset.expires_at;
      if (expiresAt && expiresAt < Date.now() / 1000) {
        console.warn('[TokenExchangeManager] OIDC access token expired');
        // Could trigger refresh here in future
        return { accessToken: null, refreshToken };
      }
      
      console.debug('[TokenExchangeManager] Found tokenset in OIDC session');
    }
    
    if (accessToken) {
      console.debug('[TokenExchangeManager] Successfully extracted access token from session');
    } else {
      console.debug('[TokenExchangeManager] No access_token found in OIDC session');
    }
    
    return { accessToken, refreshToken };
  }

  /**
   * Check if a baseURL belongs to our API
   * @param {string} baseURL - The base URL to check
   * @returns {boolean} True if this is our API endpoint
   */
  isOurAPI(baseURL) {
    if (!baseURL) return false;
    
    try {
      const url = new URL(baseURL);
      const host = url.host.toLowerCase();
      
      // Get allowed hosts from env variable or use defaults
      
      
      const isAllowed = allowedHosts.includes(host);
      
      if (!isAllowed) {
        console.debug(`[TokenExchangeManager] Host ${host} not in allowed list: ${allowedHosts.join(', ')}`);
      }
      
      return isAllowed;
    } catch (error) {
      console.error('[TokenExchangeManager] Invalid URL:', baseURL, error);
      return false;
    }
  }

  /**
   * Exchange refresh token for access token using Keycloak token endpoint
   * @param {string} refreshToken - The refresh token
   * @param {string} userId - User ID for caching
   * @returns {Promise<string|null>} The access token or null if exchange fails
   */
  async exchangeRefreshTokenForAccessToken(refreshToken, userId) {
    if (!refreshToken || !this.clientId || !this.clientSecret) {
      console.error('[TokenExchangeManager] Cannot refresh token: missing refresh token or client credentials');
      return null;
    }
    
    // Check cache first
    const cacheKey = `refresh:${userId}`;
    const cached = this.tokenCache.get(cacheKey);
    if (cached && cached.expiresAt > Date.now()) {
      console.debug('[TokenExchangeManager] Using cached access token');
      return cached.token;
    }
    
    try {
      // Use internal Keycloak URL for server-side requests
      const tokenEndpoint = `${this.keycloakUrl}/realms/${this.keycloakRealm}/protocol/openid-connect/token`;
      console.debug('[TokenExchangeManager] Token endpoint:', tokenEndpoint);
      
      // Prepare token refresh request
      const params = new URLSearchParams();
      params.append('grant_type', 'refresh_token');
      params.append('refresh_token', refreshToken);
      params.append('client_id', this.clientId);
      params.append('client_secret', this.clientSecret);
      
      // Use undici for consistency with openidStrategy.js
      const undici = require('undici');
      const response = await undici.fetch(tokenEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params.toString(),
      });
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error('[TokenExchangeManager] Token refresh failed:', response.status, errorText);
        return null;
      }
      
      const tokenData = await response.json();
      console.debug('[TokenExchangeManager] Successfully refreshed token');
      
      // Decode token to check audience (for debugging)
      try {
        const tokenParts = tokenData.access_token.split('.');
        if (tokenParts.length === 3) {
          const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
          console.debug('[TokenExchangeManager] Token claims - aud:', payload.aud, 'azp:', payload.azp, 'iss:', payload.iss);
        }
      } catch (e) {
        console.debug('[TokenExchangeManager] Could not decode token for debugging');
      }
      
      // Cache the token for 4 minutes (assuming 5 min expiry)
      this.tokenCache.set(cacheKey, {
        token: tokenData.access_token,
        expiresAt: Date.now() + (4 * 60 * 1000) // 4 minutes
      });
      
      return tokenData.access_token;
    } catch (error) {
      console.error('[TokenExchangeManager] Failed to exchange refresh token:', error);
      return null;
    }
  }

  /**
   * Get appropriate API token for custom endpoint
   * @param {Object} req - Express request object
   * @param {string} defaultApiKey - Default API key from configuration
   * @param {string} baseURL - Base URL of the endpoint (optional, for checking if it's our API)
   * @returns {Promise<string>} API token (OIDC token or default API key)
   */
  async getApiTokenForRequest(req, defaultApiKey, baseURL = null) {
    // If token exchange is not enabled, use default API key
    if (!this.isEnabled()) {
      console.debug('[TokenExchangeManager] Token exchange not enabled, using default API key');
      return defaultApiKey;
    }
    
    // Optionally check if this is our API (can be called without baseURL for backward compatibility)
    if (baseURL && !this.isOurAPI(baseURL)) {
      console.debug('[TokenExchangeManager] Not our API endpoint, using default API key');
      return defaultApiKey;
    }
    
    // Try to extract user tokens from session
    const { accessToken, refreshToken } = this.extractUserTokens(req);
    
    // If we have an access token, use it
    if (accessToken) {
      console.info('[TokenExchangeManager] Using OIDC access token for API request');
      return accessToken;
    }
    
    // If we have a refresh token, exchange it for access token
    if (refreshToken && req.user && req.user.id) {
      console.info('[TokenExchangeManager] Found refresh token, exchanging for access token');
      
      const newAccessToken = await this.exchangeRefreshTokenForAccessToken(refreshToken, req.user.id);
      if (newAccessToken) {
        console.info('[TokenExchangeManager] Successfully obtained access token via refresh');
        // Log first 50 chars of token for debugging (safe to log beginning)
        console.debug('[TokenExchangeManager] Token preview:', newAccessToken.substring(0, 50) + '...');
        return newAccessToken;
      } else {
        console.warn('[TokenExchangeManager] Failed to refresh token, falling back to default API key');
      }
    }
    
    console.debug('[TokenExchangeManager] No OIDC tokens available, using default API key');
    return defaultApiKey;
  }
}

// Export singleton instance
module.exports = new TokenExchangeManager();