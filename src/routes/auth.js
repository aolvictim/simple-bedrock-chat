const express = require('express');
const crypto = require('crypto');
const router = express.Router();

// Store OAuth state in memory
const oauthStates = new Map();

// Helper function to generate secure random string
function generateSecureRandomString() {
  return crypto.randomBytes(32).toString('hex');
}

// Helper function to decode JWT
function decodeJWT(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(base64, 'base64').toString());
  } catch (error) {
    console.error('Error decoding JWT:', error);
    return null;
  }
}

// Login route
router.get('/login', (req, res) => {
  // Generate state and store with timestamp
  const state = generateSecureRandomString();
  const nonce = generateSecureRandomString();
  const codeVerifier = generateSecureRandomString();
  const codeChallenge = crypto.createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  // Store OAuth values with 5 minute expiry
  oauthStates.set(state, {
    nonce,
    codeVerifier,
    timestamp: Date.now()
  });

  // Clean up expired states
  for (const [storedState, data] of oauthStates.entries()) {
    if (Date.now() - data.timestamp > 5 * 60 * 1000) {
      oauthStates.delete(storedState);
    }
  }

  const authUrl = new URL(process.env.AUTH_URL);
  authUrl.searchParams.append('client_id', process.env.CLIENT_ID);
  authUrl.searchParams.append('code_challenge', codeChallenge);
  authUrl.searchParams.append('code_challenge_method', 'S256');
  authUrl.searchParams.append('nonce', nonce);
  authUrl.searchParams.append('redirect_uri', process.env.REDIRECT_URI);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('state', state);
  authUrl.searchParams.append('scope', process.env.AUTH_SCOPE || 'openid profile company email offline_access');
  
  res.redirect(authUrl.toString());
});

// Callback route
router.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  // Get and validate stored state
  const storedData = oauthStates.get(state);
  if (!storedData) {
    return res.status(400).send('Invalid or expired state');
  }

  // Clean up used state
  oauthStates.delete(state);

  try {
    const tokenResponse = await fetch(process.env.TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: process.env.CLIENT_ID,
        code_verifier: storedData.codeVerifier,
        code: code,
        redirect_uri: process.env.REDIRECT_URI
      })
    });

    if (!tokenResponse.ok) {
      throw new Error('Token exchange failed');
    }

    const tokens = await tokenResponse.json();
    
    // Decode tokens to get claims
    const idTokenClaims = decodeJWT(tokens.id_token);
    const accessTokenClaims = decodeJWT(tokens.access_token);
    
    // Format tokens in the new structure
    const tokenData = {
      idToken: {
        idToken: tokens.id_token,
        claims: idTokenClaims,
        expiresAt: idTokenClaims?.exp,
        authorizeUrl: process.env.AUTH_URL,
        issuer: idTokenClaims?.iss || process.env.ISSUER_URL,
        clientId: process.env.CLIENT_ID
      },
      accessToken: {
        accessToken: tokens.access_token,
        claims: accessTokenClaims
      },
      refreshToken: tokens.refresh_token
    };

    res.send(`
      <script>
        localStorage.setItem('tokens', '${JSON.stringify(tokenData)}');
        window.location.href = '/';
      </script>
    `);
  } catch (error) {
    console.error('Auth callback error:', error);
    res.status(500).send('Authentication failed');
  }
});

// Refresh token route
router.post('/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) {
    return res.status(400).json({ error: 'Refresh token required' });
  }

  try {
    const tokenResponse = await fetch(process.env.TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: process.env.CLIENT_ID,
        refresh_token: refresh_token
      })
    });

    if (!tokenResponse.ok) {
      throw new Error('Token refresh failed');
    }

    const tokens = await tokenResponse.json();
    
    // Decode tokens to get claims
    const idTokenClaims = decodeJWT(tokens.id_token);
    const accessTokenClaims = decodeJWT(tokens.access_token);
    
    // Format tokens in the new structure
    const tokenData = {
      idToken: {
        idToken: tokens.id_token,
        claims: idTokenClaims,
        expiresAt: idTokenClaims?.exp,
        authorizeUrl: process.env.AUTH_URL,
        issuer: idTokenClaims?.iss || process.env.ISSUER_URL,
        clientId: process.env.CLIENT_ID
      },
      accessToken: {
        accessToken: tokens.access_token,
        claims: accessTokenClaims
      },
      refreshToken: tokens.refresh_token
    };

    res.json(tokenData);
  } catch (error) {
    console.error('Token refresh error:', error);
    res.status(401).json({ error: 'Token refresh failed' });
  }
});

// Logout route
router.get('/logout', (req, res) => {
  res.redirect('/');
});

module.exports = router; 