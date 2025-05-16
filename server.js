// Simple Express backend to proxy Amazon Bedrock requests
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const session = require('express-session');
const path = require('path');
const { BedrockRuntimeClient, InvokeModelWithResponseStreamCommand } = require('@aws-sdk/client-bedrock-runtime');

// Configure AWS and initialize express
const bedrock = new BedrockRuntimeClient({ region: process.env.AWS_REGION || 'us-east-1' });
const app = express();

app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'default-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Set to true in production with HTTPS
}));

// Serve index.html at root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Helper function to generate secure random string
function generateSecureRandomString(length = 64) {
  return crypto.randomBytes(length)
    .toString('base64url')
    .slice(0, length);
}

// Helper function to decode JWT without verification
function decodeJWT(token) {
  if (!token) return null;
  try {
    const base64Payload = token.split('.')[1];
    const payload = Buffer.from(base64Payload, 'base64').toString('utf8');
    return JSON.parse(payload);
  } catch (error) {
    console.error('Error decoding JWT:', error);
    return null;
  }
}

// Auth middleware
function requireAuth(req, res, next) {
  // Check for token in Authorization header or query parameter
  const authHeader = req.headers.authorization;
  const queryToken = req.query.token;
  
  let token;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (queryToken) {
    token = queryToken;
  }

  if (!token) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  req.token = token;
  next();
}

// Auth routes
app.get('/auth/login', (req, res) => {
  // Generate and store state for CSRF protection
  const state = generateSecureRandomString();
  req.session.oauth_state = state;
  
  // Generate nonce
  const nonce = generateSecureRandomString();
  req.session.oauth_nonce = nonce;
  
  // Generate code verifier and challenge for PKCE
  const codeVerifier = generateSecureRandomString();
  const codeChallenge = crypto.createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  req.session.code_verifier = codeVerifier;

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

app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;

  // Verify state to prevent CSRF
  if (state !== req.session.oauth_state) {
    return res.status(400).send('Invalid state');
  }

  try {
    // Exchange code for token
    const tokenResponse = await fetch(process.env.TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: process.env.CLIENT_ID,
        code_verifier: req.session.code_verifier,
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

    // Return tokens to frontend
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

app.get('/auth/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

// Store conversation history in memory
const conversations = new Map();

// Helper function to extract user context from JWT
function getUserContext(token) {
  try {
    const claims = decodeJWT(token);
    return {
      name: `${claims['loupe://profile/first_names']} ${claims['loupe://profile/last_name']}`,
      roles: claims['loupe://profile/role'] || [],
      companyId: claims['loupe://company/id'],
      companyType: claims['loupe://company/type'],
      subscription: claims['loupe://company/subscription']
    };
  } catch (error) {
    console.error('Error getting user context:', error);
    return null;
  }
}

// Helper function to create message body with history
const createMessageBody = (message, conversationId, userProfile, companyProfile) => {
  const history = conversations.get(conversationId) || [];
  
  // Create detailed context with full profile data
  const contextMessage = `
Context: You are chatting with a user who has the following details:

User Profile:
${JSON.stringify(userProfile, null, 2)}

Company Profile:
${JSON.stringify(companyProfile, null, 2)}

User message: `;

  const messages = [
    ...history,
    {
      role: "user",
      content: [{ 
        type: "text", 
        text: contextMessage + message 
      }]
    }
  ];
  return {
    anthropic_version: "bedrock-2023-05-31",
    max_tokens: 1000,
    messages
  };
};

// Helper function to update conversation history
const updateConversationHistory = (conversationId, userMessage, assistantMessage) => {
  const history = conversations.get(conversationId) || [];
  history.push(
    { role: "user", content: [{ type: "text", text: userMessage }] },
    { role: "assistant", content: [{ type: "text", text: assistantMessage }] }
  );
  conversations.set(conversationId, history);
};

// Helper function to fetch profiles
async function fetchProfiles(token) {
  try {
    const [userResponse, companyResponse] = await Promise.all([
      fetch('https://enterprise.ft3.atelierclient.com/api/UserProfiles', {
        headers: { 'Authorization': `Bearer ${token}` }
      }),
      fetch('https://enterprise.ft3.atelierclient.com/index.php?route=atelier_enterprise_api/company/init', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
    ]);

    if (!userResponse.ok || !companyResponse.ok) {
      // If either request fails with 401, return that status
      if (userResponse.status === 401 || companyResponse.status === 401) {
        throw { status: 401, message: 'Unauthorized' };
      }
      throw new Error('Failed to fetch profiles');
    }

    const userProfile = await userResponse.json();
    const companyProfile = await companyResponse.json();

    return {
      userProfile: userProfile.value,
      companyProfile
    };
  } catch (error) {
    // Pass through 401 errors
    if (error.status === 401) {
      throw error;
    }
    console.error('Error fetching profiles:', error);
    return { userProfile: {}, companyProfile: {} };
  }
}

// Protected chat endpoints
app.post('/chat', requireAuth, async (req, res) => {
  const userMessage = req.body.message;

  try {
    const { userProfile, companyProfile } = await fetchProfiles(req.token);
    
    const body = JSON.stringify(createMessageBody(userMessage, 'default', userProfile, companyProfile));
    const response = await bedrock.invokeModel({
      modelId: 'anthropic.claude-3-5-sonnet-20240620-v1:0',
      contentType: 'application/json',
      accept: 'application/json',
      body: body
    }).promise();

    const responseBody = JSON.parse(response.body.toString());
    res.json(responseBody);
  } catch (error) {
    console.error('Error:', error);
    if (error.status === 401) {
      res.status(401).json({ error: 'Unauthorized' });
    } else {
      res.status(500).json({ error: 'Error calling Bedrock' });
    }
  }
});

app.get('/chat/stream', requireAuth, async (req, res) => {
  const { message, conversationId } = req.query;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  try {
    const { userProfile, companyProfile } = await fetchProfiles(req.token);
    
    const command = new InvokeModelWithResponseStreamCommand({
      modelId: 'anthropic.claude-3-5-sonnet-20240620-v1:0',
      contentType: 'application/json',
      accept: 'application/json',
      body: JSON.stringify(createMessageBody(message, conversationId, userProfile, companyProfile))
    });

    const response = await bedrock.send(command);
    const stream = response.body;
    let fullAssistantResponse = '';

    for await (const chunk of stream) {
      if (!chunk.chunk?.bytes) continue;
      
      try {
        const chunkData = JSON.parse(Buffer.from(chunk.chunk.bytes).toString());
        
        if (chunkData.type === 'content_block_delta' && chunkData.delta?.text) {
          fullAssistantResponse += chunkData.delta.text;
          res.write(`data: ${JSON.stringify({ content: chunkData.delta.text })}\n\n`);
        } else if (chunkData.type === 'message_stop') {
          updateConversationHistory(conversationId, message, fullAssistantResponse);
          res.write('data: [DONE]\n\n');
        }
      } catch (error) {
        console.error('Error processing chunk:', error);
      }
    }

    res.write('data: [DONE]\n\n');
    res.end();

  } catch (error) {
    console.error('Error setting up stream:', error);
    // Send appropriate error status
    if (error.status === 401) {
      res.status(401).write('data: [UNAUTHORIZED]\n\n');
    } else {
      res.write('data: [ERROR]\n\n');
    }
    res.end();
  }
});

// Add refresh token endpoint
app.post('/auth/refresh', async (req, res) => {
  const refreshToken = req.body.refresh_token;
  if (!refreshToken) {
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
        refresh_token: refreshToken
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

// Add user profile endpoint
app.get('/api/me', requireAuth, async (req, res) => {
  try {
    const response = await fetch('https://enterprise.ft3.atelierclient.com/api/UserProfiles', {
      headers: {
        'Authorization': `Bearer ${req.token}`
      }
    });

    if (!response.ok) {
      throw new Error(`Profile fetch failed: ${response.status}`);
    }

    const profile = await response.json();
    res.json(profile.value);
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ error: 'Failed to fetch user profile' });
  }
});

// Add company profile endpoint
app.get('/api/company', requireAuth, async (req, res) => {
  try {
    const response = await fetch('https://enterprise.ft3.atelierclient.com/index.php?route=atelier_enterprise_api/company/init', {
      headers: {
        'Authorization': `Bearer ${req.token}`
      }
    });

    if (!response.ok) {
      throw new Error(`Company fetch failed: ${response.status}`);
    }

    const company = await response.json();
    res.json(company);
  } catch (error) {
    console.error('Error fetching company profile:', error);
    res.status(500).json({ error: 'Failed to fetch company profile' });
  }
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
