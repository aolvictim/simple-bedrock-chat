const express = require('express');
const { BedrockRuntimeClient, InvokeModelWithResponseStreamCommand } = require('@aws-sdk/client-bedrock-runtime');
const router = express.Router();

// Initialize Bedrock client
const bedrock = new BedrockRuntimeClient({ region: process.env.AWS_REGION || 'us-east-1' });

// Helper function to create message body
function createMessageBody(message, conversationId, userProfile, companyProfile) {
  return {
    anthropic_version: "bedrock-2023-05-31",
    max_tokens: 4096,
    messages: [
      {
        role: "user",
        content: `User Profile: ${JSON.stringify(userProfile)}\nCompany Profile: ${JSON.stringify(companyProfile)}\n\nUser Message: ${message}`
      }
    ],
    system: "You are a helpful AI assistant for Loupe. Use the provided user and company profiles to personalize your responses. Keep responses concise and professional.",
    temperature: 0.7,
    top_p: 1
  };
}

// Helper function to fetch profiles
async function fetchProfiles(token) {
  try {
    const [userResponse, companyResponse] = await Promise.all([
      fetch(`${process.env.LOUPE_API_BASE_URL}/api/UserProfiles`, {
        headers: { 'Authorization': `Bearer ${token}` }
      }),
      fetch(`${process.env.LOUPE_API_BASE_URL}/index.php?route=atelier_enterprise_api/company/init`, {
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
    if (error.status === 401) {
      throw error;
    }
    console.error('Error fetching profiles:', error);
    return { userProfile: {}, companyProfile: {} };
  }
}

// Stream chat endpoint
router.get('/stream', async (req, res) => {
  const { message, conversationId, token } = req.query;
  
  if (!message || !token) {
    return res.status(400).json({ error: 'Message and token are required' });
  }

  try {
    // Fetch profiles
    const { userProfile, companyProfile } = await fetchProfiles(token);

    // Set up SSE
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    // Create and send command
    const command = new InvokeModelWithResponseStreamCommand({
      modelId: process.env.BEDROCK_MODEL_ID || 'anthropic.claude-3-5-sonnet-20240620-v1:0',
      contentType: 'application/json',
      accept: 'application/json',
      body: JSON.stringify(createMessageBody(message, conversationId, userProfile, companyProfile))
    });

    const response = await bedrock.send(command);
    
    if (!response.body) {
      throw new Error('No response body');
    }

    // Process the stream
    for await (const chunk of response.body) {
      if (chunk.chunk?.bytes) {
        const chunkData = JSON.parse(Buffer.from(chunk.chunk.bytes).toString());
        if (chunkData.type === 'content_block_delta' && chunkData.delta?.text) {
          res.write(`data: ${JSON.stringify({ content: chunkData.delta.text })}\n\n`);
        }
      }
    }

    res.write('data: [DONE]\n\n');
    res.end();
  } catch (error) {
    console.error('Stream error:', error);
    if (error.status === 401) {
      res.status(401).json({ error: 'Unauthorized' });
    } else {
      res.status(500).json({ error: 'Failed to get response' });
    }
  }
});

module.exports = router; 