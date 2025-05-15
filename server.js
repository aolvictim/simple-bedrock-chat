// Simple Express backend to proxy Amazon Bedrock requests

const express = require('express');
const cors = require('cors');
const { BedrockRuntimeClient, InvokeModelWithResponseStreamCommand } = require('@aws-sdk/client-bedrock-runtime');

// Configure AWS and initialize express
const bedrock = new BedrockRuntimeClient({ region: 'us-east-1' });
const app = express();

app.use(cors());
app.use(express.json());

// Store conversation history in memory
const conversations = new Map();

// Helper function to create message body with history
const createMessageBody = (message, conversationId) => {
  const history = conversations.get(conversationId) || [];
  const messages = [
    ...history,
    {
      role: "user",
      content: [{ type: "text", text: message }]
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

// Regular non-streaming endpoint (keeping for backup)
app.post('/chat', async (req, res) => {
  const userMessage = req.body.message;

  const body = JSON.stringify({
    anthropic_version: "bedrock-2023-05-31",
    max_tokens: 1000,
    messages: [
      {
        role: "user",
        content: [
        //   {
        //     type: "image",
        //     source: {
        //       type: "base64",
        //       media_type: "image/jpeg",
        //       data: "iVBORw..."
        //     }
        //   },
          {
            type: "text",
            text: userMessage
          }
        ]
      }
    ]
  });

  try {
    const response = await bedrock.invokeModel({
      modelId: 'anthropic.claude-3-5-sonnet-20240620-v1:0',
      contentType: 'application/json',
      accept: 'application/json',
      body: body
    }).promise();

    const responseBody = JSON.parse(response.body.toString());
    res.json(responseBody);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error calling Bedrock');
  }
});

// Streaming chat endpoint
app.get('/chat/stream', async (req, res) => {
  const { message, conversationId = 'default' } = req.query;
  if (!message) {
    return res.status(400).send('Message is required');
  }

  // Set SSE headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });

  try {
    // Initialize stream
    const command = new InvokeModelWithResponseStreamCommand({
      modelId: 'anthropic.claude-3-5-sonnet-20240620-v1:0',
      contentType: 'application/json',
      accept: 'application/json',
      body: JSON.stringify(createMessageBody(message, conversationId))
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
          // Update conversation history when the message is complete
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
    res.write('data: [ERROR]\n\n');
    res.end();
  }
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
