import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// ✅ Connect to MongoDB
mongoose.connect(process.env.MONGO_URI!)
  .then(() => {
    console.log("✅ MongoDB connected");
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err);
  });

// JWT secret key (use env var in production)
const JWT_SECRET = "cherritalk_secret_key";

// In-memory user store
interface User {
  id: string;
  email: string;
  password: string; // hashed
}

interface SignupRequest {
  email: string;
  password: string;
}

interface LoginRequest {
  email: string;
  password: string;
}

// Data we store for each websocket
interface WebSocketData {
  userId: string;
  email: string;
  socketId: string;
}

const users: User[] = [];
const connectedUsers = new Map<string, string>(); // socketId -> email

// Create a Bun server with WebSocket support
const server = Bun.serve({
  port: Number(process.env.PORT) || 3000,
  websocket: {
    // Define the message type
    message(ws, message) {
      try {
        // Parse message
        const msg = JSON.parse(message.toString());
        
        // If this is an auth message, handle authentication
        if (msg.type === 'auth' && msg.token) {
          handleAuthentication(ws, msg.token);
          return;
        }
        
        // Check if user is authenticated
        if (!ws.data) {
          ws.send(JSON.stringify({
            type: 'error',
            message: 'Not authenticated'
          }));
          return;
        }
        
        // Handle chat message
        if (msg.type === 'chat message') {
          // Use type assertion to access the data safely
          const userData = ws.data as WebSocketData;
          
          // Broadcast chat message to all clients
          server.publish('all', JSON.stringify({
            type: 'chat message',
            text: msg.text,
            user: userData.email,
            userId: userData.userId,
            timestamp: new Date()
          }));
        }
      } catch (error) {
        console.error("Error processing message:", error);
      }
    },
    // Handle new WebSocket connections
    open(ws) {
      // Initial handshake - wait for auth message
      ws.send(JSON.stringify({
        type: 'welcome',
        message: 'Please authenticate with an auth message containing your token'
      }));
    },
    // Handle WebSocket disconnections
    close(ws) {
      try {
        const wsData = ws.data;
        if (wsData) {
          // Using type assertion to access the data
          const userData = wsData as unknown as WebSocketData;
          const socketId = userData.socketId;
          const email = userData.email;
          
          if (socketId && email) {
            console.log(`❌ User disconnected: ${socketId} (${email})`);
            connectedUsers.delete(socketId);
            
            // Notify all clients about disconnection
            server.publish('all', JSON.stringify({
              type: 'user disconnected',
              email: email
            }));
          }
        }
      } catch (error) {
        console.error("Error in WebSocket close:", error);
      }
    }
  },
  async fetch(req) {
    // Set CORS headers for all responses
    const corsHeaders = {
      "Access-Control-Allow-Origin": "http://localhost:5173, https://your-vercel-project.vercel.app",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Allow-Credentials": "true"
    };
    
    // Handle preflight OPTIONS requests
    if (req.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }
    
    const url = new URL(req.url);
    const path = url.pathname;
    
    // Base headers for all JSON responses
    const jsonHeaders = {
      ...corsHeaders,
      "Content-Type": "application/json"
    };
    
    // Home route
    if (path === '/' && req.method === 'GET') {
      return new Response('Chat server is running', { 
        headers: { ...corsHeaders } 
      });
    }
    
    // Signup route
    if (path === '/signup' && req.method === 'POST') {
      try {
        const data = await req.json() as SignupRequest;
        const { email, password } = data;
        
        if (!email || !password) {
          return new Response(JSON.stringify({ error: 'Email and password are required' }), { 
            status: 400,
            headers: jsonHeaders
          });
        }
        
        if (users.some(user => user.email === email)) {
          return new Response(JSON.stringify({ error: 'User already exists' }), { 
            status: 409,
            headers: jsonHeaders
          });
        }
        
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(password, salt);
        
        const newUser: User = {
          id: crypto.randomUUID(),
          email,
          password: hashedPassword
        };
        
        users.push(newUser);
        
        return new Response(JSON.stringify({ message: 'User created successfully' }), {
          status: 201,
          headers: jsonHeaders
        });
      } catch (error) {
        console.error('Signup error:', error);
        return new Response(JSON.stringify({ error: 'Server error' }), {
          status: 500,
          headers: jsonHeaders
        });
      }
    }
    
    // Login route
    if (path === '/login' && req.method === 'POST') {
      try {
        const data = await req.json() as LoginRequest;
        const { email, password } = data;
        
        if (!email || !password) {
          return new Response(JSON.stringify({ error: 'Email and password are required' }), { 
            status: 400,
            headers: jsonHeaders
          });
        }
        
        const user = users.find(u => u.email === email);
        if (!user) {
          return new Response(JSON.stringify({ error: 'Invalid credentials' }), { 
            status: 401,
            headers: jsonHeaders
          });
        }
        
        const isMatch = bcrypt.compareSync(password, user.password);
        if (!isMatch) {
          return new Response(JSON.stringify({ error: 'Invalid credentials' }), { 
            status: 401,
            headers: jsonHeaders
          });
        }
        
        const token = jwt.sign(
          { userId: user.id, email: user.email },
          JWT_SECRET,
          { expiresIn: '1h' }
        );
        
        return new Response(JSON.stringify({ token }), {
          status: 200,
          headers: jsonHeaders
        });
      } catch (error) {
        console.error('Login error:', error);
        return new Response(JSON.stringify({ error: 'Server error' }), {
          status: 500,
          headers: jsonHeaders
        });
      }
    }
    
    // Connected users route
    if (path === '/users/connected' && req.method === 'GET') {
      return new Response(JSON.stringify({
        count: connectedUsers.size,
        users: Array.from(connectedUsers.values())
      }), {
        status: 200,
        headers: jsonHeaders
      });
    }
    
    // Not found for anything else
    return new Response('Not Found', { 
      status: 404,
      headers: corsHeaders
    });
  }
});

// Helper function to handle authentication
function handleAuthentication(ws: any, token: string) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string, email: string };
    
    // Generate a unique ID for this websocket connection
    const socketId = crypto.randomUUID();
    
    // Store user data in socket
    ws.data = { 
      userId: decoded.userId, 
      email: decoded.email,
      socketId: socketId
    };
    
    // Add to connected users map
    connectedUsers.set(socketId, decoded.email);
    
    console.log(`✅ User connected: ${socketId} (${decoded.email})`);
    
    // Notify current user of all connected users
    ws.send(JSON.stringify({ 
      type: 'connected users',
      users: Array.from(connectedUsers.values())
    }));
    
    // Notify others
    server.publish('all', JSON.stringify({
      type: 'user connected',
      email: decoded.email
    }));
    
  } catch (err) {
    console.error('Socket authentication error:', err);
    ws.send(JSON.stringify({
      type: 'error',
      message: 'Authentication failed: Invalid token'
    }));
  }
}

console.log(`Server running on ${server.hostname}:${server.port}`);
