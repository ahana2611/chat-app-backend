import express from 'express';
import type { Request, Response } from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: "http://localhost:5173",
    methods: ["GET", "POST"]
  }
});

// Enable CORS and JSON parsing
app.use(cors());
app.use(express.json());

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

const users: User[] = [];
const connectedUsers = new Map<string, string>(); // socketId -> email

// Home route
app.get('/', (req, res) => {
  res.send('Chat server is running');
});

// Signup
app.post('/signup', (req: Request, res: Response) => {
  try {
    const { email, password }: SignupRequest = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    if (users.some(user => user.email === email)) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const salt = bcrypt.genSaltSync(10);
    const hashedPassword = bcrypt.hashSync(password, salt);

    const newUser: User = {
      id: crypto.randomUUID(),
      email,
      password: hashedPassword
    };

    users.push(newUser);

    return res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error('Signup error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/login', (req: Request, res: Response) => {
  try {
    const { email, password }: LoginRequest = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = bcrypt.compareSync(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    return res.json({ token });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Server error' });
  }
});

// 🔐 JWT Middleware for Socket.IO (query token based)
io.use((socket, next) => {
  // Get token from query parameters
  const token = socket.handshake.query.token;

  if (!token || typeof token !== 'string') {
    return next(new Error('Authentication error: Token missing'));
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { userId: string, email: string };
    
    // Store user data in socket for later use
    socket.data.userId = decoded.userId;
    socket.data.email = decoded.email;
    
    // Add to connected users map
    connectedUsers.set(socket.id, decoded.email);
    
    next();
  } catch (err) {
    console.error('Socket authentication error:', err);
    next(new Error('Authentication error: Invalid token'));
  }
});

// Socket.IO Connection Handling
io.on('connection', (socket) => {
  const email = socket.data.email;
  const userId = socket.data.userId;

  console.log(`✅ User connected: ${socket.id} (${email})`);

  // Notify current user of all connected users
  socket.emit('connected users', Array.from(connectedUsers.values()));

  // Notify others
  socket.broadcast.emit('user connected', { email });

  // Chat message handling
  socket.on('chat message', (msg) => {
    io.emit('chat message', {
      text: msg,
      user: email,
      userId,
      timestamp: new Date()
    });
  });

  // Disconnection
  socket.on('disconnect', () => {
    console.log(`❌ User disconnected: ${socket.id} (${email})`);
    connectedUsers.delete(socket.id);
    io.emit('user disconnected', { email });
  });
});

// GET connected users
app.get('/users/connected', (req: Request, res: Response) => {
  res.json({
    count: connectedUsers.size,
    users: Array.from(connectedUsers.values())
  });
});

// Start server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
