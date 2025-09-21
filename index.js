import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import compression from 'compression';
import mysql from 'mysql2/promise';
import { z } from 'zod';

const app = express();
const isProd = process.env.NODE_ENV === 'production';

app.set('trust proxy', 1);

app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));
app.use(compression());
app.use(express.urlencoded({ extended: true, limit: '64kb' }));
app.use(express.json({ limit: '64kb' }));

const parseOrigins = (raw) =>
  (raw ?? '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);

const allowList = parseOrigins(process.env.CORS_ORIGIN)
  .concat(isProd ? [] : ['http://localhost:5173', 'http://localhost:3000']);

const corsOptions = {
  origin(origin, cb) {
    if (!origin || allowList.includes(origin)) return cb(null, true);
    return cb(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  credentials: false,
  maxAge: 86400,
};
app.use(cors(corsOptions));

const limiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: 'Too many requests. Please retry later.' },
  keyGenerator: ipKeyGenerator, 
});
app.use('/api', limiter);

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT ?? 3306),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD || process.env.DB_PASS,
  database: process.env.DB_NAME,
  connectionLimit: 10,
  enableKeepAlive: true,
  waitForConnections: true,
});

(async () => {
  try {
    const conn = await pool.getConnection();
    await conn.ping();
    conn.release();
    console.log('✅ DB pool ready');
  } catch (e) {

    console.error('❌ DB connection failed at startup:', e?.message || e);
  }
})();

const normalizePhone = (v) => v.replace(/[^\d+]/g, '');
const ipFromReq = (req) => (req.headers['x-forwarded-for']?.toString().split(',')[0]
  ?? req.socket?.remoteAddress
  ?? null);
const uaFromReq = (req) => (req.headers['user-agent'] ?? '').slice(0, 255);

const contactSchema = z.object({
  firstName: z.string().trim().min(2).max(100),
  emailTxt: z.string().trim().email().max(255),
  phone: z.string().trim().transform(normalizePhone)
    .refine(v => /^\+?\d{10,15}$/.test(v), 'Phone must be 10-15 digits'),
  message: z.string().trim().max(100).optional().or(z.literal('')),
  source: z.enum(['home', 'contactus']),
});

const plotInquirySchema = z.object({
  plot_number: z.string().trim().min(1).max(32),
  full_name: z.string().trim().min(2).max(120),
  email: z.string().trim().email().max(190),
  phone: z.string().trim().transform(normalizePhone)
    .refine(v => /^\+?\d{10,15}$/.test(v), 'Phone must be 10-15 digits'),
  budget_range: z.enum(['75-100L', '100-150L', '150L+']).optional().nullable(),
  inquiry_type: z.enum(['more_info', 'site_visit', 'ready_to_buy']).default('more_info'),
  message: z.string().trim().max(2000).optional().or(z.literal('')).nullable(),
});

app.get('/api/health', (_req, res) => res.json({ ok: true }));

app.post('/api/contact', async (req, res) => {
  try {
    const parsed = contactSchema.parse(req.body);
    const sql = `
      INSERT INTO contacts (first_name, email, phone, message, source, ip, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    const params = [
      parsed.firstName,
      parsed.emailTxt,
      parsed.phone,
      parsed.message || null,
      parsed.source,
      ipFromReq(req),
      uaFromReq(req),
    ];
    const [result] = await pool.execute(sql, params);
    return res.status(201).json({
      ok: true,
      id: result.insertId,
      message: '✅ Thanks! We received your message.',
    });
  } catch (err) {
    if (err?.issues) {
      return res.status(400).json({
        ok: false,
        message: 'Validation failed',
        errors: err.issues.map(i => ({ path: i.path?.join('.') ?? '', msg: i.message })),
      });
    }
    console.error('POST /api/contact error:', {
  message: err?.message,
  code: err?.code,
  errno: err?.errno,
  sqlState: err?.sqlState,
  sqlMessage: err?.sqlMessage,
  sql: err?.sql,
});
    return res.status(500).json({ ok: false, message: 'Something went wrong. Please try again.' });
  }
});

app.post('/api/plot-inquiries', async (req, res) => {
  try {
    const parsed = plotInquirySchema.parse(req.body);
    const sql = `
      INSERT INTO plot_inquiries
        (plot_number, full_name, email, phone, budget_range, inquiry_type, message, ip, user_agent)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const params = [
      parsed.plot_number,
      parsed.full_name,
      parsed.email,
      parsed.phone,
      parsed.budget_range ?? null,
      parsed.inquiry_type ?? 'more_info',
      parsed.message ?? null,
      ipFromReq(req),
      uaFromReq(req),
    ];
    const [result] = await pool.execute(sql, params);
    return res.status(201).json({ ok: true, id: result.insertId });
  } catch (err) {
    if (err?.issues) {
      return res.status(400).json({
        ok: false,
        message: 'Validation failed',
        errors: err.issues.map(i => ({ path: i.path?.join('.') ?? '', msg: i.message })),
      });
    }
    console.error('POST /api/plot-inquiries error:', isProd ? err?.message : err);
    return res.status(500).json({ ok: false, message: 'Database error.' });
  }
});

app.get("/", (req, res) => {
  res.send("✅ API is running. Use /api/* routes.");
});


app.get('/api/contacts', async (req, res) => {
  try {
    const adminToken = process.env.ADMIN_TOKEN;
    if (adminToken) {
      const provided = req.headers['x-admin-token'];
      if (provided !== adminToken) return res.status(403).json({ ok: false, message: 'Forbidden' });
    } else if (isProd) {
      return res.status(404).json({ ok: false, message: 'Not found' });
    }

    const [rows] = await pool.query(
      'SELECT id, first_name, email, phone, message, source, created_at FROM contacts ORDER BY id DESC LIMIT 100'
    );
    res.json({ ok: true, data: rows });
  } catch (e) {
    res.status(500).json({ ok: false, message: 'Failed to fetch' });
  }
});

app.use('/api', (_req, res) =>
  res.status(404).json({ ok: false, message: 'Not found' })
);

const PORT = Number(process.env.PORT ?? 8080);
const server = app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT}`);
});

const shutdown = async (signal) => {
  console.log(`\n${signal} received. Shutting down...`);
  server.close(async () => {
    try {
      await pool.end();
      console.log('DB pool closed. Bye!');
      process.exit(0);
    } catch {
      process.exit(1);
    }
  });
};
['SIGINT', 'SIGTERM'].forEach(sig => process.on(sig, () => shutdown(sig)));
