// =============================================================================
//  Yia — AI Turnkey Toolkit — Express Backend
//  Handles: Stripe Checkout, Webhook verification, Payment polling, PDF delivery
// =============================================================================
'use strict';

require('dotenv').config();

const express  = require('express');
const cors     = require('cors');
const stripe   = require('stripe')(process.env.STRIPE_SECRET_KEY);
const low      = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const crypto   = require('crypto');
const path     = require('path');
const fs       = require('fs');

// -----------------------------------------------------------------------------
//  Startup — fail fast if critical env vars are missing
// -----------------------------------------------------------------------------
const REQUIRED_ENV = ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET'];
const missing = REQUIRED_ENV.filter(k => !process.env[k]);
if (missing.length) {
  console.error(`[startup] FATAL — missing required env vars: ${missing.join(', ')}`);
  process.exit(1);
}

const DOMAIN = (process.env.DOMAIN || 'http://localhost:3000').replace(/\/$/, '');
const PORT   = parseInt(process.env.PORT || '3000', 10);

// -----------------------------------------------------------------------------
//  Database — lowdb JSON file store (no native compilation needed)
//  Schema: { purchases: [ { user_email, stripe_payment_id, stripe_session_id,
//                            download_token, token_expires_at, downloaded_at,
//                            created_at } ] }
// -----------------------------------------------------------------------------
const adapter = new FileSync(path.join(__dirname, 'purchases.json'));
const db      = low(adapter);
db.defaults({ purchases: [] }).write();

// -----------------------------------------------------------------------------
//  Express app
// -----------------------------------------------------------------------------
const app = express();

// CORS — restrict to own domain in production; allow localhost for dev
const allowedOrigins = [
  DOMAIN,
  'http://localhost:3000',
  'http://127.0.0.1:3000',
].filter(Boolean);

app.use(cors({
  origin: (origin, cb) => {
    // Requests with no Origin header (e.g. curl, server-to-server) are allowed
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    cb(new Error(`CORS: origin "${origin}" is not permitted`));
  },
  credentials: true,
}));

// Serve all static files (index.html, success.html, images, etc.)
app.use(express.static(path.join(__dirname)));

// =============================================================================
//  POST /webhook
//  ⚠  This route MUST be registered BEFORE express.json() so that Stripe's
//     signature verification receives the raw, unmodified request body.
// =============================================================================
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];

  if (!sig) {
    console.warn('[webhook] Request received without stripe-signature header');
    return res.status(400).send('Missing stripe-signature header');
  }

  // --- Verify event authenticity -----------------------------------------
  let event;
  try {
    event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('[webhook] Signature verification failed:', err.message);
    return res.status(400).send(`Webhook signature error: ${err.message}`);
  }

  // --- Handle checkout.session.completed ---------------------------------
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;

    // Only process sessions where money has actually moved
    if (session.payment_status !== 'paid') {
      console.log('[webhook] Session status is not "paid" — skipping:', session.id);
      return res.json({ received: true });
    }

    // Idempotency guard — Stripe may deliver the same event more than once
    const alreadyRecorded = db
      .get('purchases')
      .find({ stripe_session_id: session.id })
      .value();

    if (alreadyRecorded) {
      console.log('[webhook] Duplicate event ignored for session:', session.id);
      return res.json({ received: true });
    }

    // Generate a cryptographically secure, single-use download token
    const downloadToken = crypto.randomBytes(32).toString('hex'); // 64 hex chars
    const expiresAt     = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    const userEmail     = session.customer_details?.email || '';
    const paymentId     = session.payment_intent || session.id;

    try {
      db.get('purchases').push({
        user_email:        userEmail,
        stripe_payment_id: paymentId,
        stripe_session_id: session.id,
        download_token:    downloadToken,
        token_expires_at:  expiresAt,
        downloaded_at:     null,
        created_at:        new Date().toISOString(),
      }).write();

      console.log(`[webhook] ✓ Purchase recorded — email: ${userEmail || '(none)'}, session: ${session.id}`);
    } catch (dbErr) {
      console.error('[webhook] Failed to write purchase to database:', dbErr.message);
      // Still return 200 so Stripe doesn't keep retrying for a DB issue
    }
  }

  res.json({ received: true });
});

// =============================================================================
//  JSON body parser — registered AFTER /webhook so raw body is preserved there
// =============================================================================
app.use(express.json());

// =============================================================================
//  POST /create-checkout-session
//  Creates a Stripe-hosted Checkout session and returns its redirect URL.
//  The client uses window.location.href = url to redirect — no Stripe.js needed.
// =============================================================================
app.post('/create-checkout-session', async (req, res) => {
  try {
    const sessionParams = {
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name:        'AI Turnkey Toolkit',
              description: '30-day AI implementation program — full materials yours to keep.',
            },
            unit_amount: 150000, // $1,500.00 in cents
          },
          quantity: 1,
        },
      ],
      mode:        'payment',
      success_url: `${DOMAIN}/success.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url:  `${DOMAIN}/#outofbox`,
    };

    // Pre-fill the email field if the client sends one
    if (req.body?.email && typeof req.body.email === 'string') {
      sessionParams.customer_email = req.body.email.trim();
    }

    const session = await stripe.checkout.sessions.create(sessionParams);

    console.log(`[checkout] Session created: ${session.id}`);
    res.json({ url: session.url });

  } catch (err) {
    console.error('[checkout] Failed to create session:', err.message);
    res.status(500).json({ error: 'Could not initialise checkout. Please try again.' });
  }
});

// =============================================================================
//  GET /api/check-payment-status?session_id=xxx
//  Polled by success.html after Stripe redirects back.
//  Returns { verified: true, token } once the webhook has recorded the payment,
//  or { verified: false } while still waiting.
// =============================================================================
app.get('/api/check-payment-status', (req, res) => {
  const { session_id } = req.query;

  if (!session_id || typeof session_id !== 'string') {
    return res.status(400).json({ verified: false, error: 'session_id query parameter is required' });
  }

  try {
    const record = db
      .get('purchases')
      .find({ stripe_session_id: session_id })
      .value();

    if (!record) {
      return res.json({ verified: false });
    }

    // Payment confirmed — return the token so the client can build the download URL
    return res.json({
      verified: true,
      token:    record.download_token,
      email:    record.user_email,
    });

  } catch (err) {
    console.error('[check-payment-status] DB read error:', err.message);
    res.status(500).json({ verified: false, error: 'Internal error — please try again' });
  }
});

// =============================================================================
//  GET /api/download?token=xxx
//  Validates the token (exists, not expired, not yet used), burns it on first
//  use, then streams the PDF as a forced attachment download.
// =============================================================================
app.get('/api/download', (req, res) => {
  const { token } = req.query;

  // Validate token format before touching the database
  if (!token || typeof token !== 'string' || !/^[a-f0-9]{64}$/.test(token)) {
    return res.status(400).send('Invalid download token.');
  }

  let record;
  try {
    record = db.get('purchases').find({ download_token: token }).value();
  } catch (err) {
    console.error('[download] DB read error:', err.message);
    return res.status(500).send('Internal error. Please contact strategy@yia.ai.');
  }

  // --- Token not found ---
  if (!record) {
    return res.status(404).send(
      'Download token not found. Please contact strategy@yia.ai.'
    );
  }

  // --- Token expired (> 24 hours old) ---
  if (new Date(record.token_expires_at) < new Date()) {
    return res.status(410).send(
      'This download link has expired. Links are valid for 24 hours. ' +
      'Please contact strategy@yia.ai for a replacement.'
    );
  }

  // --- Token already used ---
  if (record.downloaded_at !== null) {
    return res.status(410).send(
      'This download link has already been used. Each link is single-use. ' +
      'Please contact strategy@yia.ai if you need a new one.'
    );
  }

  // --- Confirm PDF file is accessible on disk ---
  const pdfPath = process.env.PDF_FILE_PATH;

  if (!pdfPath) {
    console.error('[download] PDF_FILE_PATH env var is not set');
    return res.status(500).send('File unavailable. Please contact strategy@yia.ai.');
  }

  if (!fs.existsSync(pdfPath)) {
    console.error('[download] PDF not found at configured path:', pdfPath);
    return res.status(500).send('File unavailable. Please contact strategy@yia.ai.');
  }

  // --- Burn the token BEFORE streaming to prevent race-condition reuse ---
  try {
    db.get('purchases')
      .find({ download_token: token })
      .assign({ downloaded_at: new Date().toISOString() })
      .write();
  } catch (err) {
    console.error('[download] Failed to mark token as used:', err.message);
    return res.status(500).send('Internal error. Please contact strategy@yia.ai.');
  }

  console.log(`[download] ✓ PDF delivered — email: ${record.user_email}, token: ${token.slice(0, 8)}…`);

  // --- Stream the PDF as a forced browser download ---
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'attachment; filename="Yia-AI-Turnkey-Toolkit.pdf"');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.setHeader('Pragma', 'no-cache');

  const stream = fs.createReadStream(pdfPath);

  stream.on('error', (streamErr) => {
    console.error('[download] Stream error:', streamErr.message);
    // Headers already partially sent — can't send a clean error response here
    res.destroy();
  });

  stream.pipe(res);
});

// =============================================================================
//  Start server
// =============================================================================
app.listen(PORT, () => {
  console.log(`\n[server] ✓ Yia running at http://localhost:${PORT}`);
  console.log(`[server]   DOMAIN         = ${DOMAIN}`);
  console.log(`[server]   PDF_FILE_PATH  = ${process.env.PDF_FILE_PATH || '⚠ NOT SET — downloads will fail'}`);
  console.log('');
});
