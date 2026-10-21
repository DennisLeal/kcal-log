PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  amount INTEGER NOT NULL,
  currency TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('creating', 'pending', 'paid', 'failed')),
  checkout_session_id TEXT UNIQUE,
  payment_id TEXT,
  created_at INTEGER NOT NULL,
  paid_at INTEGER,
  buyer_email_sent_at INTEGER,
  owner_email_sent_at INTEGER
);

CREATE INDEX IF NOT EXISTS orders_email_status_paid_at
  ON orders (email, status, paid_at DESC);

CREATE TABLE IF NOT EXISTS processed_events (
  event_id TEXT PRIMARY KEY,
  processed_at INTEGER NOT NULL,
  order_id TEXT NOT NULL REFERENCES orders(id)
);

CREATE TABLE IF NOT EXISTS access_codes (
  email TEXT PRIMARY KEY,
  order_id TEXT NOT NULL REFERENCES orders(id),
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS access_tokens (
  token_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  order_id TEXT NOT NULL REFERENCES orders(id),
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS access_tokens_order_id
  ON access_tokens (order_id, email);

CREATE TABLE IF NOT EXISTS rate_limits (
  rate_key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  request_count INTEGER NOT NULL
);
