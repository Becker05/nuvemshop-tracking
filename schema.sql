CREATE TABLE IF NOT EXISTS stores (
  store_id TEXT PRIMARY KEY,
  token_iv TEXT NOT NULL,
  token_ciphertext TEXT NOT NULL,
  scopes TEXT NOT NULL,
  installed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS order_events (
  store_id TEXT NOT NULL,
  order_id TEXT NOT NULL,
  event TEXT NOT NULL CHECK (event IN ('order/created', 'order/paid')),
  first_seen_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  deliveries INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (store_id, order_id, event)
);

