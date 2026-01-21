import pg from "pg";

const { Pool } = pg;

export const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL || "postgres://pizzeria:pizzeria@db:5432/pizzeria",
});

export async function queryOne(sql, params = []) {
  const res = await pool.query(sql, params);
  return res.rows[0] || null;
}

export async function queryAll(sql, params = []) {
  const res = await pool.query(sql, params);
  return res.rows;
}

export async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'USER',
      status TEXT NOT NULL DEFAULT 'PENDING',
      created_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS approval_tokens (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      action TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      order_json TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'RECEIVED',
      created_at TIMESTAMPTZ NOT NULL
    );

    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL
    );
  `);

  // =========================
  // MIGRACIONES
  // =========================
  await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'RECEIVED'`);
  await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS preparing_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS ready_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS admin_deleted_at TIMESTAMPTZ`);
  await pool.query(`ALTER TABLE orders ADD COLUMN IF NOT EXISTS user_final_status TEXT`);

  // =========================
  // NORMALIZACIÓN (por si venías de OPEN/DONE)
  // =========================
  try {
    await pool.query(`
      UPDATE orders SET status='RECEIVED' WHERE UPPER(COALESCE(status,''))='OPEN';
      UPDATE orders SET status='READY'    WHERE UPPER(COALESCE(status,''))='DONE';
    `);
  } catch {
    // si alguna DB antigua hiciera cosas raras, no queremos romper arranque
  }

  // =========================
  // Ajuste de secuencias (evitar IDs huecos tras borrados)
  // =========================
  await pool.query(`
    SELECT setval(
      pg_get_serial_sequence('users', 'id'),
      GREATEST(COALESCE((SELECT MAX(id) FROM users), 1), 1),
      true
    );
  `);
  await pool.query(`
    SELECT setval(
      pg_get_serial_sequence('orders', 'id'),
      GREATEST(COALESCE((SELECT MAX(id) FROM orders), 1), 1),
      true
    );
  `);

  // =========================
  // ÍNDICES
  // =========================
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_orders_user_created
      ON orders(user_id, created_at);

    CREATE INDEX IF NOT EXISTS idx_orders_status_created
      ON orders(status, created_at);

    CREATE INDEX IF NOT EXISTS idx_orders_preparing_at
      ON orders(preparing_at);

    CREATE INDEX IF NOT EXISTS idx_orders_ready_at
      ON orders(ready_at);

    CREATE INDEX IF NOT EXISTS idx_orders_admin_deleted_at
      ON orders(admin_deleted_at);

    CREATE INDEX IF NOT EXISTS idx_orders_user_final_status
      ON orders(user_final_status);

    CREATE INDEX IF NOT EXISTS idx_pwdreset_user
      ON password_reset_tokens(user_id);

    CREATE INDEX IF NOT EXISTS idx_pwdreset_expires
      ON password_reset_tokens(expires_at);
  `);
}
