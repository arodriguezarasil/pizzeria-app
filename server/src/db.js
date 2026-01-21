import Database from "better-sqlite3";

export const db = new Database("pizzeria.sqlite");

function hasColumn(table, column) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  return cols.some((c) => c.name === column);
}

export function initDb() {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'USER',
      status TEXT NOT NULL DEFAULT 'PENDING',
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS approval_tokens (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      action TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      order_json TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'RECEIVED', -- RECEIVED | PREPARING | READY
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      token TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  // =========================
  // MIGRACIONES
  // =========================
  if (!hasColumn("orders", "status")) {
    db.exec(`ALTER TABLE orders ADD COLUMN status TEXT NOT NULL DEFAULT 'RECEIVED'`);
  }

  if (!hasColumn("orders", "preparing_at")) {
    db.exec(`ALTER TABLE orders ADD COLUMN preparing_at TEXT`);
  }

  if (!hasColumn("orders", "ready_at")) {
    db.exec(`ALTER TABLE orders ADD COLUMN ready_at TEXT`);
  }

  // ✅ Soft-delete SOLO para admin (el pedido NO se borra de la DB)
  if (!hasColumn("orders", "admin_deleted_at")) {
    db.exec(`ALTER TABLE orders ADD COLUMN admin_deleted_at TEXT`);
  }

  // ✅ IMPORTANTE: lo usa tu server para lo que ve el cliente tras el “eliminar” del admin
  // READY -> READY, si no estaba READY -> CANCELLED
  if (!hasColumn("orders", "user_final_status")) {
    db.exec(`ALTER TABLE orders ADD COLUMN user_final_status TEXT`);
  }

  // =========================
  // NORMALIZACIÓN (por si venías de OPEN/DONE)
  // =========================
  try {
    db.exec(`
      UPDATE orders SET status='RECEIVED' WHERE UPPER(COALESCE(status,''))='OPEN';
      UPDATE orders SET status='READY'    WHERE UPPER(COALESCE(status,''))='DONE';
    `);
  } catch {
    // si alguna DB antigua hiciera cosas raras, no queremos romper arranque
  }

  // =========================
  // ÍNDICES
  // =========================
  db.exec(`
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
