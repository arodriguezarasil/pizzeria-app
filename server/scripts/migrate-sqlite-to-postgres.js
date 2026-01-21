import Database from "better-sqlite3";
import { initDb, pool } from "../src/db.js";

const sqlitePath = process.env.SQLITE_PATH || "/data/pizzeria.sqlite";
const truncate = String(process.env.MIGRATE_TRUNCATE || "").toLowerCase() === "true";

function hasColumn(db, table, column) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all();
  return cols.some((c) => c.name === column);
}

function selectWithDefaults(db, table, columns) {
  const selectCols = columns
    .map((col) => (hasColumn(db, table, col) ? col : `NULL AS ${col}`))
    .join(", ");
  return `SELECT ${selectCols} FROM ${table}`;
}

async function migrate() {
  const sqlite = new Database(sqlitePath, { readonly: true });

  await initDb();
  await pool.query("BEGIN");

  try {
    const tables = sqlite
      .prepare("SELECT name FROM sqlite_master WHERE type='table'")
      .all()
      .map((row) => row.name);
    if (!tables.includes("users")) {
      throw new Error(
        `SQLite sin tablas esperadas. Archivo: ${sqlitePath}. Tablas: ${tables.join(", ")}`
      );
    }

    if (truncate) {
      await pool.query(`
        TRUNCATE TABLE approval_tokens, sessions, password_reset_tokens, orders, users
        RESTART IDENTITY CASCADE
      `);
    }

    const users = sqlite
      .prepare("SELECT id, username, email, password_hash, role, status, created_at FROM users")
      .all();
    for (const row of users) {
      await pool.query(
        `
          INSERT INTO users (id, username, email, password_hash, role, status, created_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7)
          ON CONFLICT (id) DO NOTHING
        `,
        [row.id, row.username, row.email, row.password_hash, row.role, row.status, row.created_at]
      );
    }

    const ordersSql = selectWithDefaults(sqlite, "orders", [
      "id",
      "user_id",
      "order_json",
      "status",
      "created_at",
      "preparing_at",
      "ready_at",
      "admin_deleted_at",
      "user_final_status",
    ]);
    const orders = sqlite.prepare(ordersSql).all();
    for (const row of orders) {
      await pool.query(
        `
          INSERT INTO orders (
            id, user_id, order_json, status, created_at,
            preparing_at, ready_at, admin_deleted_at, user_final_status
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
          ON CONFLICT (id) DO NOTHING
        `,
        [
          row.id,
          row.user_id,
          row.order_json,
          row.status,
          row.created_at,
          row.preparing_at,
          row.ready_at,
          row.admin_deleted_at,
          row.user_final_status,
        ]
      );
    }

    const sessions = sqlite
      .prepare("SELECT id, user_id, expires_at, created_at FROM sessions")
      .all();
    for (const row of sessions) {
      await pool.query(
        `
          INSERT INTO sessions (id, user_id, expires_at, created_at)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (id) DO NOTHING
        `,
        [row.id, row.user_id, row.expires_at, row.created_at]
      );
    }

    const approvals = sqlite
      .prepare("SELECT token, user_id, action, expires_at, created_at FROM approval_tokens")
      .all();
    for (const row of approvals) {
      await pool.query(
        `
          INSERT INTO approval_tokens (token, user_id, action, expires_at, created_at)
          VALUES ($1, $2, $3, $4, $5)
          ON CONFLICT (token) DO NOTHING
        `,
        [row.token, row.user_id, row.action, row.expires_at, row.created_at]
      );
    }

    const resets = sqlite
      .prepare("SELECT token, user_id, expires_at, created_at FROM password_reset_tokens")
      .all();
    for (const row of resets) {
      await pool.query(
        `
          INSERT INTO password_reset_tokens (token, user_id, expires_at, created_at)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (token) DO NOTHING
        `,
        [row.token, row.user_id, row.expires_at, row.created_at]
      );
    }

    await pool.query(`
      SELECT setval(pg_get_serial_sequence('users', 'id'), COALESCE(MAX(id), 1))
      FROM users
    `);
    await pool.query(`
      SELECT setval(pg_get_serial_sequence('orders', 'id'), COALESCE(MAX(id), 1))
      FROM orders
    `);

    await pool.query("COMMIT");
    console.log("✅ Migración completada.");
  } catch (e) {
    await pool.query("ROLLBACK");
    console.error("❌ Error migrando:", e);
    process.exitCode = 1;
  } finally {
    sqlite.close();
    await pool.end();
  }
}

migrate();
