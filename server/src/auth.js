import crypto from "crypto";
import { queryOne, pool } from "./db.js";
import bcrypt from "bcryptjs";

export async function createSession(userId, sessionSecret) {
  const sid = crypto.randomBytes(24).toString("hex");
  const now = new Date();
  const expires = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 7); // 7 días

  await pool.query(
    `
      INSERT INTO sessions (id, user_id, expires_at, created_at)
      VALUES ($1, $2, $3, $4)
    `,
    [sid, userId, expires.toISOString(), now.toISOString()]
  );

  // Cookie value firmada simple
  const sig = crypto.createHmac("sha256", sessionSecret).update(sid).digest("hex");
  return `${sid}.${sig}`;
}

export function verifySessionCookie(cookieVal, sessionSecret) {
  if (!cookieVal || typeof cookieVal !== "string") return null;
  const [sid, sig] = cookieVal.split(".");
  if (!sid || !sig) return null;

  const expected = crypto.createHmac("sha256", sessionSecret).update(sid).digest("hex");
  if (!timingSafeEqual(sig, expected)) return null;

  return { sessionId: sid };
}

function timingSafeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

export async function destroySession(sessionId) {
  await pool.query("DELETE FROM sessions WHERE id = $1", [sessionId]);
}

export async function ensureAdminFromEnv() {
  const username = String(process.env.ADMIN_USERNAME || "").trim().toLowerCase();
  const email = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const password = String(process.env.ADMIN_PASSWORD || "");

  if (!username || !email || !password) {
    console.warn("⚠️ Admin env incompleto. Define ADMIN_USERNAME/ADMIN_EMAIL/ADMIN_PASSWORD en .env");
    return;
  }

  const exists = await queryOne("SELECT id FROM users WHERE role='ADMIN' LIMIT 1");
  if (exists) return;

  const hash = bcrypt.hashSync(password, 12);
  const createdAt = new Date().toISOString();

  await pool.query(
    `
      INSERT INTO users (username, email, password_hash, role, status, created_at)
      VALUES ($1, $2, $3, 'ADMIN', 'APPROVED', $4)
    `,
    [username, email, hash, createdAt]
  );

  console.log("✅ Admin creado desde .env:", username, email);
}
