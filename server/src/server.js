// server/src/server.js
import "dotenv/config";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

import { db, initDb } from "./db.js";
import {
  ensureAdminFromEnv,
  createSession,
  verifySessionCookie,
  destroySession,
} from "./auth.js";
import { sendApprovalEmail, sendPasswordResetEmail } from "./mail.js";

const app = express();

const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret";
const APP_ORIGIN = process.env.APP_ORIGIN || `http://localhost:${PORT}`;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PUBLIC_DIR = path.join(__dirname, "..", "..", "public");

// =====================
// Middlewares base
// =====================
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(cors({ origin: APP_ORIGIN, credentials: true }));

// =====================
// Anti-cache en páginas protegidas
// =====================
function noStore(_req, res, next) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  res.setHeader("Surrogate-Control", "no-store");
  next();
}

// Servimos páginas protegidas con no-store
app.get("/index.html", noStore, (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));
app.get("/admin.html", noStore, (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "admin.html")));
app.get("/admin-orders.html", noStore, (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "admin-orders.html")));
app.get("/my-orders.html", noStore, (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "my-orders.html")));

// Anti-cache también en password reset
app.get("/forgot-password.html", noStore, (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "forgot-password.html")));
app.get("/reset-password.html", noStore, (_req, res) => res.sendFile(path.join(PUBLIC_DIR, "reset-password.html")));

// Frontend estático
app.use(express.static(PUBLIC_DIR));

// =====================
// Cargar usuario desde cookie -> sesión -> user real
// =====================
app.use((req, _res, next) => {
  try {
    const cookieVal = req.cookies?.session;
    const sess = verifySessionCookie(cookieVal, SESSION_SECRET);
    if (!sess) {
      req.user = null;
      return next();
    }

    const sessionId = sess.sessionId;
    const nowIso = new Date().toISOString();

    const srow = db.prepare(`
      SELECT id, user_id, expires_at
      FROM sessions
      WHERE id = ? AND expires_at > ?
    `).get(sessionId, nowIso);

    if (!srow) {
      req.user = null;
      return next();
    }

    const urow = db.prepare(`
      SELECT id, username, email, role, status
      FROM users
      WHERE id = ?
    `).get(srow.user_id);

    // Solo usuarios aprobados
    if (!urow || urow.status !== "APPROVED") {
      req.user = null;
      return next();
    }

    req.user = {
      id: urow.id,
      username: urow.username,
      email: urow.email,
      role: urow.role,
    };
    next();
  } catch (e) {
    console.error("Session middleware error:", e);
    req.user = null;
    next();
  }
});

// =====================
// Guards
// =====================
function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "No autenticado" });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: "No autenticado" });
  if (String(req.user.role).toUpperCase() !== "ADMIN") {
    return res.status(403).json({ error: "No autorizado" });
  }
  next();
}

// =====================
// Health
// =====================
app.get("/api/health", (_req, res) => res.json({ ok: true }));

// =====================
// Register
// =====================
app.post("/api/register", async (req, res) => {
  try {
    const { username, email, password } = req.body || {};
    if (!username || !email || !password) {
      return res.status(400).json({ error: "Faltan campos" });
    }

    const normUser = String(username).trim().toLowerCase();
    const normEmail = String(email).trim().toLowerCase();

    if (normUser.length < 3) return res.status(400).json({ error: "Usuario demasiado corto" });
    if (!normEmail.includes("@")) return res.status(400).json({ error: "Email inválido" });
    if (String(password).length < 6) return res.status(400).json({ error: "Contraseña demasiado corta" });

    const exists = db
      .prepare("SELECT id, status FROM users WHERE username = ? OR email = ?")
      .get(normUser, normEmail);

    if (exists) {
      return res.status(409).json({
        error: "Usuario o email ya existe",
        status: exists.status,
      });
    }

    const hash = bcrypt.hashSync(String(password), 12);
    const createdAt = new Date().toISOString();

    const info = db.prepare(`
      INSERT INTO users (username, email, password_hash, role, status, created_at)
      VALUES (?, ?, ?, 'USER', 'PENDING', ?)
    `).run(normUser, normEmail, hash, createdAt);

    const userId = info.lastInsertRowid;

    const approveToken = crypto.randomBytes(24).toString("hex");
    const rejectToken = crypto.randomBytes(24).toString("hex");
    const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 3).toISOString();

    db.prepare(`
      INSERT INTO approval_tokens (token, user_id, action, expires_at, created_at)
      VALUES (?, ?, 'APPROVE', ?, ?),
             (?, ?, 'REJECT',  ?, ?)
    `).run(
      approveToken, userId, expiresAt, createdAt,
      rejectToken, userId, expiresAt, createdAt
    );

    const approveUrl = `${APP_ORIGIN}/api/approve?token=${approveToken}`;
    const rejectUrl = `${APP_ORIGIN}/api/reject?token=${rejectToken}`;

    try {
      await sendApprovalEmail({
        toAdminEmail: process.env.ADMIN_EMAIL,
        username: normUser,
        email: normEmail,
        approveUrl,
        rejectUrl,
      });
    } catch (e) {
      console.error("Email error:", e);
      return res.status(201).json({
        ok: true,
        message: "Solicitud creada, pero falló el email. Revisa SMTP.",
        status: "PENDING",
      });
    }

    return res.status(201).json({
      ok: true,
      message: "Solicitud enviada. Espera aprobación.",
      status: "PENDING",
    });
  } catch (e) {
    console.error("REGISTER ERROR:", e);
    return res.status(500).json({ error: "Error interno en registro" });
  }
});

// Approve/reject
app.get("/api/approve", (req, res) => handleDecision(req, res, "APPROVE"));
app.get("/api/reject", (req, res) => handleDecision(req, res, "REJECT"));

function handleDecision(req, res, action) {
  try {
    const token = String(req.query?.token || "");
    if (!token) return res.status(400).send("Falta token");

    const row = db.prepare(
      "SELECT token, user_id, action, expires_at FROM approval_tokens WHERE token = ?"
    ).get(token);

    if (!row) return res.status(400).send("Token inválido");
    if (row.action !== action) return res.status(400).send("Acción no coincide");
    if (new Date(row.expires_at).getTime() < Date.now()) return res.status(400).send("Token caducado");

    const newStatus = action === "APPROVE" ? "APPROVED" : "REJECTED";
    db.prepare("UPDATE users SET status = ? WHERE id = ?").run(newStatus, row.user_id);
    db.prepare("DELETE FROM approval_tokens WHERE user_id = ?").run(row.user_id);

    return res.send(`
      <html><body style="font-family:Arial;padding:20px">
        <h2>${newStatus === "APPROVED" ? "✅ Usuario aprobado" : "❌ Usuario rechazado"}</h2>
        <p>Ya puedes cerrar esta pestaña.</p>
      </body></html>
    `);
  } catch (e) {
    console.error("DECISION ERROR:", e);
    return res.status(500).send("Error interno");
  }
}

// =====================
// Login
// =====================
app.post("/api/login", (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body || {};
    if (!usernameOrEmail || !password) return res.status(400).json({ error: "Faltan campos" });

    const key = String(usernameOrEmail).trim().toLowerCase();
    const user = db.prepare(`
      SELECT id, username, email, password_hash, role, status
      FROM users
      WHERE username = ? OR email = ?
    `).get(key, key);

    if (!user) return res.status(401).json({ error: "Credenciales incorrectas" });
    if (user.status !== "APPROVED") return res.status(403).json({ error: "Tu cuenta aún no está aprobada" });

    const ok = bcrypt.compareSync(String(password), user.password_hash);
    if (!ok) return res.status(401).json({ error: "Credenciales incorrectas" });

    const cookieVal = createSession(user.id, SESSION_SECRET);
    res.cookie("session", cookieVal, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 1000 * 60 * 60 * 24 * 7,
    });

    return res.json({
      ok: true,
      user: { id: user.id, username: user.username, email: user.email, role: user.role },
    });
  } catch (e) {
    console.error("LOGIN ERROR:", e);
    return res.status(500).json({ error: "Error interno en login" });
  }
});

// =====================
// Password reset (forgot + check + reset)
// =====================
app.post("/api/password/forgot", async (req, res) => {
  try {
    const { email } = req.body || {};
    const normEmail = String(email || "").trim().toLowerCase();
    if (!normEmail || !normEmail.includes("@")) {
      return res.status(400).json({ error: "Email inválido" });
    }

    const user = db.prepare(`
      SELECT id, email
      FROM users
      WHERE email = ?
    `).get(normEmail);

    if (!user) {
      return res.status(404).json({
        error: "No tienes cuenta con este correo. Por favor regístrate.",
      });
    }

    db.prepare(`DELETE FROM password_reset_tokens WHERE user_id = ?`).run(user.id);

    const token = crypto.randomBytes(24).toString("hex");
    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    db.prepare(`
      INSERT INTO password_reset_tokens (token, user_id, expires_at, created_at)
      VALUES (?, ?, ?, ?)
    `).run(token, user.id, expiresAt, createdAt);

    const resetUrl = `${APP_ORIGIN}/reset-password.html?token=${encodeURIComponent(token)}`;

    try {
      await sendPasswordResetEmail({ to: normEmail, resetUrl });
      return res.json({ ok: true, message: "Te hemos enviado un enlace para restablecer la contraseña." });
    } catch (e) {
      console.error("RESET EMAIL ERROR:", e);
      return res.status(500).json({ error: "No se pudo enviar el email. Revisa SMTP." });
    }
  } catch (e) {
    console.error("FORGOT ERROR:", e);
    return res.status(500).json({ error: "Error interno" });
  }
});

app.get("/api/password/reset/check", (req, res) => {
  try {
    const token = String(req.query?.token || "").trim();
    if (!token) return res.status(400).json({ error: "Falta token" });

    const row = db.prepare(`
      SELECT prt.token, prt.user_id, prt.expires_at, u.email
      FROM password_reset_tokens prt
      JOIN users u ON u.id = prt.user_id
      WHERE prt.token = ?
    `).get(token);

    if (!row) return res.status(400).json({ error: "Enlace inválido" });

    if (new Date(row.expires_at).getTime() < Date.now()) {
      db.prepare(`DELETE FROM password_reset_tokens WHERE token = ?`).run(token);
      return res.status(400).json({ error: "Enlace caducado" });
    }

    return res.json({ ok: true, email: row.email });
  } catch (e) {
    console.error("RESET CHECK ERROR:", e);
    return res.status(500).json({ error: "Error interno" });
  }
});

app.post("/api/password/reset", (req, res) => {
  try {
    const { token, username, password, confirmPassword } = req.body || {};

    const t = String(token || "").trim();
    const normUser = String(username || "").trim().toLowerCase();

    if (!t) return res.status(400).json({ error: "Falta token" });
    if (normUser.length < 3) return res.status(400).json({ error: "Usuario demasiado corto" });
    if (!password || String(password).length < 6) return res.status(400).json({ error: "Contraseña demasiado corta" });
    if (String(password) !== String(confirmPassword)) return res.status(400).json({ error: "Las contraseñas no coinciden" });

    const row = db.prepare(`
      SELECT token, user_id, expires_at
      FROM password_reset_tokens
      WHERE token = ?
    `).get(t);

    if (!row) return res.status(400).json({ error: "Token inválido" });

    if (new Date(row.expires_at).getTime() < Date.now()) {
      db.prepare(`DELETE FROM password_reset_tokens WHERE token = ?`).run(t);
      return res.status(400).json({ error: "Token caducado" });
    }

    const taken = db.prepare(`
      SELECT id FROM users WHERE username = ? AND id <> ?
    `).get(normUser, row.user_id);

    if (taken) return res.status(409).json({ error: "Ese nombre de usuario ya está en uso" });

    const hash = bcrypt.hashSync(String(password), 12);

    db.prepare(`
      UPDATE users
      SET username = ?, password_hash = ?
      WHERE id = ?
    `).run(normUser, hash, row.user_id);

    db.prepare(`DELETE FROM sessions WHERE user_id = ?`).run(row.user_id);
    db.prepare(`DELETE FROM password_reset_tokens WHERE user_id = ?`).run(row.user_id);

    return res.json({ ok: true, message: "Contraseña actualizada. Inicia sesión de nuevo." });
  } catch (e) {
    console.error("RESET ERROR:", e);
    return res.status(500).json({ error: "Error interno" });
  }
});

// =====================
// Logout
// =====================
app.post("/api/logout", (req, res) => {
  try {
    const cookieVal = req.cookies?.session;
    const sess = verifySessionCookie(cookieVal, SESSION_SECRET);
    const sessionId = sess?.sessionId;
    if (sessionId) destroySession(sessionId);
  } catch {}
  res.clearCookie("session");
  return res.json({ ok: true });
});

// =====================
// Me
// =====================
app.get("/api/me", (req, res) => {
  if (!req.user) return res.json({ loggedIn: false });
  return res.json({ loggedIn: true, user: req.user });
});

// =====================
// My orders (historial usuario)
// - Si admin_deleted_at != NULL: usuario ve user_final_status (READY o CANCELLED)
// =====================
app.get("/api/my/orders", requireAuth, (req, res) => {
  try {
    const userId = req.user.id;

    const rows = db.prepare(`
      SELECT id, status, created_at, order_json, admin_deleted_at, user_final_status
      FROM orders
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 50
    `).all(userId);

    const orders = rows.map((r) => {
      let parsed = {};
      try { parsed = JSON.parse(r.order_json || "{}"); } catch {}

      const visibleStatus = r.admin_deleted_at
        ? (r.user_final_status || "CANCELLED")
        : (r.status || "RECEIVED");

      return { id: r.id, status: visibleStatus, created_at: r.created_at, order: parsed };
    });

    res.json({ ok: true, orders });
  } catch (e) {
    console.error("MY ORDERS ERROR:", e);
    res.status(500).json({ error: "Error interno cargando pedidos" });
  }
});

// =====================
// Orders (max 3 pizzas + 10 min cooldown excepto ADMIN)
// =====================
app.post("/api/orders", requireAuth, (req, res) => {
  try {
    const userId = req.user.id;
    const role = String(req.user.role || "USER").toUpperCase();

    const body = req.body || {};
    const orderObj = (body && typeof body.order === "object" && body.order) ? body.order : body;

    const items = Array.isArray(orderObj.items) ? orderObj.items : [];
    if (!items.length) return res.status(400).json({ error: "El pedido está vacío" });

    const totalPizzas = items.reduce((acc, it) => {
      const q = Number(it?.qty || 0);
      return acc + (Number.isFinite(q) ? Math.max(0, q) : 0);
    }, 0);

    if (totalPizzas <= 0) return res.status(400).json({ error: "Cantidad inválida" });
    if (totalPizzas > 3) return res.status(400).json({ error: "Máximo 3 pizzas por pedido" });

    const cooldownMs = 10 * 60 * 1000;

    if (role !== "ADMIN") {
      const last = db.prepare(`
        SELECT created_at
        FROM orders
        WHERE user_id = ?
        ORDER BY created_at DESC
        LIMIT 1
      `).get(userId);

      if (last?.created_at) {
        const lastMs = new Date(last.created_at).getTime();
        const diff = Date.now() - lastMs;

        if (diff < cooldownMs) {
          const retryAfterSec = Math.ceil((cooldownMs - diff) / 1000);
          return res.status(429).json({
            error: "Debes esperar 10 minutos entre pedidos.",
            retryAfterSec,
          });
        }
      }
    }

    const createdAt = new Date().toISOString();

    const orderJson = JSON.stringify({
      personName: orderObj.personName || req.user.username,
      items,
      createdAt,
    });

    const info = db.prepare(`
      INSERT INTO orders (user_id, order_json, status, created_at)
      VALUES (?, ?, 'RECEIVED', ?)
    `).run(userId, orderJson, createdAt);

    return res.status(201).json({
      ok: true,
      id: info.lastInsertRowid,
      cooldownSec: role === "ADMIN" ? 0 : 600,
    });
  } catch (e) {
    console.error("Error guardando pedido:", e);
    return res.status(500).json({ error: "Error interno al guardar el pedido" });
  }
});

// =====================
// Admin users (+ orders_count)
// =====================
app.get("/api/admin/users", requireAdmin, (_req, res) => {
  const rows = db.prepare(`
    SELECT
      u.id, u.username, u.email, u.role, u.status, u.created_at,
      COUNT(o.id) AS orders_count
    FROM users u
    LEFT JOIN orders o ON o.user_id = u.id
    GROUP BY u.id
    ORDER BY u.created_at DESC
  `).all();

  res.json({ ok: true, users: rows });
});

app.delete("/api/admin/users/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: "ID inválido" });

  const u = db.prepare("SELECT id, role FROM users WHERE id = ?").get(id);
  if (!u) return res.status(404).json({ error: "Usuario no existe" });
  if (String(u.role).toUpperCase() === "ADMIN") return res.status(403).json({ error: "No puedes borrar un ADMIN" });

  db.prepare("DELETE FROM sessions WHERE user_id = ?").run(id);
  db.prepare("DELETE FROM approval_tokens WHERE user_id = ?").run(id);
  db.prepare("DELETE FROM password_reset_tokens WHERE user_id = ?").run(id);
  db.prepare("DELETE FROM orders WHERE user_id = ?").run(id);
  db.prepare("DELETE FROM users WHERE id = ?").run(id);

  res.json({ ok: true });
});

// =====================
// Admin orders (lista)
// - NO muestra pedidos eliminados por admin (admin_deleted_at IS NULL)
// =====================
app.get("/api/admin/orders", requireAdmin, (_req, res) => {
  try {
    const rows = db.prepare(`
      SELECT
        o.id,
        o.status,
        o.created_at,
        o.preparing_at,
        o.ready_at,
        o.admin_deleted_at,
        o.user_final_status,
        o.order_json,
        u.username AS u_username,
        u.email AS u_email
      FROM orders o
      JOIN users u ON u.id = o.user_id
      WHERE o.admin_deleted_at IS NULL
      ORDER BY o.created_at DESC
      LIMIT 200
    `).all();

    const orders = rows.map((r) => {
      let parsed = {};
      try { parsed = JSON.parse(r.order_json || "{}"); } catch {}

      return {
        id: r.id,
        status: r.status || "RECEIVED",
        created_at: r.created_at,
        preparing_at: r.preparing_at || null,
        ready_at: r.ready_at || null,
        order: parsed,
        user: { username: r.u_username, email: r.u_email },
      };
    });

    res.json({ ok: true, orders });
  } catch (e) {
    console.error("ADMIN ORDERS ERROR:", e);
    res.status(500).json({ error: "Error interno cargando pedidos" });
  }
});

// =====================
// Admin: tap en tarjeta -> alterna RECEIVED <-> PREPARING
// =====================
// =====================
// Admin: tap en tarjeta (toggle RECIBIDO ⇄ EN PREPARACIÓN)
// =====================
app.patch("/api/admin/orders/:id/prepare", requireAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: "ID inválido" });

    const row = db.prepare(`
      SELECT id, status
      FROM orders
      WHERE id=? AND admin_deleted_at IS NULL
    `).get(id);

    if (!row) return res.status(404).json({ error: "Pedido no existe" });

    const st = String(row.status || "RECEIVED").toUpperCase();

    if (st === "RECEIVED") {
      db.prepare(`
        UPDATE orders
        SET status='PREPARING', preparing_at=datetime('now')
        WHERE id=?
      `).run(id);
      return res.json({ ok: true, status: "PREPARING" });
    }

    if (st === "PREPARING") {
      db.prepare(`
        UPDATE orders
        SET status='RECEIVED', preparing_at=NULL
        WHERE id=?
      `).run(id);
      return res.json({ ok: true, status: "RECEIVED" });
    }

    // Si está READY, no lo cambiamos con tap
    return res.json({ ok: true, status: row.status });
  } catch (e) {
    console.error("PREPARE TOGGLE ERROR:", e);
    res.status(500).json({ error: "Error interno" });
  }
});


// =====================
// Admin: botón "Listo" y "Volver a preparación"
// Reglas:
// - PREPARING -> READY (pone ready_at)
// - READY -> PREPARING (quita ready_at)
// - RECEIVED -> PREPARING (más coherente que saltar a READY)
// =====================
app.patch("/api/admin/orders/:id/toggle", requireAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: "ID inválido" });

    const row = db.prepare(`
      SELECT id, status
      FROM orders
      WHERE id=? AND admin_deleted_at IS NULL
    `).get(id);

    if (!row) return res.status(404).json({ error: "Pedido no existe" });

    const st = String(row.status || "RECEIVED").toUpperCase();
    const nowIso = new Date().toISOString();

    if (st === "READY") {
      db.prepare(`UPDATE orders SET status='PREPARING', ready_at=NULL WHERE id=?`).run(id);
      return res.json({ ok: true, status: "PREPARING" });
    }

    if (st === "RECEIVED") {
      db.prepare(`UPDATE orders SET status='PREPARING', preparing_at=? WHERE id=?`).run(nowIso, id);
      return res.json({ ok: true, status: "PREPARING" });
    }

    // PREPARING -> READY
    db.prepare(`UPDATE orders SET status='READY', ready_at=? WHERE id=?`).run(nowIso, id);
    return res.json({ ok: true, status: "READY" });
  } catch (e) {
    console.error("TOGGLE ERROR:", e);
    res.status(500).json({ error: "Error interno" });
  }
});

// Compat antigua /done -> READY
app.patch("/api/admin/orders/:id/done", requireAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: "ID inválido" });

    const nowIso = new Date().toISOString();
    db.prepare(`
      UPDATE orders
      SET status='READY', ready_at=?
      WHERE id=? AND admin_deleted_at IS NULL
    `).run(nowIso, id);

    res.json({ ok: true, status: "READY", ready_at: nowIso });
  } catch (e) {
    console.error("DONE COMPAT ERROR:", e);
    res.status(500).json({ error: "Error interno" });
  }
});

// =====================
// Admin: eliminar (soft-delete) desde UI
// - READY: usuario sigue viendo READY
// - RECEIVED/PREPARING: usuario ve CANCELLED
// - Admin deja de verlo (admin_deleted_at)
// =====================
// =====================
// Admin: ELIMINAR (soft-delete para admin)
// - Si estaba READY: el cliente seguirá viéndolo READY
// - Si estaba RECEIVED/PREPARING: el cliente lo verá CANCELLED
// =====================
app.delete("/api/admin/orders/:id", requireAdmin, (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: "ID inválido" });

    const row = db.prepare(`
      SELECT id, status
      FROM orders
      WHERE id=? AND admin_deleted_at IS NULL
    `).get(id);

    if (!row) return res.status(404).json({ error: "Pedido no existe" });

    const st = String(row.status || "RECEIVED").toUpperCase();
    const userFinal = (st === "READY") ? "READY" : "CANCELLED";

    // opcional: si no estaba READY, dejamos también status='CANCELLED' para coherencia
    const newStatus = (st === "READY") ? "READY" : "CANCELLED";

    db.prepare(`
      UPDATE orders
      SET admin_deleted_at=datetime('now'),
          user_final_status=?,
          status=?
      WHERE id=?
    `).run(userFinal, newStatus, id);

    return res.json({ ok: true });
  } catch (e) {
    console.error("ADMIN DELETE ORDER ERROR:", e);
    res.status(500).json({ error: "Error interno" });
  }
});

// =====================
// Boot
// =====================
initDb();
ensureAdminFromEnv();
app.listen(PORT, () => console.log(`✅ Server en ${APP_ORIGIN}`));
