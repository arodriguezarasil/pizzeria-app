import nodemailer from "nodemailer";

/* =========================
   Transporter común
========================= */
function getTransporter() {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 465);
  const secure = String(process.env.SMTP_SECURE || "true").toLowerCase() === "true";
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    throw new Error("SMTP no configurado (falta host/user/pass)");
  }

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass }
  });
}

/* =========================
   Email aprobación registro
========================= */
export async function sendApprovalEmail({ toAdminEmail, username, email, approveUrl, rejectUrl }) {
  if (!toAdminEmail) {
    throw new Error("ADMIN_EMAIL no configurado");
  }

  const transporter = getTransporter();

  const html = `
    <div style="font-family:Arial;line-height:1.5">
      <h2>Solicitud de registro</h2>
      <p><b>Usuario:</b> ${escapeHtml(username)}</p>
      <p><b>Email:</b> ${escapeHtml(email)}</p>
      <p>
        <a href="${approveUrl}" style="display:inline-block;padding:10px 14px;background:#1e7f43;color:#fff;border-radius:8px;text-decoration:none;font-weight:700">
          ✅ Aprobar
        </a>
        &nbsp;
        <a href="${rejectUrl}" style="display:inline-block;padding:10px 14px;background:#8c1d18;color:#fff;border-radius:8px;text-decoration:none;font-weight:700">
          ❌ Rechazar
        </a>
      </p>
      <p style="color:#666;font-size:12px">Este enlace caduca en 3 días.</p>
    </div>
  `;

  await transporter.sendMail({
    from: process.env.SMTP_USER,
    to: toAdminEmail,
    subject: `Solicitud de registro: ${username}`,
    html
  });
}

/* =========================
   Email reset contraseña
========================= */
export async function sendPasswordResetEmail({ to, resetUrl }) {
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 465);
  const secure = String(process.env.SMTP_SECURE || "true").toLowerCase() === "true";
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!host || !user || !pass) {
    throw new Error("SMTP no configurado (falta host/user/pass)");
  }

  const transporter = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass }
  });

  const html = `
    <div style="font-family:Arial;line-height:1.5">
      <h2>Restablecer contraseña</h2>
      <p>Has solicitado restablecer tu contraseña. Pulsa el botón:</p>
      <p>
        <a href="${resetUrl}" style="display:inline-block;padding:10px 14px;background:#8c1d18;color:#fff;border-radius:8px;text-decoration:none;font-weight:700">
          🔒 Cambiar credenciales
        </a>
      </p>
      <p style="color:#666;font-size:12px">Este enlace caduca en 15 minutos. Si no fuiste tú, ignora este correo.</p>
    </div>
  `;

  await transporter.sendMail({
    from: user,
    to,
    subject: `Restablecer contraseña`,
    html
  });
}

/* =========================
   Utils
========================= */
function escapeHtml(str) {
  return String(str).replace(/[&<>"']/g, (m) => ({
    "&":"&amp;",
    "<":"&lt;",
    ">":"&gt;",
    '"':"&quot;",
    "'":"&#039;"
  }[m]));
}
