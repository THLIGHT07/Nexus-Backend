/**
 * services/mailer.js
 * -----------------------------------------------------------------------------
 * Sends the one-time-code emails through Brevo's transactional email API
 * (https://developers.brevo.com/reference/sendtransacemail). Free tier is enough.
 *
 * .env:
 *   BREVO_API_KEY      your Brevo API key (v3)            — required to send real mail
 *   BREVO_FROM_EMAIL   sender address                      — must be a VERIFIED sender in your Brevo account
 *   BREVO_FROM_NAME    sender display name  [Nexus Storage]
 *
 * Needs Node 18+ (built-in fetch). The API key is only ever sent to Brevo and never logged.
 *
 * Local development: with no BREVO_API_KEY (and NODE_ENV not "production") the email is NOT sent;
 * the code is printed to the server console instead, so you can test without a Brevo account.
 */

const BREVO_URL = process.env.BREVO_API_URL || 'https://api.brevo.com/v3/smtp/email'; // override only for tests

const isConfigured = () => Boolean(process.env.BREVO_API_KEY && process.env.BREVO_FROM_EMAIL);

const COPY = {
  reset:        { subject: 'NEXUS STORAGE — password reset code',  heading: 'Reset your password',  line: 'Use this code to reset your Nexus Storage password.' },
  change:       { subject: 'NEXUS STORAGE — confirm password change', heading: 'Confirm password change', line: 'Use this code to confirm changing your Nexus Storage password.' },
  verify_email: { subject: 'NEXUS STORAGE — verify your email',    heading: 'Verify your email',    line: 'Use this code to link this email address to your Nexus Storage account.' },
};

function buildMessage(purpose, code, expiresMinutes) {
  const c = COPY[purpose] || COPY.reset;
  const text =
    `NEXUS STORAGE\n\n${c.heading}\n\n${c.line}\n\nYour code: ${code}\n\n` +
    `It expires in ${expiresMinutes} minutes and works once.\n` +
    `If you didn't ask for this, you can ignore this email — your account is unchanged. Never share this code with anyone.`;
  // Inline styles + tables only: that is what email clients render reliably.
  const html = `<!doctype html><html><body style="margin:0;padding:0;background:#0b0b12;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#0b0b12;padding:32px 12px;">
  <tr><td align="center">
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:440px;background:#14141f;border:1px solid #2c2a52;border-radius:18px;">
      <tr><td align="center" style="padding:34px 30px 8px;font-family:Segoe UI,Arial,sans-serif;">
        <div style="font-size:12px;letter-spacing:.28em;color:#8f84ff;font-weight:700;">NEXUS STORAGE</div>
        <div style="font-size:21px;color:#ffffff;font-weight:700;margin-top:14px;">${c.heading}</div>
        <div style="font-size:14px;color:#a3a3b8;line-height:1.55;margin-top:10px;">${c.line}</div>
      </td></tr>
      <tr><td align="center" style="padding:18px 30px;">
        <div style="display:inline-block;padding:16px 26px;background:#0d0d16;border:1px solid #7c6fff;border-radius:12px;font-family:Consolas,Menlo,monospace;font-size:34px;letter-spacing:.38em;color:#ffffff;font-weight:700;">${code}</div>
      </td></tr>
      <tr><td align="center" style="padding:0 30px 30px;font-family:Segoe UI,Arial,sans-serif;font-size:12.5px;color:#8a8aa0;line-height:1.6;">
        Expires in <b style="color:#c9c9dd;">${expiresMinutes} minutes</b> and works once.<br>
        Didn't request this? Ignore this email — nothing has changed.<br>
        Never share this code with anyone.
      </td></tr>
    </table>
  </td></tr>
</table></body></html>`;
  return { subject: c.subject, text, html };
}

/** Sends a one-time-code email. Rejects if the mail could not be handed to Brevo. */
async function sendOtpEmail({ to, code, purpose, expiresMinutes }) {
  if (!isConfigured()) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Email is not configured (set BREVO_API_KEY and BREVO_FROM_EMAIL).');
    }
    console.log(`[mail:dev] Brevo not configured — ${purpose} code for ${to}: ${code}  (expires in ${expiresMinutes} min)`);
    return;
  }

  const { subject, text, html } = buildMessage(purpose, code, expiresMinutes);
  let res;
  try {
    res = await fetch(BREVO_URL, {
      method: 'POST',
      headers: { 'api-key': process.env.BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({
        sender: { name: process.env.BREVO_FROM_NAME || 'Nexus Storage', email: process.env.BREVO_FROM_EMAIL },
        to: [{ email: to }],
        subject,
        htmlContent: html,
        textContent: text,
      }),
      signal: AbortSignal.timeout(10000),
    });
  } catch (err) {
    throw new Error(`Brevo request failed: ${err.name === 'TimeoutError' ? 'timed out' : err.message}`);
  }
  if (!res.ok) {
    let detail = '';
    try { detail = (await res.text()).slice(0, 300); } catch (e) { /* ignore */ }
    throw new Error(`Brevo rejected the email (HTTP ${res.status}) ${detail}`);
  }
}

module.exports = { sendOtpEmail, isConfigured, buildMessage };
