// Fires when someone submits the "notify" waitlist form on reedrides.com.
// Netlify calls this via a signed "Outgoing webhook" form notification
// (Site configuration -> Notifications -> Forms -> notify -> Outgoing webhook).
//
// It (1) sends the signer a confirmation email and (2) adds them as a
// contact in Resend so the full list can get one broadcast on launch day.
//
// Requires two env vars, set in Netlify (Site configuration -> Environment
// variables), never committed here:
//   RESEND_API_KEY          - a Resend API key with "Sending access"
//   NETLIFY_WEBHOOK_SECRET   - the same secret entered on the Outgoing
//                              webhook notification's "Secret" field

const crypto = require('crypto');

const RESEND_API_KEY = process.env.RESEND_API_KEY;
const WEBHOOK_SECRET = process.env.NETLIFY_WEBHOOK_SECRET;
const FROM_EMAIL = 'Reed Rides <hello@reedrides.com>';
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function base64UrlDecode(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(padded, 'base64');
}

function base64UrlEncode(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Verifies Netlify's X-Webhook-Signature header: a JWT (HS256) whose
// payload carries { iss: "netlify", sha256: <hex sha256 of raw body> }.
// See: https://docs.netlify.com/deploy/deploy-notifications/
function verifyNetlifySignature(token, secret, rawBody) {
  if (!token || !secret) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  const [headerB64, payloadB64, sigB64] = parts;

  const expectedSig = base64UrlEncode(
    crypto.createHmac('sha256', secret).update(`${headerB64}.${payloadB64}`).digest()
  );

  const a = Buffer.from(expectedSig);
  const b = Buffer.from(sigB64);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;

  let claims;
  try {
    claims = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
  } catch {
    return false;
  }
  if (claims.iss !== 'netlify') return false;

  const bodyHash = crypto.createHash('sha256').update(rawBody).digest('hex');
  return claims.sha256 === bodyHash;
}

async function resendRequest(path, body) {
  const res = await fetch(`https://api.resend.com${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Resend ${path} -> ${res.status}: ${text}`);
  }
  return res.json().catch(() => ({}));
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: 'Method Not Allowed' };
  }

  if (!RESEND_API_KEY || !WEBHOOK_SECRET) {
    console.error('notify-signup: missing RESEND_API_KEY or NETLIFY_WEBHOOK_SECRET');
    return { statusCode: 500, body: 'Server not configured' };
  }

  const rawBody = event.isBase64Encoded
    ? Buffer.from(event.body || '', 'base64')
    : Buffer.from(event.body || '', 'utf8');

  const signature =
    event.headers['x-webhook-signature'] || event.headers['X-Webhook-Signature'];

  if (!verifyNetlifySignature(signature, WEBHOOK_SECRET, rawBody)) {
    console.warn('notify-signup: rejected request with invalid/missing signature');
    return { statusCode: 401, body: 'Invalid signature' };
  }

  let parsed;
  try {
    parsed = JSON.parse(rawBody.toString('utf8'));
  } catch {
    return { statusCode: 400, body: 'Bad JSON' };
  }

  const submission = parsed.payload || parsed;
  const formName = submission.form_name;
  const data = submission.data || {};

  if (formName !== 'notify') {
    return { statusCode: 200, body: 'ignored: not the notify form' };
  }

  if (data['bot-field']) {
    console.warn('notify-signup: honeypot tripped, ignoring');
    return { statusCode: 200, body: 'ignored: spam' };
  }

  const email = String(submission.email || data.email || '').trim();
  if (!EMAIL_PATTERN.test(email)) {
    return { statusCode: 200, body: 'ignored: invalid email' };
  }

  const tasks = [
    resendRequest('/emails', {
      from: FROM_EMAIL,
      to: email,
      reply_to: 'reed@reedrides.com',
      subject: "You're on the list",
      text:
        "Thanks for signing up for Reed Rides.\n\n" +
        "We'll send you one email, the day the app goes live on the App Store and Google Play. " +
        "That's it, nothing before then.\n\n" +
        '- Reed',
      html:
        '<p>Thanks for signing up for Reed Rides.</p>' +
        "<p>We'll send you one email, the day the app goes live on the App Store and Google Play. " +
        "That's it, nothing before then.</p>" +
        '<p>- Reed</p>',
    }),
    resendRequest('/contacts', {
      email,
      unsubscribed: false,
      properties: {
        source: 'reedrides.com waitlist',
        signed_up_at: new Date().toISOString(),
      },
    }),
  ];

  const results = await Promise.allSettled(tasks);
  results.forEach((r, i) => {
    if (r.status === 'rejected') {
      console.error(`notify-signup: task ${i} failed:`, r.reason?.message || r.reason);
    }
  });

  // Always 200 back to Netlify - it doesn't retry on failure, and a
  // Resend hiccup shouldn't make Netlify think the notification itself failed.
  return { statusCode: 200, body: 'ok' };
};
