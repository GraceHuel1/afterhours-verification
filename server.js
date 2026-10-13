const crypto = require("node:crypto");
const path = require("node:path");
const express = require("express");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = Number(process.env.PORT || 10000);
const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const REDIRECT_URI = process.env.DISCORD_REDIRECT_URI;
const SESSION_SECRET = process.env.SESSION_SECRET;
const PROD = process.env.NODE_ENV === "production";

for (const [key, value] of Object.entries({
  DISCORD_CLIENT_ID: CLIENT_ID, DISCORD_CLIENT_SECRET: CLIENT_SECRET,
  DISCORD_REDIRECT_URI: REDIRECT_URI, SESSION_SECRET
})) {
  if (!value) { console.error(`Missing environment variable: ${key}`); process.exit(1); }
}
if (SESSION_SECRET.length < 32) {
  console.error("SESSION_SECRET must be at least 32 characters."); process.exit(1);
}
if (PROD && !/^https:\/\/.+\/auth\/discord\/callback$/.test(REDIRECT_URI)) {
  console.error("Production redirect URI must be HTTPS and end with /auth/discord/callback.");
  process.exit(1);
}

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], styleSrc: ["'self'", "https://fonts.googleapis.com"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"], scriptSrc: ["'self'"],
    imgSrc: ["'self'", "data:", "https://cdn.discordapp.com"],
    connectSrc: ["'self'"], objectSrc: ["'none'"], baseUri: ["'self'"],
    frameAncestors: ["'none'"], formAction: ["'self'", "https://discord.com"]
  } }
}));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public"), { maxAge: PROD ? "1h" : 0 }));
app.use("/auth", rateLimit({
  windowMs: 15 * 60 * 1000, limit: 30,
  standardHeaders: "draft-7", legacyHeaders: false
}));

const cookieOptions = { httpOnly: true, secure: PROD, sameSite: "lax", path: "/" };
const sign = value => crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("base64url");
function equal(a, b) {
  const x = Buffer.from(String(a || "")), y = Buffer.from(String(b || ""));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function setSignedCookie(res, name, data, seconds) {
  const payload = Buffer.from(JSON.stringify(data)).toString("base64url");
  res.cookie(name, `${payload}.${sign(payload)}`, { ...cookieOptions, maxAge: seconds * 1000 });
}
function readSignedCookie(req, name) {
  const raw = req.cookies[name];
  if (!raw || typeof raw !== "string") return null;
  const i = raw.lastIndexOf(".");
  if (i < 1 || !equal(raw.slice(i + 1), sign(raw.slice(0, i)))) return null;
  try {
    const value = JSON.parse(Buffer.from(raw.slice(0, i), "base64url").toString());
    return value.exp > Date.now() ? value : null;
  } catch { return null; }
}
function escapeHtml(v) {
  return String(v || "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}
function resultPage(title, message, user = null) {
  const avatar = user && user.avatar
    ? `<img class="avatar" src="${escapeHtml(user.avatar)}" alt="" referrerpolicy="no-referrer">`
    : `<div class="avatar placeholder">♡</div>`;
  const name = user ? `<div class="identity">${escapeHtml(user.name)}</div>` : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#10080f">
  <title>${escapeHtml(title)} · AFTERHOURS</title><link rel="stylesheet" href="/styles.css"></head>
  <body><main class="shell"><div class="orb orb-one"></div><div class="orb orb-two"></div>
  <section class="card result"><div class="brand-mark">୨୧</div><p class="eyebrow">AFTERHOURS · MEMBER PORTAL</p>
  ${avatar}<h1>${escapeHtml(title)}</h1><p class="subtitle">${escapeHtml(message)}</p>${name}
  <a class="button secondary" href="/">Return home</a>
  <p class="fineprint">This confirms your Discord identity only. It does not assign server roles.</p></section></main></body></html>`;
}

app.get("/healthz", (_req, res) => res.status(200).send("ok"));
app.get("/auth/discord", (_req, res) => {
  const state = crypto.randomBytes(32).toString("base64url");
  setSignedCookie(res, "ah_oauth_state", { state, exp: Date.now() + 10 * 60 * 1000 }, 600);
  const url = new URL("https://discord.com/oauth2/authorize");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", REDIRECT_URI);
  url.searchParams.set("scope", "identify");
  url.searchParams.set("state", state);
  res.redirect(302, url.toString());
});
app.get("/auth/discord/callback", async (req, res) => {
  const expected = readSignedCookie(req, "ah_oauth_state");
  res.clearCookie("ah_oauth_state", cookieOptions);
  const code = typeof req.query.code === "string" ? req.query.code : "";
  const state = typeof req.query.state === "string" ? req.query.state : "";
  if (!expected || !state || !equal(expected.state, state)) {
    return res.status(400).send(resultPage("Link expired", "Please return to AFTERHOURS and start again."));
  }
  if (req.query.error) {
    return res.status(400).send(resultPage("Authorization cancelled", "You cancelled Discord authorization. You can try again."));
  }
  if (!code) return res.status(400).send(resultPage("Could not verify", "Discord did not return an authorization code. Please try again."));
  try {
    const tokenRes = await fetch("https://discord.com/api/v10/oauth2/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
        grant_type: "authorization_code", code, redirect_uri: REDIRECT_URI
      }),
      signal: AbortSignal.timeout(10000)
    });
    if (!tokenRes.ok) {
      console.error("Discord token exchange status:", tokenRes.status);
      return res.status(502).send(resultPage("Discord unavailable", "We couldn't complete verification. Please try again later."));
    }
    const token = await tokenRes.json();
    if (!token.access_token) throw new Error("No access token in Discord response");
    const userRes = await fetch("https://discord.com/api/v10/users/@me", {
      headers: { Authorization: `Bearer ${token.access_token}` },
      signal: AbortSignal.timeout(10000)
    });
    if (!userRes.ok) {
      console.error("Discord profile status:", userRes.status);
      return res.status(502).send(resultPage("Profile unavailable", "We couldn't load your Discord profile. Please try again."));
    }
    const user = await userRes.json();
    if (!user.id || !user.username) throw new Error("Incomplete Discord profile");
    const avatar = user.avatar
      ? `https://cdn.discordapp.com/avatars/${encodeURIComponent(user.id)}/${encodeURIComponent(user.avatar)}.png?size=128`
      : "";
    setSignedCookie(res, "ah_session", {
      userId: user.id, username: user.username, name: user.global_name || user.username,
      avatar, exp: Date.now() + 60 * 60 * 1000
    }, 3600);
    // The access token is intentionally not stored or logged.
    res.set("Cache-Control", "no-store");
    return res.send(resultPage("Identity confirmed", "Your Discord identity has been authenticated successfully.", {
      name: user.global_name || user.username, avatar
    }));
  } catch (e) {
    console.error("OAuth callback error:", e.message);
    return res.status(502).send(resultPage("Something went wrong", "We couldn't finish verification. Please try again shortly."));
  }
});
app.get("/api/me", (req, res) => {
  const session = readSignedCookie(req, "ah_session");
  res.set("Cache-Control", "no-store");
  if (!session) return res.status(401).json({ authenticated: false });
  res.json({ authenticated: true, user: {
    id: session.userId, username: session.username, name: session.name, avatar: session.avatar
  }});
});
app.post("/auth/logout", (_req, res) => {
  res.clearCookie("ah_session", cookieOptions);
  res.redirect(303, "/");
});
app.get("/privacy", (req, res) => {
  res.set("Cache-Control", "public, max-age=300");
  res.type("html").send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#10080f">
  <title>Privacy Policy | AFTERHOURS</title>
  <link rel="stylesheet" href="/styles.css">
  <style>
    body {
      background: #10080f;
      color: #f9eaf3;
      font-family: Arial, sans-serif;
      line-height: 1.8;
      margin: 0;
    }
    .privacy-container {
      max-width: 780px;
      margin: 60px auto;
      padding: 35px;
      background: #1b101a;
      border: 1px solid #66334f;
      border-radius: 20px;
    }
    h1, h2 { color: #ff91c3; }
    h1 { text-align: center; }
    h2 { margin-top: 30px; }
    .subtitle {
      text-align: center;
      color: #c9a4b9;
    }
    a { color: #ff91c3; }
    footer {
      text-align: center;
      color: #b99aaa;
      margin-top: 40px;
    }
    @media(max-width: 600px) {
      .privacy-container {
        margin: 15px;
        padding: 22px;
      }
    }
  </style>
</head>
<body>
  <main class="privacy-container">
    <h1>୨୧ AFTERHOURS</h1>
    <p class="subtitle">PRIVACY POLICY</p>
    <p class="subtitle">Last updated: October 13, 2026</p>

    <h2>1. Introduction</h2>
    <p>
      Welcome to AFTERHOURS. We respect your privacy.
      This policy explains how our Discord identity
      verification service processes your information.
    </p>

    <h2>2. Information We Process</h2>
    <p>
      When you authorize our verification service
      through Discord OAuth2, we process:
    </p>
    <ul>
      <li>Discord User ID</li>
      <li>Discord username</li>
      <li>Discord display name</li>
      <li>Discord avatar information</li>
      <li>Temporary authentication information</li>
    </ul>

    <h2>3. How We Use Information</h2>
    <p>
      We use this information to authenticate your
      Discord identity, display verification results,
      and maintain a temporary authenticated session.
    </p>

    <h2>4. Cookies and Sessions</h2>
    <p>
      Our website uses temporary cookies for OAuth2
      security and authenticated sessions.
      The authentication state cookie lasts up to
      10 minutes. The session cookie lasts up to
      60 minutes.
    </p>

    <h2>5. Discord Access Tokens</h2>
    <p>
      Discord access tokens are used to retrieve
      your Discord identity. Our application does
      not intentionally store or log these tokens.
    </p>

    <h2>6. Data Sharing</h2>
    <p>
      We do not sell your personal information.
      Discord and our hosting provider may process
      information necessary to operate this service.
    </p>

    <h2>7. Data Retention</h2>
    <p>
      Authentication cookies expire automatically.
      Additional technical records may be retained
      by service providers according to their
      applicable policies.
    </p>

    <h2>8. Security</h2>
    <p>
      We use security measures including signed
      cookies, OAuth2 state validation, HTTPS
      in production, and request rate limiting.
    </p>

    <h2>9. Your Privacy Rights</h2>
    <p>
      You may contact our team to request
      information about personal data processed
      by our service, or request its deletion,
      subject to applicable law.
    </p>

    <h2>10. Third-Party Services</h2>
    <p>
      Our website uses Discord OAuth2 and
      Render hosting. These providers have
      their own privacy policies.
    </p>

    <h2>11. Policy Changes</h2>
    <p>
      We may update this Privacy Policy.
      The latest version will be available
      on this page.
    </p>

    <h2>12. Contact</h2>
    <p>
      For privacy questions or data requests,
      contact the AFTERHOURS moderation team:
    </p>
    <p>
      <a href="https://discord.gg/4zxdjFF5K">
        Join AFTERHOURS on Discord
      </a>
    </p>

    <footer>
      © 2026 AFTERHOURS · All rights reserved
    </footer>
  </main>
</body>
</html>
  `);
});

app.get("/terms", (req, res) => {
  res.type("html").send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport"
        content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#10080f">
  <title>Terms of Service | AFTERHOURS</title>
  <style>
    * { box-sizing: border-box; }

    body {
      margin: 0;
      background: #10080f;
      color: #f9eaf3;
      font-family: Arial, sans-serif;
      line-height: 1.8;
    }

    .container {
      max-width: 800px;
      margin: 60px auto;
      padding: 40px;
      background: #1b101a;
      border: 1px solid #66334f;
      border-radius: 20px;
    }

    h1 {
      color: #ff91c3;
      text-align: center;
      font-size: 36px;
    }

    h2 {
      color: #ff91c3;
      margin-top: 30px;
    }

    .subtitle {
      text-align: center;
      color: #c9a4b9;
    }

    a {
      color: #ff91c3;
      text-decoration: none;
    }

    a:hover {
      text-decoration: underline;
    }

    footer {
      text-align: center;
      margin-top: 40px;
      color: #b99aaa;
      font-size: 13px;
    }

    @media (max-width: 600px) {
      .container {
        margin: 15px;
        padding: 22px;
      }
    }
  </style>
</head>
<body>
  <main class="container">

    <h1>୨୧ AFTERHOURS</h1>
    <p class="subtitle">TERMS OF SERVICE</p>
    <p class="subtitle">
      Last updated: October 13, 2026
    </p>

    <h2>1. Acceptance of Terms</h2>
    <p>
      By accessing or using the AFTERHOURS
      Discord verification service, you agree
      to these Terms of Service.
      If you do not agree, please do not use
      the verification service.
    </p>

    <h2>2. About Our Service</h2>
    <p>
      AFTERHOURS provides a Discord OAuth2
      identity verification service.
      The service allows users to authenticate
      their Discord identity through Discord.
    </p>

    <h2>3. Eligibility</h2>
    <p>
      You must meet Discord's applicable
      minimum age requirements and comply
      with Discord's Terms of Service.
    </p>

    <h2>4. User Responsibilities</h2>
    <p>
      You agree to use the service responsibly,
      provide authorization through your own
      Discord account, and follow applicable
      Discord policies and community rules.
    </p>

    <h2>5. Prohibited Activities</h2>
    <p>
      Users may not abuse the verification
      system, impersonate others, attempt
      unauthorized access, or interfere
      with the service's operation.
    </p>

    <h2>6. Verification</h2>
    <p>
      Authentication confirms the Discord
      identity associated with the account
      used to authorize the service.
      It does not independently confirm
      a person's real-world identity.
    </p>

    <h2>7. Availability</h2>
    <p>
      We aim to keep the verification
      service available but cannot
      guarantee uninterrupted operation.
      Maintenance, technical problems,
      or third-party outages may affect
      availability.
    </p>

    <h2>8. Privacy</h2>
    <p>
      Information processed through our
      verification service is described
      in our
      <a href="/privacy">Privacy Policy</a>.
    </p>

    <h2>9. Service Restrictions</h2>
    <p>
      We may restrict access to the service
      when reasonably necessary to protect
      its security, prevent abuse, or comply
      with applicable requirements.
    </p>

    <h2>10. Changes to These Terms</h2>
    <p>
      We may update these Terms of Service.
      Updated terms will be published
      on this page.
    </p>

    <h2>11. Contact</h2>
    <p>
      For questions about these terms,
      contact the AFTERHOURS moderation
      team through our Discord community.
    </p>

    <p>
      <a href="https://discord.gg/4zxdjFF5K">
        Join AFTERHOURS Discord
      </a>
    </p>

    <footer>
      <p>© 2026 AFTERHOURS</p>
      <p>
        <a href="/">Home</a> ·
        <a href="/privacy">Privacy Policy</a> ·
        <a href="/terms">Terms of Service</a>
      </p>
    </footer>

  </main>
</body>
</html>
  `);
});

app.listen(PORT, "0.0.0.0", () => console.log(`AFTERHOURS site listening on ${PORT}`));
