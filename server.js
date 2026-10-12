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
const BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
const GUILD_ID = process.env.DISCORD_GUILD_ID;
const VERIFIED_ROLE_ID = process.env.DISCORD_VERIFIED_ROLE_ID;
const SESSION_SECRET = process.env.SESSION_SECRET;
const PROD = process.env.NODE_ENV === "production";

for (const [key, value] of Object.entries({
  DISCORD_CLIENT_ID: CLIENT_ID, DISCORD_CLIENT_SECRET: CLIENT_SECRET,
  DISCORD_REDIRECT_URI: REDIRECT_URI, SESSION_SECRET
  DISCORD_BOT_TOKEN: BOT_TOKEN,
DISCORD_GUILD_ID: GUILD_ID,
DISCORD_VERIFIED_ROLE_ID: VERIFIED_ROLE_ID,
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
    <p class="fineprint">AFTERHOURS · Discord verification</p></section></main></body></html>`;    <p class="fineprint">AFTERHOURS · Discord verification</p></section></main></body></html>`;    <p class="fineprint">AFTERHOURS · Discord verification</p></section></main></body></html>`;    <p class="fineprint">AFTERHOURS · Discord verification</p></section></main></body></html>`;    <p class="fineprint">AFTERHOURS · Discord verification</p></section></main></body></html>`;    <p class="fineprint">AFTERHOURS · Discord verification</p></section></main></body></html>`;    <p class="fineprint">AFTERHOURS · Discord verification</p></section></main></body></html>`;    <p class="fineprint">AFTERHOURS · Discord verification</p></section></main></body></html>`;    <p class="fineprint">AFTERHOURS · Discord verification</p></section></main></body></html>`;
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
        // Confirm the authenticated Discord user is already in AFTERHOURS.
    const memberRes = await fetch(
      `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${user.id}`,
      {
        headers: { Authorization: `Bot ${BOT_TOKEN}` },
        signal: AbortSignal.timeout(10000)
      }
    );

    if (memberRes.status === 404) {
      return res.status(403).send(resultPage(
        "Join AFTERHOURS first",
        "You need to join the AFTERHOURS Discord server before verifying."
      ));
    }

    if (!memberRes.ok) {
      console.error("Discord member check status:", memberRes.status);
      return res.status(502).send(resultPage(
        "Verification unavailable",
        "We couldn't check your server membership. Please try again later."
      ));
    }

    // Assign the Verified role using the bot.
    const roleRes = await fetch(
      `https://discord.com/api/v10/guilds/${GUILD_ID}/members/${user.id}/roles/${VERIFIED_ROLE_ID}`,
      {
        method: "PUT",
        headers: {
          Authorization: `Bot ${BOT_TOKEN}`,
          "X-Audit-Log-Reason": "Member completed AFTERHOURS website verification"
        },
        signal: AbortSignal.timeout(10000)
      }
    );

    if (!roleRes.ok) {
      console.error("Discord role assignment status:", roleRes.status);
      return res.status(502).send(resultPage(
        "Role assignment failed",
        "Your identity was confirmed, but we couldn't assign the Verified role. Please contact an AFTERHOURS moderator."
      ));
    }
    const avatar = user.avatar
      ? `https://cdn.discordapp.com/avatars/${encodeURIComponent(user.id)}/${encodeURIComponent(user.avatar)}.png?size=128`
      : "";
    setSignedCookie(res, "ah_session", {
      userId: user.id, username: user.username, name: user.global_name || user.username,
      avatar, exp: Date.now() + 60 * 60 * 1000
    }, 3600);
    // The access token is intentionally not stored or logged.
    res.set("Cache-Control", "no-store");
    return res.send(resultPage("You're verified!", "Your Discord identity is confirmed and your Verified role has been assigned.", {
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
app.listen(PORT, "0.0.0.0", () => console.log(`AFTERHOURS site listening on ${PORT}`));
