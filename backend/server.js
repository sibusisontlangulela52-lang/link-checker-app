// dotenv must load BEFORE anything reads process.env
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

const app = express();
const PORT = process.env.PORT || 5000;

// Supabase client (backend only - uses the SECRET key, never put it in the frontend)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);

// Codespaces / most hosts sit behind a proxy
app.set("trust proxy", 1);

// Middleware
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || "*" }));
app.use(express.json({ limit: "10kb" }));

// Max 20 checks per minute per IP
app.use(
  "/api/",
  rateLimit({
    windowMs: 60 * 1000,
    max: 20,
    message: { error: "Too many requests. Please wait a minute and try again." },
  })
);

// Test route
app.get("/", (req, res) => {
  res.json({
    message: "LinkGuard backend is running successfully!",
  });
});

// ---------- Auth helpers ----------

// Reads the "Authorization: Bearer <token>" header and asks Supabase who it belongs to.
// Returns the user, or null if nobody is logged in / the token is invalid.
async function getUserFromRequest(req) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;

  if (!token) return null;

  try {
    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data?.user) return null;
    return data.user;
  } catch (error) {
    return null;
  }
}

// Looks up the user's plan. Anything unexpected falls back to "free".
async function getPlan(userId) {
  try {
    const { data, error } = await supabase
      .from("profiles")
      .select("plan, premium_until")
      .eq("id", userId)
      .single();

    if (error || !data) return "free";

    const stillValid =
      !data.premium_until || new Date(data.premium_until) > new Date();

    return data.plan === "premium" && stillValid ? "premium" : "free";
  } catch (error) {
    return "free";
  }
}

// ---------- URL analysis ----------

const SUSPICIOUS_WORDS = [
  "login",
  "signin",
  "verify",
  "account",
  "password",
  "secure",
  "update",
  "free",
  "winner",
  "claim",
  "urgent",
  "bonus",
];

const SUSPICIOUS_TLDS = [".zip", ".xyz", ".top", ".tk", ".click", ".gq", ".ml"];

const SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly"];

function analyseUrl(parsedUrl) {
  const reasons = [];
  let score = 0;

  const hostname = parsedUrl.hostname.toLowerCase();

  // 1. No HTTPS
  if (parsedUrl.protocol !== "https:") {
    score += 30;
    reasons.push("it does not use HTTPS");
  }

  // 2. IP address instead of a domain name
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 40;
    reasons.push("it uses an IP address instead of a domain name");
  }

  // 3. Credentials in the URL (e.g. https://paypal.com@evil.com)
  if (parsedUrl.username || parsedUrl.password) {
    score += 40;
    reasons.push("it contains a username or password before the domain");
  }

  // 4. Punycode (can be used for lookalike domains)
  if (hostname.startsWith("xn--") || hostname.includes(".xn--")) {
    score += 30;
    reasons.push("it uses an internationalised domain that can imitate other sites");
  }

  // 5. Too many subdomains
  if (hostname.split(".").length > 4) {
    score += 15;
    reasons.push("it has an unusually large number of subdomains");
  }

  // 6. Very long URL
  if (parsedUrl.href.length > 100) {
    score += 10;
    reasons.push("the URL is unusually long");
  }

  // 7. Suspicious top-level domain
  if (SUSPICIOUS_TLDS.some((tld) => hostname.endsWith(tld))) {
    score += 20;
    reasons.push("it uses a top-level domain often abused in scams");
  }

  // 8. URL shortener
  if (SHORTENERS.includes(hostname)) {
    score += 15;
    reasons.push("it is a shortened link that hides the real destination");
  }

  // 9. Suspicious words (matched as whole words, so "freedom" won't trigger "free")
  const tokens = parsedUrl.href.toLowerCase().split(/[^a-z0-9]+/);
  const matchedWords = SUSPICIOUS_WORDS.filter((word) => tokens.includes(word));

  if (matchedWords.length > 0) {
    score += Math.min(matchedWords.length * 15, 30);
    reasons.push(
      `it contains words often used in phishing (${matchedWords.join(", ")})`
    );
  }

  score = Math.min(score, 100);

  let risk = "Low";
  if (score >= 60) risk = "High";
  else if (score >= 25) risk = "Medium";

  const message =
    reasons.length === 0
      ? "No obvious suspicious patterns were detected."
      : `Flagged because ${reasons.join("; ")}.`;

  return { risk, riskScore: score || 5, message };
}

// ---------- Link checking route ----------

app.post("/api/check", async (req, res) => {
  let { url } = req.body || {};

  if (!url || typeof url !== "string") {
    return res.status(400).json({ error: "Please provide a URL." });
  }

  url = url.trim();

  if (url.length > 2048) {
    return res.status(400).json({ error: "That URL is too long." });
  }

  // Add https:// only if the user didn't type any protocol
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) {
    url = "https://" + url;
  }

  // Validate the URL on its own so other errors aren't mislabelled as "invalid URL"
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (error) {
    return res.status(400).json({ error: "The URL you entered is not valid." });
  }

  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    return res
      .status(400)
      .json({ error: "Only http and https links can be checked." });
  }

  // Who is asking? (null if not logged in)
  const user = await getUserFromRequest(req);
  const plan = user ? await getPlan(user.id) : "free";

  const { risk, riskScore, message } = analyseUrl(parsedUrl);

  // Save the scan. If saving fails, still return the result to the user.
  let saved = true;
  try {
    const { error: databaseError } = await supabase.from("scans").insert([
      {
        url: parsedUrl.href,
        risk_level: risk,
        risk_score: riskScore,
        message: message,
        user_id: user ? user.id : null,
      },
    ]);

    if (databaseError) {
      saved = false;
      console.error("Database error:", databaseError);
    }
  } catch (error) {
    saved = false;
    console.error("Database error:", error);
  }

  res.json({
    url: parsedUrl.href,
    risk,
    riskScore,
    message,
    plan,
    saved,
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`LinkGuard backend running on http://localhost:${PORT}`);
});
