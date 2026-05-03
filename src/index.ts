import crypto from "node:crypto";
import express from "express";
import path from "node:path";
import fs from "node:fs";
import { eq, and } from "drizzle-orm";
import JWT from "jsonwebtoken";
import jose from "node-jose";
import { db } from "./db";
import {
  usersTable,
  applicationsTable,
  authorizationCodesTable,
} from "./db/schema";
import { PRIVATE_KEY, PUBLIC_KEY } from "./utils/cert";
import type { JWTClaims } from "./utils/user-token";

const app = express();
const PORT = process.env.PORT ?? 8000;

app.use(express.json());
app.use(express.static(path.resolve("public")));

app.get("/", (req, res) => res.json({ message: "Hello from Auth Server" }));

app.get("/health", (req, res) =>
  res.json({ message: "Server is healthy", healthy: true }),
);

// OIDC Endpoints
app.get("/.well-known/openid-configuration", (req, res) => {
  const ISSUER = `http://localhost:${PORT}`;
  return res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/o/authenticate`,
    token_endpoint: `${ISSUER}/o/token-info`,
    userinfo_endpoint: `${ISSUER}/o/userinfo`,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
  });
});

app.get("/.well-known/jwks.json", async (_, res) => {
  const key = await jose.JWK.asKey(PUBLIC_KEY, "pem");
  return res.json({ keys: [key.toJSON()] });
});

// ─── Admin Routes ───────────────────────────────────────────

app.get("/admin/register", (req, res) => {
  return res.sendFile(path.resolve("public", "register-app.html"));
});

app.post("/admin/register-app", async (req, res) => {
  const { displayName, applicationUrl, redirectUri } = req.body;

  if (!displayName || !applicationUrl || !redirectUri) {
    res
      .status(400)
      .json({ message: "Display name, application URL, and redirect URI are required." });
    return;
  }

  const clientId = crypto.randomBytes(32).toString("hex");
  const clientSecret = crypto.randomBytes(32).toString("hex");

  await db.insert(applicationsTable).values({
    displayName,
    applicationUrl,
    redirectUri,
    clientId,
    clientSecret,
  });

  res.status(201).json({ clientId, clientSecret });
});

// ─── OAuth Authenticate ─────────────────────────────────────

app.get("/o/authenticate", async (req, res) => {
  const clientId = req.query.client_id as string | undefined;

  if (!clientId) {
    res.status(400).json({ message: "client_id query parameter is required." });
    return;
  }

  const [application] = await db
    .select()
    .from(applicationsTable)
    .where(eq(applicationsTable.clientId, clientId))
    .limit(1);

  if (!application) {
    res.status(400).json({ message: "Invalid client_id." });
    return;
  }

  // Read the template and inject app name
  const templatePath = path.resolve("public", "authenticate.html");
  let html = fs.readFileSync(templatePath, "utf-8");
  html = html.replace("{{APP_NAME}}", application.displayName);

  res.type("html").send(html);
});

app.post("/o/authenticate/sign-in", async (req, res) => {
  const { email, password, client_id } = req.body;

  if (!email || !password) {
    res.status(400).json({ message: "Email and password are required." });
    return;
  }

  // Validate user credentials
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if (!user || !user.password || !user.salt) {
    res.status(401).json({ message: "Invalid email or password." });
    return;
  }

  const hash = crypto
    .createHash("sha256")
    .update(password + user.salt)
    .digest("hex");

  if (hash !== user.password) {
    res.status(401).json({ message: "Invalid email or password." });
    return;
  }

  // If client_id is provided, do the OAuth code flow
  if (client_id) {
    const [application] = await db
      .select()
      .from(applicationsTable)
      .where(eq(applicationsTable.clientId, client_id))
      .limit(1);

    if (!application) {
      res.status(400).json({ message: "Invalid client_id." });
      return;
    }

    // Generate short code
    const code = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 60 * 1000); // 1 minute

    await db.insert(authorizationCodesTable).values({
      code,
      userId: user.id,
      applicationId: application.id,
      expiresAt,
    });

    const redirectUrl = `${application.redirectUri}?code=${code}`;
    res.json({ redirect: redirectUrl });
    return;
  }

  // Fallback: no client_id, just return token directly (existing behavior)
  const ISSUER = `http://localhost:${PORT}`;
  const now = Math.floor(Date.now() / 1000);

  const claims: JWTClaims = {
    iss: ISSUER,
    sub: user.id,
    email: user.email,
    email_verified: String(user.emailVerified),
    exp: now + 3600,
    given_name: user.firstName ?? "",
    family_name: user.lastName ?? undefined,
    name: [user.firstName, user.lastName].filter(Boolean).join(" "),
    picture: user.profileImageURL ?? undefined,
  };

  const token = JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });

  res.json({ token });
});

app.post("/o/authenticate/sign-up", async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  if (!email || !password || !firstName) {
    res
      .status(400)
      .json({ message: "First name, email, and password are required." });
    return;
  }

  const [existing] = await db
    .select({ id: usersTable.id })
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if (existing) {
    res
      .status(409)
      .json({ message: "An account with this email already exists." });
    return;
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto
    .createHash("sha256")
    .update(password + salt)
    .digest("hex");

  await db.insert(usersTable).values({
    firstName,
    lastName: lastName ?? null,
    email,
    password: hash,
    salt,
  });

  res.status(201).json({ ok: true });
});

// ─── Token Exchange ─────────────────────────────────────────

app.post("/o/token-info", async (req, res) => {
  const { code, client_secret } = req.body;

  if (!code || !client_secret) {
    res.status(400).json({ message: "code and client_secret are required." });
    return;
  }

  // Find the application by client_secret
  const [application] = await db
    .select()
    .from(applicationsTable)
    .where(eq(applicationsTable.clientSecret, client_secret))
    .limit(1);

  if (!application) {
    res.status(401).json({ message: "Invalid client_secret." });
    return;
  }

  // Find the authorization code
  const [authCode] = await db
    .select()
    .from(authorizationCodesTable)
    .where(
      and(
        eq(authorizationCodesTable.code, code),
        eq(authorizationCodesTable.applicationId, application.id),
      ),
    )
    .limit(1);

  if (!authCode) {
    res.status(400).json({ message: "Invalid authorization code." });
    return;
  }

  if (authCode.used) {
    res.status(400).json({ message: "Authorization code has already been used." });
    return;
  }

  if (new Date() > authCode.expiresAt) {
    res.status(400).json({ message: "Authorization code has expired." });
    return;
  }

  // Mark code as used
  await db
    .update(authorizationCodesTable)
    .set({ used: true })
    .where(eq(authorizationCodesTable.id, authCode.id));

  // Fetch the user
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, authCode.userId))
    .limit(1);

  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  // Generate JWT token
  const ISSUER = `http://localhost:${PORT}`;
  const now = Math.floor(Date.now() / 1000);

  const claims: JWTClaims = {
    iss: ISSUER,
    sub: user.id,
    email: user.email,
    email_verified: String(user.emailVerified),
    exp: now + 3600,
    given_name: user.firstName ?? "",
    family_name: user.lastName ?? undefined,
    name: [user.firstName, user.lastName].filter(Boolean).join(" "),
    picture: user.profileImageURL ?? undefined,
  };

  const token = JWT.sign(claims, PRIVATE_KEY, { algorithm: "RS256" });

  res.json({ token });
});

// ─── User Info ──────────────────────────────────────────────

app.get("/o/userinfo", async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    res
      .status(401)
      .json({ message: "Missing or invalid Authorization header." });
    return;
  }

  const token = authHeader.slice(7);

  let claims: JWTClaims;
  try {
    claims = JWT.verify(token, PUBLIC_KEY, {
      algorithms: ["RS256"],
    }) as JWTClaims;
  } catch {
    res.status(401).json({ message: "Invalid or expired token." });
    return;
  }

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, claims.sub))
    .limit(1);

  if (!user) {
    res.status(404).json({ message: "User not found." });
    return;
  }

  res.json({
    sub: user.id,
    email: user.email,
    email_verified: user.emailVerified,
    given_name: user.firstName,
    family_name: user.lastName,
    name: [user.firstName, user.lastName].filter(Boolean).join(" "),
    picture: user.profileImageURL,
  });
});

app.listen(PORT, () => {
  console.log(`AuthServer is running on PORT ${PORT}`);
});
