import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { EncryptJWT, jwtDecrypt } from "jose";
import { env } from "../config/env.js";
import { pool } from "../db/pool.js";

const cookieOptions = { httpOnly: true, sameSite: "lax" as const, secure: env.NODE_ENV === "production", path: "/" };
const sessionKey = createHash("sha256").update(env.SESSION_SECRET).digest();

function encryptionKey(): Uint8Array {
  const key = Buffer.from(env.ENCRYPTION_KEY, "base64");
  if (key.length !== 32) throw new Error("ENCRYPTION_KEY must be a base64-encoded 32-byte key");
  return key;
}

export async function startGithubOAuth(reply: import("fastify").FastifyReply) {
  if (!env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) throw new Error("GitHub OAuth is not configured");
  const state = randomBytes(32).toString("hex");
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  reply.setCookie("github_oauth_state", state, { ...cookieOptions, maxAge: 600 });
  reply.setCookie("github_oauth_verifier", verifier, { ...cookieOptions, maxAge: 600 });
  const authorize = new URL("https://github.com/login/oauth/authorize");
  authorize.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  authorize.searchParams.set("redirect_uri", `${env.API_URL}/api/auth/github/callback`);
  authorize.searchParams.set("scope", "offline_access");
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("code_challenge", challenge);
  authorize.searchParams.set("code_challenge_method", "S256");
  return authorize.toString();
}

export async function finishGithubOAuth(input: { code: string; state: string; cookieState?: string; codeVerifier?: string }) {
  const { code, state, cookieState, codeVerifier } = input;
  if (!cookieState || state.length !== cookieState.length || !timingSafeEqual(Buffer.from(state), Buffer.from(cookieState))) {
    throw new Error("Invalid OAuth state");
  }
  if (!codeVerifier) throw new Error("Missing OAuth PKCE verifier");
  const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST", headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code, code_verifier: codeVerifier }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!tokenResponse.ok) throw new Error("GitHub token exchange failed");
  const tokenBody = await tokenResponse.json() as { access_token?: string; refresh_token?: string; expires_in?: number; refresh_token_expires_in?: number; error?: string };
  if (!tokenBody.access_token) throw new Error(tokenBody.error ?? "GitHub did not return an access token");
  const profileResponse = await fetch("https://api.github.com/user", { headers: { authorization: `Bearer ${tokenBody.access_token}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28" }, signal: AbortSignal.timeout(10_000) });
  if (!profileResponse.ok) throw new Error("GitHub profile lookup failed");
  const profile = await profileResponse.json() as { id: number; login: string; name?: string | null; avatar_url?: string | null };
  const encryptedToken = await new EncryptJWT({ token: tokenBody.access_token }).setProtectedHeader({ alg: "dir", enc: "A256GCM" }).setIssuedAt().encrypt(encryptionKey());
  const encryptedRefresh = tokenBody.refresh_token ? await new EncryptJWT({ token: tokenBody.refresh_token }).setProtectedHeader({ alg: "dir", enc: "A256GCM" }).setIssuedAt().encrypt(encryptionKey()) : null;
  const accessExpiresAt = tokenBody.expires_in ? new Date(Date.now() + tokenBody.expires_in * 1000) : null;
  const refreshExpiresAt = tokenBody.refresh_token_expires_in ? new Date(Date.now() + tokenBody.refresh_token_expires_in * 1000) : null;
  const db = await pool.connect();
  try {
    await db.query("BEGIN");
    const user = await db.query<{ id: string }>(
      `INSERT INTO users (github_id, github_login, name, avatar_url) VALUES ($1, $2, $3, $4)
       ON CONFLICT (github_id) DO UPDATE SET github_login = EXCLUDED.github_login, name = EXCLUDED.name, avatar_url = EXCLUDED.avatar_url, updated_at = now()
       RETURNING id`, [profile.id, profile.login, profile.name ?? null, profile.avatar_url ?? null],
    );
    await db.query(
      `INSERT INTO github_accounts (user_id, encrypted_access_token, encrypted_refresh_token, access_token_expires_at, refresh_token_expires_at) VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (user_id) DO UPDATE SET encrypted_access_token = EXCLUDED.encrypted_access_token, encrypted_refresh_token = EXCLUDED.encrypted_refresh_token,
       access_token_expires_at = EXCLUDED.access_token_expires_at, refresh_token_expires_at = EXCLUDED.refresh_token_expires_at, updated_at = now()`,
      [user.rows[0]!.id, encryptedToken, encryptedRefresh, accessExpiresAt, refreshExpiresAt],
    );
    await db.query("COMMIT");
    const jwt = await new EncryptJWT({ sub: user.rows[0]!.id, login: profile.login }).setProtectedHeader({ alg: "dir", enc: "A256GCM" }).setIssuedAt().setExpirationTime("7d").encrypt(sessionKey);
    return { jwt, profile };
  } catch (error) {
    await db.query("ROLLBACK");
    throw error;
  } finally { db.release(); }
}

export async function readSession(token?: string) {
  if (!token) return null;
  try {
    const { payload } = await jwtDecrypt(token, sessionKey);
    if (typeof payload.sub !== "string" || typeof payload.login !== "string") return null;
    return { id: payload.sub, githubLogin: payload.login };
  } catch { return null; }
}

export async function verifyStoredToken(token: string) {
  return (await jwtDecrypt(token, encryptionKey())).payload.token;
}

export async function githubUserAccessToken(userId: string) {
  const result = await pool.query<{ encrypted_access_token: string; encrypted_refresh_token: string | null; access_token_expires_at: Date | null; refresh_token_expires_at: Date | null }>(
    "SELECT encrypted_access_token, encrypted_refresh_token, access_token_expires_at, refresh_token_expires_at FROM github_accounts WHERE user_id = $1", [userId],
  );
  const row = result.rows[0];
  if (!row) throw new Error("GitHub user authorization is unavailable");
  if (!row.access_token_expires_at || row.access_token_expires_at.getTime() > Date.now() + 60_000) {
    const access = await verifyStoredToken(row.encrypted_access_token);
    if (typeof access === "string") return access;
  }
  if (!row.encrypted_refresh_token || (row.refresh_token_expires_at && row.refresh_token_expires_at.getTime() <= Date.now())) throw new Error("GitHub authorization expired; sign in again");
  const refresh = await verifyStoredToken(row.encrypted_refresh_token);
  if (typeof refresh !== "string") throw new Error("GitHub refresh token is invalid");
  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST", headers: { accept: "application/json", "content-type": "application/json" },
    body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, grant_type: "refresh_token", refresh_token: refresh }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error("GitHub token refresh failed");
  const token = await response.json() as { access_token?: string; refresh_token?: string; expires_in?: number; refresh_token_expires_in?: number; error?: string };
  if (!token.access_token) throw new Error(token.error ?? "GitHub did not return a refreshed access token");
  const encryptedAccess = await new EncryptJWT({ token: token.access_token }).setProtectedHeader({ alg: "dir", enc: "A256GCM" }).setIssuedAt().encrypt(encryptionKey());
  const encryptedRefresh = token.refresh_token ? await new EncryptJWT({ token: token.refresh_token }).setProtectedHeader({ alg: "dir", enc: "A256GCM" }).setIssuedAt().encrypt(encryptionKey()) : row.encrypted_refresh_token;
  await pool.query(
    `UPDATE github_accounts SET encrypted_access_token = $2, encrypted_refresh_token = $3,
     access_token_expires_at = $4, refresh_token_expires_at = $5, updated_at = now() WHERE user_id = $1`,
    [userId, encryptedAccess, encryptedRefresh, token.expires_in ? new Date(Date.now() + token.expires_in * 1000) : null, token.refresh_token_expires_in ? new Date(Date.now() + token.refresh_token_expires_in * 1000) : row.refresh_token_expires_at],
  );
  return token.access_token;
}

export { cookieOptions };
