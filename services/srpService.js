import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const srpServer = require('secure-remote-password/server');

/**
 * In-memory SRP pending sessions.
 * Keyed by email; each entry lives for 5 minutes then is evicted.
 *
 * Structure: { serverEphemeralSecret, clientPublicEphemeral, expiresAt }
 */
const pending = new Map();
const SESSION_TTL_MS = 5 * 60 * 1000;

setInterval(() => {
  const now = Date.now();
  for (const [email, s] of pending) {
    if (s.expiresAt < now) pending.delete(email);
  }
}, 60_000).unref();

/** Generate a server-side SRP ephemeral from the stored verifier. */
export function srpGenerateEphemeral(srpVerifier) {
  return srpServer.generateEphemeral(srpVerifier);
}

/** Stash the server ephemeral until the client's /complete call. */
export function srpStorePending(email, serverEphemeralSecret, clientPublicEphemeral) {
  pending.set(email.toLowerCase(), {
    serverEphemeralSecret,
    clientPublicEphemeral,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
}

/** Retrieve and remove the pending session. Returns null if expired or absent. */
export function srpConsumePending(email) {
  const session = pending.get(email.toLowerCase());
  pending.delete(email.toLowerCase());
  if (!session || session.expiresAt < Date.now()) return null;
  return session;
}

/**
 * Derive the SRP server session and verify the client proof.
 * Throws if the proof is invalid.
 */
export function srpDeriveSession(serverEphemeralSecret, clientPublicEphemeral, salt, username, verifier, clientProof) {
  return srpServer.deriveSession(
    serverEphemeralSecret,
    clientPublicEphemeral,
    salt,
    username,
    verifier,
    clientProof
  );
}
