import { createHash } from "crypto";
import type { IncomingMessage } from "http";
import { verifyEvent, type Event } from "nostr-tools";

/**
 * Management routes: wallet, keys, clients, providers, daemon control and
 * usage. They need a NIP-98 event signed by the daemon's own Nostr key (the
 * `nsec` in config.json, which the CLI shares). Everything else stays as it
 * was: /health, /ping, /version, the model listings, and the OpenAI-compatible
 * proxy routes that apps call with their per-client API keys.
 */
const MANAGEMENT_SEGMENTS = new Set([
  "balance",
  "clients",
  "cooldowns",
  "keys",
  "nwc",
  "providers",
  "refund",
  "settings",
  "status",
  "stop",
  "usage",
  "usagePi",
  "wallet",
]);

export function isManagementRoute(pathname: string): boolean {
  return MANAGEMENT_SEGMENTS.has(pathname.split("/")[1] ?? "");
}

/**
 * A browser request from another origin (a web page posting to the local
 * daemon). Requests without an Origin header (CLI, curl, apps) pass.
 */
export function isCrossOriginRequest(
  req: IncomingMessage,
  host: string,
): boolean {
  const origin = req.headers.origin;
  if (origin === undefined) return false;
  return origin !== `http://${host}` && origin !== `https://${host}`;
}

const NIP98_KIND = 27235;
const MAX_CLOCK_SKEW_SECONDS = 60;

export type ManagementAuthenticator = (
  req: IncomingMessage,
  /** The request path and query, as the client sent it. */
  pathAndQuery: string,
  readRawBody: () => Promise<Buffer>,
) => Promise<string | null>;

function tag(event: Event, name: string): string | undefined {
  return event.tags.find((t) => t[0] === name)?.[1];
}

function pathAndQueryOf(url: string): string | null {
  try {
    const parsed = new URL(url, "http://localhost");
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return null;
  }
}

/**
 * Verify `Authorization: Nostr <base64 event>` (NIP-98) against `pubkey`.
 * Returns null when the request is authorized, otherwise the reason.
 *
 * The `u` tag is compared on path and query only: scheme and host change
 * behind a reverse proxy, and the signer is the daemon's own key, so the event
 * cannot be meant for another server. A body must be bound by the `payload`
 * tag, and each signature is accepted once.
 */
export function createNip98ManagementAuth(
  pubkey: string | undefined,
  now: () => number = () => Math.floor(Date.now() / 1000),
): ManagementAuthenticator {
  const seen = new Map<string, number>();

  return async (req, pathAndQuery, readRawBody) => {
    if (!pubkey) {
      return "Management API is unavailable: the daemon has no valid nsec in its config.";
    }
    const header = req.headers.authorization;
    const match = header?.match(/^Nostr\s+(\S+)$/i);
    if (!match?.[1]) {
      return "Missing NIP-98 Authorization header signed by the daemon's nsec.";
    }

    let event: Event;
    try {
      event = JSON.parse(Buffer.from(match[1], "base64").toString("utf8"));
    } catch {
      return "Invalid NIP-98 Authorization header.";
    }
    if (!event || typeof event !== "object" || !Array.isArray(event.tags)) {
      return "Invalid NIP-98 Authorization header.";
    }
    if (event.kind !== NIP98_KIND || event.pubkey !== pubkey) {
      return "NIP-98 event is not signed by the daemon's nsec.";
    }
    if (!verifyEvent(event)) {
      return "Invalid NIP-98 signature.";
    }
    const at = now();
    if (
      typeof event.created_at !== "number" ||
      Math.abs(at - event.created_at) > MAX_CLOCK_SKEW_SECONDS
    ) {
      return "NIP-98 event is expired or from the future.";
    }
    if (tag(event, "method")?.toUpperCase() !== req.method?.toUpperCase()) {
      return "NIP-98 method does not match the request.";
    }
    const signedUrl = tag(event, "u");
    if (!signedUrl || pathAndQueryOf(signedUrl) !== pathAndQueryOf(pathAndQuery)) {
      return "NIP-98 URL does not match the request.";
    }

    const body = await readRawBody();
    const payload = tag(event, "payload");
    if (body.length > 0 || payload !== undefined) {
      const digest = createHash("sha256").update(body).digest("hex");
      if (payload?.toLowerCase() !== digest) {
        return "NIP-98 payload hash does not match the request body.";
      }
    }

    for (const [sig, expiry] of seen) {
      if (expiry < at) seen.delete(sig);
    }
    if (seen.has(event.sig)) {
      return "NIP-98 event was already used.";
    }
    seen.set(event.sig, event.created_at + MAX_CLOCK_SKEW_SECONDS);
    return null;
  };
}
