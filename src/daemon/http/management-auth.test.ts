import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { createServer, type Server } from "http";
import { connect, type AddressInfo } from "net";
import { generateSecretKey, getPublicKey, nip19 } from "nostr-tools";
import { createDaemonRequestHandler } from "./index";
import { createNip98ManagementAuth, isManagementRoute } from "./management-auth";
import { createNIP98Authorization } from "../../utils/nip98";
import { callDaemonUrl } from "../../utils/daemon-client";
import { DEFAULT_CONFIG } from "../../utils/config";

const daemonKey = generateSecretKey();
const otherKey = generateSecretKey();

const calls = { getAllApiKeys: 0, sendCashu: 0, shutdown: 0 };
const apiKeys = [
  { baseUrl: "https://node.example/", key: "sk-node-secret", balance: 21, lastUsed: null },
];

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  server = createServer(
    createDaemonRequestHandler({
      authenticateManagement: createNip98ManagementAuth(getPublicKey(daemonKey)),
      server: { close() {} },
      shutdown: () => {
        calls.shutdown++;
      },
      store: {
        getState: () => ({
          clientIds: [
            { clientId: "app", name: "App", apiKey: "sk-client-secret", createdAt: 1 },
          ],
        }),
      },
      storageAdapter: {
        getAllApiKeys: () => {
          calls.getAllApiKeys++;
          return apiKeys;
        },
      },
      walletClient: {
        sendCashu: async () => {
          calls.sendCashu++;
          return "cashuBtoken";
        },
      },
      getRoutstr21Models: async () => [{ id: "model-a" }],
    } as any),
  );
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => {
  server.close();
});

async function signed(
  method: "GET" | "POST",
  path: string,
  options: { body?: string; key?: Uint8Array; url?: string; signedBody?: string } = {},
): Promise<Response> {
  const signedBody = options.signedBody ?? options.body;
  const authorization = await createNIP98Authorization(
    options.key ?? daemonKey,
    options.url ?? `${baseUrl}${path}`,
    method,
    signedBody ? new TextEncoder().encode(signedBody) : undefined,
  );
  return fetch(`${baseUrl}${path}`, {
    method,
    headers: { Authorization: authorization, "Content-Type": "application/json" },
    body: options.body,
  });
}

/** Send raw bytes, so the Host header can be malformed. */
function rawRequest(request: string): Promise<string> {
  const { port } = server.address() as AddressInfo;
  return new Promise((resolve, reject) => {
    const socket = connect(port, "127.0.0.1", () => socket.write(request));
    let data = "";
    socket.on("data", (chunk) => {
      data += chunk.toString();
      if (data.includes("\r\n\r\n")) socket.end();
    });
    socket.on("end", () => resolve(data));
    socket.on("error", reject);
    setTimeout(() => {
      socket.destroy();
      resolve(data);
    }, 2000);
  });
}

describe("management route classification", () => {
  it("covers wallet, keys, clients and daemon control but not proxy routes", () => {
    for (const path of [
      "/keys/api", "/keys/api/delete", "/clients", "/clients/add", "/wallet/send/cashu",
      "/wallet/send/bolt11", "/wallet/receive/bolt11/q1", "/stop", "/status", "/balance",
      "/nwc/connect", "/providers", "/settings/auto-refresh", "/usage", "/usagePi", "/refund",
    ]) {
      expect(isManagementRoute(path)).toBe(true);
    }
    for (const path of [
      "/health", "/ping", "/version", "/models", "/models/m/providers", "/v1/models",
      "/v1/chat/completions", "/chat/completions", "/v1/messages", "/v1/responses",
    ]) {
      expect(isManagementRoute(path)).toBe(false);
    }
  });
});

describe("management API authentication", () => {
  it("refuses unauthenticated management requests", async () => {
    const before = { ...calls };
    for (const [method, path, body] of [
      ["GET", "/keys/api"],
      ["GET", "/clients"],
      ["POST", "/wallet/send/cashu", JSON.stringify({ amount: 5 })],
      ["POST", "/stop"],
    ] as const) {
      const res = await fetch(`${baseUrl}${path}`, { method, body });
      expect(res.status).toBe(401);
      const text = await res.text();
      expect(text).not.toContain("sk-");
    }
    expect(calls).toEqual(before);
  });

  it("refuses NIP-98 signed by another key", async () => {
    const res = await signed("GET", "/keys/api", { key: otherKey });
    expect(res.status).toBe(401);
  });

  it("serves management requests signed by the daemon's nsec", async () => {
    const keys = await signed("GET", "/keys/api");
    expect(keys.status).toBe(200);
    expect(((await keys.json()) as any).output.apiKeys[0].key).toBe("sk-node-secret");

    const clients = await signed("GET", "/clients");
    expect(clients.status).toBe(200);
    expect(((await clients.json()) as any).output.clients[0].apiKey).toBe("sk-client-secret");

    const body = JSON.stringify({ amount: 5 });
    const send = await signed("POST", "/wallet/send/cashu", { body });
    expect(send.status).toBe(200);
    expect(((await send.json()) as any).output.token).toBe("cashuBtoken");
  });

  it("binds the signature to the method, URL and body, and accepts it once", async () => {
    const before = calls.sendCashu;
    const body = JSON.stringify({ amount: 5 });
    expect(
      (await signed("POST", "/wallet/send/cashu", {
        body: JSON.stringify({ amount: 5000 }),
        signedBody: body,
      })).status,
    ).toBe(401);
    expect(
      (await signed("POST", "/wallet/send/cashu", { body, url: `${baseUrl}/wallet/receive/cashu` })).status,
    ).toBe(401);

    const authorization = await createNIP98Authorization(
      daemonKey,
      `${baseUrl}/wallet/send/cashu`,
      "POST",
      new TextEncoder().encode(body),
    );
    const send = () =>
      fetch(`${baseUrl}/wallet/send/cashu`, {
        method: "POST",
        headers: { Authorization: authorization },
        body,
      });
    expect((await send()).status).toBe(200);
    expect((await send()).status).toBe(401);
    expect(calls.sendCashu).toBe(before + 1);
  });

  it("refuses expired events", async () => {
    const authenticate = createNip98ManagementAuth(
      getPublicKey(daemonKey),
      () => Math.floor(Date.now() / 1000) + 120,
    );
    const authorization = await createNIP98Authorization(daemonKey, "http://x/stop", "POST");
    const req = { method: "POST", headers: { authorization } } as any;
    expect(await authenticate(req, "/stop", async () => Buffer.alloc(0))).toContain("expired");
  });

  it("works with the CLI's daemon client and stops the daemon on POST /stop", async () => {
    const config = { ...DEFAULT_CONFIG, nsec: nip19.nsecEncode(daemonKey) };
    const result = await callDaemonUrl(baseUrl, "/clients", {}, config);
    expect((result.output as any).clients[0].id).toBe("app");

    const before = calls.shutdown;
    const stop = await callDaemonUrl(baseUrl, "/stop", { method: "POST" }, config);
    expect(stop.output).toBe("stopping");
    await Bun.sleep(100);
    expect(calls.shutdown).toBe(before + 1);
  });
});

describe("request validation", () => {
  it("answers a malformed Host header with 400", async () => {
    const response = await rawRequest(
      "GET /health HTTP/1.1\r\nHost: bad host[\r\nConnection: close\r\n\r\n",
    );
    expect(response.startsWith("HTTP/1.1 400")).toBe(true);
    expect(response).toContain("Invalid Host header");
  });

  it("refuses cross-origin browser requests to management routes", async () => {
    const res = await fetch(`${baseUrl}/wallet/send/cashu`, {
      method: "POST",
      headers: { Origin: "https://evil.example", "Content-Type": "text/plain" },
      body: JSON.stringify({ amount: 5 }),
    });
    expect(res.status).toBe(403);

    const authed = await createNIP98Authorization(daemonKey, `${baseUrl}/clients`, "GET");
    const withAuth = await fetch(`${baseUrl}/clients`, {
      headers: { Origin: "https://evil.example", Authorization: authed },
    });
    expect(withAuth.status).toBe(403);
  });

  it("allows a same-origin request with valid auth", async () => {
    const authorization = await createNIP98Authorization(daemonKey, `${baseUrl}/clients`, "GET");
    const res = await fetch(`${baseUrl}/clients`, {
      headers: { Origin: baseUrl, Authorization: authorization },
    });
    expect(res.status).toBe(200);
  });
});

describe("proxy routes are unchanged", () => {
  it("serves the model list without auth", async () => {
    const res = await fetch(`${baseUrl}/v1/models`, {
      headers: { Origin: "https://evil.example" },
    });
    expect(res.status).toBe(200);
    expect(((await res.json()) as any).data[0].id).toBe("model-a");
  });

  it("routes POST /v1/chat/completions to the proxy without management auth", async () => {
    const res = await fetch(`${baseUrl}/v1/chat/completions`, {
      method: "POST",
      headers: { Authorization: "Bearer sk-client-secret", "Content-Type": "application/json" },
      body: JSON.stringify({ messages: [] }),
    });
    // Reaches the proxy path (which wants a model), not the auth guard.
    expect(res.status).toBe(400);
    expect(((await res.json()) as any).error).toBe("Missing required 'model' field.");
  });

  it("keeps /health public", async () => {
    expect((await fetch(`${baseUrl}/health`)).status).toBe(200);
  });
});
