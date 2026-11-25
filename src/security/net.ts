import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import dns from 'node:dns';
import net from 'node:net';
import { redactProxyUrl, SecretRegistry, defaultSecretRegistry } from './redact.ts';

export class ProxyConfigError extends Error {
  readonly code = 'PROXY_CONFIG_INVALID';
  constructor(message: string) {
    super(message);
    this.name = 'ProxyConfigError';
  }
}

export class SsrfBlockedError extends Error {
  readonly code = 'SSRF_BLOCKED';
  constructor(message: string) {
    super(message);
    this.name = 'SSRF_BLOCKED';
  }
}

export class CrossOriginRedirectError extends Error {
  readonly code = 'CROSS_ORIGIN_REDIRECT';
  constructor(message: string) {
    super(message);
    this.name = 'CrossOriginRedirectError';
  }
}

export class ResponseTooLargeError extends Error {
  readonly code = 'RESPONSE_TOO_LARGE';
  constructor(message: string) {
    super(message);
    this.name = 'ResponseTooLargeError';
  }
}

export interface ValidatedProxyConfig {
  protocol: 'http:' | 'https:';
  hostname: string; // Always bracket-stripped (e.g. '::1', 'proxy.local')
  port: number;
  proxyAuthHeader?: string;
  displayUrl: string;
}

export type ProxyState =
  | { kind: 'direct' }
  | { kind: 'proxy'; config: ValidatedProxyConfig }
  | { kind: 'invalid'; error: ProxyConfigError };

export interface HttpResponseResult {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: Buffer;
}

export function stripIpv6Brackets(host: string): string {
  return host.replace(/^\[|\]$/g, '');
}

export function formatHostForUrl(bareHost: string): string {
  const clean = stripIpv6Brackets(bareHost);
  return clean.includes(':') ? `[${clean}]` : clean;
}

/**
 * Parses and validates an outbound proxy URL fail-closed.
 * - Empty string / null / undefined => { kind: 'direct' }
 * - Any invalid, non-http/https, malformed, bad-percent-escape, or path/query-bearing URL => { kind: 'invalid', error }
 */
export function parseProxyStateFailClosed(
  rawProxyUrl: string | undefined | null,
  creds?: { username?: string; password?: string },
  registry: SecretRegistry = defaultSecretRegistry,
): ProxyState {
  if (!rawProxyUrl || !rawProxyUrl.trim()) {
    return { kind: 'direct' };
  }
  const trimmed = rawProxyUrl.trim();
  const safeDisplay = redactProxyUrl(trimmed);

  if (/[\r\n\x00-\x1f\x7f\s]/.test(trimmed)) {
    return {
      kind: 'invalid',
      error: new ProxyConfigError(`Invalid proxy URL (control characters): ${safeDisplay}`),
    };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return {
      kind: 'invalid',
      error: new ProxyConfigError(
        `Proxy URL must be http(s)://[user:pass@]host[:port], got ${safeDisplay}`,
      ),
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      kind: 'invalid',
      error: new ProxyConfigError(
        `Unsupported proxy scheme "${parsed.protocol}" (only http:// and https:// supported): ${safeDisplay}`,
      ),
    };
  }

  const bareHost = stripIpv6Brackets(parsed.hostname);
  if (!bareHost) {
    return {
      kind: 'invalid',
      error: new ProxyConfigError(`Proxy URL missing hostname: ${safeDisplay}`),
    };
  }

  if ((parsed.pathname && parsed.pathname !== '/') || parsed.search || parsed.hash) {
    return {
      kind: 'invalid',
      error: new ProxyConfigError(
        `Proxy URL must not contain path, query, or fragment: ${safeDisplay}`,
      ),
    };
  }

  // Reject trailing colon with empty port like http://proxy:
  const authority = trimmed.slice(parsed.protocol.length + 2).replace(/\/$/, '');
  const hostPortPart = authority.includes('@')
    ? authority.slice(authority.lastIndexOf('@') + 1)
    : authority;
  if (hostPortPart.endsWith(':')) {
    return {
      kind: 'invalid',
      error: new ProxyConfigError(`Proxy URL has empty port: ${safeDisplay}`),
    };
  }

  const defaultPort = parsed.protocol === 'https:' ? 443 : 80;
  const port = parsed.port ? Number(parsed.port) : defaultPort;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return {
      kind: 'invalid',
      error: new ProxyConfigError(`Proxy URL has invalid port: ${safeDisplay}`),
    };
  }

  let rawUser: string;
  let rawPass: string;
  try {
    rawUser = parsed.username ? decodeURIComponent(parsed.username) : (creds?.username ?? '');
    rawPass = parsed.password ? decodeURIComponent(parsed.password) : (creds?.password ?? '');
  } catch {
    return {
      kind: 'invalid',
      error: new ProxyConfigError(
        `Proxy URL contains invalid percent-encoded credentials: ${safeDisplay}`,
      ),
    };
  }

  let proxyAuthHeader: string | undefined;
  if (rawUser || rawPass) {
    registry.registerBasicPair(rawUser, rawPass);
    const token = Buffer.from(`${rawUser}:${rawPass}`, 'utf8').toString('base64');
    proxyAuthHeader = `Basic ${token}`;
  }

  const displayUrl = `${parsed.protocol}//${formatHostForUrl(bareHost)}:${port}`;

  return {
    kind: 'proxy',
    config: {
      protocol: parsed.protocol,
      hostname: bareHost,
      port,
      proxyAuthHeader,
      displayUrl,
    },
  };
}

function isIpv4Blocked(ip: string, allowPrivateIntranet: boolean): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b, c, d] = parts as [number, number, number, number];
  // 0.0.0.0/8 (unspecified), 127.0.0.0/8 (loopback)
  if (a === 0 || a === 127) return true;
  // 169.254.0.0/16 (link-local & AWS/GCP/Azure metadata)
  if (a === 169 && b === 254) return true;
  // 100.100.100.200 (Alibaba Cloud metadata)
  if (a === 100 && b === 100 && c === 100 && d === 200) return true;
  // 224.0.0.0/4 multicast & 240.0.0.0/4 reserved
  if (a >= 224) return true;

  if (!allowPrivateIntranet) {
    // RFC1918 + CGNAT 100.64.0.0/10
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
  }
  return false;
}

/**
 * Parses an IPv6 address (including compressed `::` and embedded dotted-quad IPv4)
 * into eight canonical 16-bit unsigned integers, or returns null if malformed.
 */
function parseIpv6ToGroups(ip: string): number[] | null {
  let addr = ip.trim().toLowerCase();
  const zoneIdx = addr.indexOf('%');
  if (zoneIdx >= 0) addr = addr.slice(0, zoneIdx);

  // Convert trailing dotted-quad IPv4 to two 16-bit hex groups
  const lastColon = addr.lastIndexOf(':');
  if (lastColon >= 0 && addr.slice(lastColon + 1).includes('.')) {
    const ipv4 = addr.slice(lastColon + 1);
    if (!net.isIPv4(ipv4)) return null;
    const octets = ipv4.split('.').map(Number) as [number, number, number, number];
    const g1 = ((octets[0] << 8) | octets[1]).toString(16);
    const g2 = ((octets[2] << 8) | octets[3]).toString(16);
    addr = `${addr.slice(0, lastColon + 1)}${g1}:${g2}`;
  }

  const halves = addr.split('::');
  if (halves.length > 2) return null;

  const parseHalf = (s: string): number[] | null => {
    if (!s) return [];
    const parts = s.split(':');
    const nums: number[] = [];
    for (const part of parts) {
      if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
      nums.push(Number.parseInt(part, 16));
    }
    return nums;
  };

  const left = parseHalf(halves[0] ?? '');
  if (!left) return null;
  if (halves.length === 1) {
    return left.length === 8 ? left : null;
  }
  const right = parseHalf(halves[1] ?? '');
  if (!right) return null;
  const missing = 8 - (left.length + right.length);
  if (missing < 1) return null;
  return [...left, ...new Array<number>(missing).fill(0), ...right];
}

function groupsToIpv4(hi: number, lo: number): string {
  return `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
}

export function isIpAddressBlocked(ip: string, opts: { allowPrivateIntranet: boolean }): boolean {
  const normalized = stripIpv6Brackets(ip.trim().toLowerCase());
  const version = net.isIP(normalized);
  if (version === 4) {
    return isIpv4Blocked(normalized, opts.allowPrivateIntranet);
  }
  if (version === 6) {
    const g = parseIpv6ToGroups(normalized);
    if (!g) return true;
    const [g0, g1, g2, g3, g4, g5, g6, g7] = g as [
      number,
      number,
      number,
      number,
      number,
      number,
      number,
      number,
    ];

    // ::/128 (unspecified) and ::1/128 (loopback)
    if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0 && g6 === 0 && (g7 === 0 || g7 === 1)) {
      return true;
    }

    // AWS IMDSv2 IPv6 fd00:ec2::254
    if (g0 === 0xfd00 && g1 === 0x0ec2 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0 && g6 === 0 && g7 === 0x0254) {
      return true;
    }

    // IPv4-mapped ::ffff:0:0/96
    if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff) {
      return isIpv4Blocked(groupsToIpv4(g6, g7), opts.allowPrivateIntranet);
    }

    // IPv4-translated ::ffff:0:0:0/96
    if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0xffff && g5 === 0) {
      return isIpv4Blocked(groupsToIpv4(g6, g7), opts.allowPrivateIntranet);
    }

    // Deprecated IPv4-compatible ::/96
    if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
      return isIpv4Blocked(groupsToIpv4(g6, g7), opts.allowPrivateIntranet);
    }

    // NAT64 well-known prefix 64:ff9b::/96 and local-use 64:ff9b:1::/48
    if (g0 === 0x0064 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) {
      return isIpv4Blocked(groupsToIpv4(g6, g7), opts.allowPrivateIntranet);
    }
    if (g0 === 0x0064 && g1 === 0xff9b && g2 === 0x0001) {
      return isIpv4Blocked(groupsToIpv4(g6, g7), opts.allowPrivateIntranet);
    }

    // 6to4 2002::/16 embeds IPv4 in g1:g2
    if (g0 === 0x2002) {
      return isIpv4Blocked(groupsToIpv4(g1, g2), opts.allowPrivateIntranet);
    }

    // Link-local fe80::/10
    if ((g0 & 0xffc0) === 0xfe80) return true;
    // Multicast ff00::/8
    if ((g0 & 0xff00) === 0xff00) return true;
    // Unique local fc00::/7
    if (!opts.allowPrivateIntranet && (g0 & 0xfe00) === 0xfc00) return true;
    return false;
  }
  return true;
}

export function assertAllowedResolvedIp(ip: string, opts: { allowPrivateIntranet: boolean }): void {
  if (isIpAddressBlocked(ip, opts)) {
    throw new SsrfBlockedError(`Refusing connection to blocked IP address: ${ip}`);
  }
}

export function isTestLoopbackApiAllowed(explicitFlag?: boolean): boolean {
  return explicitFlag === true || process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API === '1';
}

export function validateGitHubApiBaseUrl(
  rawUrl: string,
  opts?: { allowInsecureLocalForTests?: boolean },
): { apiBaseUrl: URL; webOrigin: string; isGhes: boolean; allowPrivateIntranet: boolean } {
  const trimmed = (rawUrl || '').trim().replace(/\/+$/, '');
  if (!trimmed || /[\r\n\x00-\x1f\x7f\s]/.test(trimmed)) {
    throw new SsrfBlockedError('GitHub apiBaseUrl is invalid');
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new SsrfBlockedError(`GitHub apiBaseUrl is not a valid URL: ${redactProxyUrl(trimmed)}`);
  }

  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new SsrfBlockedError('GitHub apiBaseUrl must not contain credentials, query, or fragment');
  }
  if (parsed.pathname.split('/').some(seg => seg === '..')) {
    throw new SsrfBlockedError('GitHub apiBaseUrl must not contain path traversal segments');
  }

  const host = parsed.hostname.toLowerCase();
  const bareHost = stripIpv6Brackets(host);
  const normalizedFqdn = bareHost.replace(/\.+$/, '');
  const allowLocalTest = isTestLoopbackApiAllowed(opts?.allowInsecureLocalForTests);

  if (
    allowLocalTest &&
    (parsed.protocol === 'http:' || parsed.protocol === 'https:') &&
    (normalizedFqdn === '127.0.0.1' || normalizedFqdn === 'localhost' || normalizedFqdn === '::1')
  ) {
    return {
      apiBaseUrl: parsed,
      webOrigin: parsed.origin,
      isGhes: false,
      allowPrivateIntranet: true,
    };
  }

  if (parsed.protocol !== 'https:') {
    throw new SsrfBlockedError('GitHub apiBaseUrl must use https://');
  }

  if (
    !normalizedFqdn ||
    normalizedFqdn === 'localhost' ||
    normalizedFqdn.endsWith('.localhost') ||
    normalizedFqdn === 'metadata.google.internal' ||
    normalizedFqdn === 'metadata'
  ) {
    throw new SsrfBlockedError(`Blocked GitHub apiBaseUrl host: ${host}`);
  }

  const isPublicGithub = normalizedFqdn === 'api.github.com';
  if (net.isIP(bareHost)) {
    assertAllowedResolvedIp(bareHost, { allowPrivateIntranet: !isPublicGithub });
  }

  const webOrigin = isPublicGithub ? 'https://github.com' : parsed.origin;
  return {
    apiBaseUrl: parsed,
    webOrigin,
    isGhes: !isPublicGithub,
    allowPrivateIntranet: !isPublicGithub,
  };
}

function makeCheckedLookup(allowPrivateIntranet: boolean) {
  return (
    hostname: string,
    options: dns.LookupOptions,
    callback: (
      err: NodeJS.ErrnoException | null,
      address: string | dns.LookupAddress[],
      family?: number,
    ) => void,
  ) => {
    dns.lookup(hostname, options, (err, address, family) => {
      if (err) {
        callback(err, address, family);
        return;
      }
      try {
        if (Array.isArray(address)) {
          for (const entry of address) {
            assertAllowedResolvedIp(entry.address, { allowPrivateIntranet });
          }
        } else if (typeof address === 'string') {
          assertAllowedResolvedIp(address, { allowPrivateIntranet });
        }
      } catch (blockErr) {
        callback(blockErr as NodeJS.ErrnoException, address, family);
        return;
      }
      callback(null, address, family);
    });
  };
}

function readBoundedResponse(
  res: http.IncomingMessage,
  maxBytes: number,
): Promise<HttpResponseResult> {
  return new Promise((resolvePromise, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      res.destroy();
      reject(err);
    };

    res.on('data', (chunk: Buffer | string) => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += buf.length;
      if (total > maxBytes) {
        fail(new ResponseTooLargeError(`HTTP response exceeded ${maxBytes} bytes`));
        return;
      }
      chunks.push(buf);
    });

    res.on('error', err => fail(err));
    res.on('aborted', () => fail(new Error('HTTP response aborted prematurely')));
    res.on('end', () => {
      if (settled) return;
      settled = true;
      resolvePromise({
        status: res.statusCode ?? 0,
        headers: res.headers,
        body: chunks.length === 1 ? chunks[0]! : Buffer.concat(chunks, total),
      });
    });
  });
}

function openConnectTunnel(
  proxy: ValidatedProxyConfig,
  targetHost: string,
  targetPort: number,
  timeoutMs: number,
  signal?: AbortSignal,
  ca?: string | Buffer,
): Promise<net.Socket> {
  return new Promise((resolvePromise, reject) => {
    const bareTarget = stripIpv6Brackets(targetHost);
    if (/[\r\n\s]/.test(bareTarget)) {
      reject(new ProxyConfigError('Invalid target host for CONNECT tunnel'));
      return;
    }
    const authority = `${formatHostForUrl(bareTarget)}:${targetPort}`;
    const headers: Record<string, string> = {
      Host: authority,
    };
    // NEVER send target Authorization header on CONNECT!
    if (proxy.proxyAuthHeader) {
      headers['Proxy-Authorization'] = proxy.proxyAuthHeader;
    }

    const isHttpsProxy = proxy.protocol === 'https:';
    const transport = isHttpsProxy ? https : http;
    const reqOpts: https.RequestOptions = {
      host: proxy.hostname,
      port: proxy.port,
      method: 'CONNECT',
      path: authority,
      headers,
      agent: false,
      timeout: timeoutMs,
      ...(isHttpsProxy
        ? {
            rejectUnauthorized: true,
            minVersion: 'TLSv1.2',
            servername: net.isIP(proxy.hostname) ? undefined : proxy.hostname,
            ...(ca ? { ca } : {}),
          }
        : {}),
    };
    const req = transport.request(reqOpts);

    let settled = false;
    const done = (err: Error | null, socket?: net.Socket) => {
      if (settled) return;
      settled = true;
      if (signal) signal.removeEventListener('abort', onAbort);
      if (err) {
        req.destroy();
        reject(err);
      } else {
        resolvePromise(socket!);
      }
    };

    const onAbort = () => {
      const abortErr = new Error('Proxy CONNECT aborted');
      abortErr.name = 'AbortError';
      done(abortErr);
    };
    if (signal) {
      if (signal.aborted) {
        onAbort();
        return;
      }
      signal.addEventListener('abort', onAbort, { once: true });
    }

    req.on('connect', (res, socket, head) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        done(new ProxyConfigError(`Proxy CONNECT failed with HTTP ${res.statusCode ?? 0}`));
        return;
      }
      if (head && head.length > 0) {
        socket.unshift(head);
      }
      done(null, socket);
    });

    req.on('timeout', () => {
      done(new Error(`Proxy CONNECT timed out after ${timeoutMs}ms`));
    });
    req.on('error', err => done(err));
    req.end();
  });
}

async function performSingleOutboundRequest(opts: {
  url: URL;
  method: string;
  headers: Record<string, string>;
  body?: Buffer;
  proxy: ProxyState;
  allowPrivateIntranet: boolean;
  skipIpBlockCheck?: boolean;
  timeoutMs: number;
  maxResponseBytes: number;
  signal?: AbortSignal;
  ca?: string | Buffer;
}): Promise<HttpResponseResult> {
  if (opts.proxy.kind === 'invalid') {
    throw opts.proxy.error;
  }

  const headers: Record<string, string> = { ...opts.headers };
  if (opts.body !== undefined) {
    headers['Content-Length'] = String(opts.body.length);
  }

  const bareTargetHost = stripIpv6Brackets(opts.url.hostname);
  const targetPort = opts.url.port
    ? Number(opts.url.port)
    : opts.url.protocol === 'https:'
      ? 443
      : 80;

  // Proxied request
  if (opts.proxy.kind === 'proxy') {
    const proxy = opts.proxy.config;
    if (opts.url.protocol === 'https:') {
      const tunnelSocket = await openConnectTunnel(
        proxy,
        bareTargetHost,
        targetPort,
        opts.timeoutMs,
        opts.signal,
        opts.ca,
      );

      return await new Promise<HttpResponseResult>((resolvePromise, reject) => {
        let settled = false;
        const tlsSocket = tls.connect({
          socket: tunnelSocket,
          // Always pass explicit host so checkServerIdentity validates IP/hostname properly (not 'localhost')
          host: bareTargetHost,
          // Omit SNI for IP literals per RFC 6066
          servername: net.isIP(bareTargetHost) ? undefined : bareTargetHost,
          rejectUnauthorized: true,
          minVersion: 'TLSv1.2',
          ...(opts.ca ? { ca: opts.ca } : {}),
        });

        const tunnelAgent = new http.Agent({ keepAlive: false, maxSockets: 1 });
        tunnelAgent.createConnection = () => tlsSocket;

        const finish = (err: Error | null, res?: HttpResponseResult) => {
          if (settled) return;
          settled = true;
          if (opts.signal) opts.signal.removeEventListener('abort', onAbort);
          // Always tear down TLS + tunnel sockets and agent so no open file descriptors leak
          tlsSocket.destroy();
          tunnelSocket.destroy();
          tunnelAgent.destroy();
          if (err) {
            reject(err);
          } else {
            resolvePromise(res!);
          }
        };

        tlsSocket.on('error', err => finish(err));

        // Attach tlsSocket via a dedicated single-use Agent whose createConnection returns tlsSocket.
        // Passing `agent: false` with `createConnection` in Node.js ignores options.createConnection!
        const req = http.request(
          {
            host: bareTargetHost,
            port: targetPort,
            path: `${opts.url.pathname}${opts.url.search}`,
            method: opts.method,
            headers: {
              Host: opts.url.host,
              Connection: 'close',
              ...headers,
            },
            agent: tunnelAgent,
            timeout: opts.timeoutMs,
          },
          res => {
            readBoundedResponse(res, opts.maxResponseBytes).then(
              r => finish(null, r),
              e => finish(e as Error),
            );
          },
        );

        const onAbort = () => {
          const abortErr = new Error('HTTP request aborted');
          abortErr.name = 'AbortError';
          req.destroy();
          finish(abortErr);
        };
        if (opts.signal) {
          if (opts.signal.aborted) {
            onAbort();
            return;
          }
          opts.signal.addEventListener('abort', onAbort, { once: true });
        }

        req.on('upgrade', (_res, socket) => {
          socket.destroy();
          finish(new Error('Unexpected HTTP upgrade response'));
        });
        req.on('timeout', () => {
          req.destroy();
          finish(new Error(`HTTP request timed out after ${opts.timeoutMs}ms`));
        });
        req.on('error', err => finish(err));
        if (opts.body) req.write(opts.body);
        req.end();
      });
    }

    // Plain HTTP target via HTTP/HTTPS proxy (absolute-form request target)
    const proxyHeaders: Record<string, string> = {
      Host: opts.url.host,
      Connection: 'close',
      ...headers,
    };
    if (proxy.proxyAuthHeader) {
      proxyHeaders['Proxy-Authorization'] = proxy.proxyAuthHeader;
    }
    const isHttpsProxy = proxy.protocol === 'https:';
    const transport = isHttpsProxy ? https : http;
    return await new Promise<HttpResponseResult>((resolvePromise, reject) => {
      let settled = false;
      const finish = (err: Error | null, res?: HttpResponseResult) => {
        if (settled) return;
        settled = true;
        if (opts.signal) opts.signal.removeEventListener('abort', onAbort);
        if (err) reject(err);
        else resolvePromise(res!);
      };

      const req = transport.request(
        {
          host: proxy.hostname,
          port: proxy.port,
          path: opts.url.toString(),
          method: opts.method,
          headers: proxyHeaders,
          agent: false,
          timeout: opts.timeoutMs,
          ...(isHttpsProxy
            ? {
                rejectUnauthorized: true,
                minVersion: 'TLSv1.2',
                servername: net.isIP(proxy.hostname) ? undefined : proxy.hostname,
                ...(opts.ca ? { ca: opts.ca } : {}),
              }
            : {}),
        },
        res => {
          readBoundedResponse(res, opts.maxResponseBytes).then(
            r => finish(null, r),
            e => finish(e as Error),
          );
        },
      );

      const onAbort = () => {
        const abortErr = new Error('HTTP request aborted');
        abortErr.name = 'AbortError';
        req.destroy();
        finish(abortErr);
      };
      if (opts.signal) {
        if (opts.signal.aborted) {
          onAbort();
          return;
        }
        opts.signal.addEventListener('abort', onAbort, { once: true });
      }

      req.on('upgrade', (_res, socket) => {
        socket.destroy();
        finish(new Error('Unexpected HTTP upgrade response'));
      });
      req.on('timeout', () => {
        req.destroy();
        finish(new Error(`HTTP request timed out after ${opts.timeoutMs}ms`));
      });
      req.on('error', err => finish(err));
      if (opts.body) req.write(opts.body);
      req.end();
    });
  }

  // Direct request (explicitly ignores HTTP_PROXY / HTTPS_PROXY env vars)
  const isHttps = opts.url.protocol === 'https:';
  const transport = isHttps ? https : http;
  const lookup = opts.skipIpBlockCheck ? undefined : makeCheckedLookup(opts.allowPrivateIntranet);

  return await new Promise<HttpResponseResult>((resolvePromise, reject) => {
    let settled = false;
    const finish = (err: Error | null, res?: HttpResponseResult) => {
      if (settled) return;
      settled = true;
      if (opts.signal) opts.signal.removeEventListener('abort', onAbort);
      if (err) reject(err);
      else resolvePromise(res!);
    };

    const reqOpts: https.RequestOptions = {
      hostname: bareTargetHost,
      port: targetPort,
      path: `${opts.url.pathname}${opts.url.search}`,
      method: opts.method,
      headers,
      agent: false,
      timeout: opts.timeoutMs,
      ...(lookup ? { lookup } : {}),
      ...(isHttps
        ? {
            rejectUnauthorized: true,
            minVersion: 'TLSv1.2',
            servername: net.isIP(bareTargetHost) ? undefined : bareTargetHost,
            ...(opts.ca ? { ca: opts.ca } : {}),
          }
        : {}),
    };

    const req = transport.request(reqOpts, res => {
      readBoundedResponse(res, opts.maxResponseBytes).then(
        r => finish(null, r),
        e => finish(e as Error),
      );
    });

    const onAbort = () => {
      const abortErr = new Error('HTTP request aborted');
      abortErr.name = 'AbortError';
      req.destroy();
      finish(abortErr);
    };
    if (opts.signal) {
      if (opts.signal.aborted) {
        onAbort();
        return;
      }
      opts.signal.addEventListener('abort', onAbort, { once: true });
    }

    req.on('upgrade', (_res, socket) => {
      socket.destroy();
      finish(new Error('Unexpected HTTP upgrade response'));
    });
    req.on('timeout', () => {
      req.destroy();
      finish(new Error(`HTTP request timed out after ${opts.timeoutMs}ms`));
    });
    req.on('error', err => finish(err));
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function pathMatchesAllowedPrefix(pathname: string, allowedPathPrefix: string): boolean {
  const norm = allowedPathPrefix.replace(/\/+$/, '');
  if (!norm || norm === '/') return true;
  return pathname === norm || pathname.startsWith(`${norm}/`);
}

/**
 * Performs an outbound HTTP/HTTPS request with fail-closed proxy enforcement,
 * SSRF IP checks, bounded body reading, and strict same-origin segment-bounded redirects.
 */
export async function secureOutboundRequest(opts: {
  url: URL;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD';
  headers: Record<string, string>;
  body?: Buffer;
  proxy: ProxyState;
  allowPrivateIntranet: boolean;
  allowedOrigin: string;
  allowedPathPrefix?: string;
  skipIpBlockCheck?: boolean;
  timeoutMs?: number;
  maxResponseBytes?: number;
  signal?: AbortSignal;
  ca?: string | Buffer;
}): Promise<HttpResponseResult> {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const maxResponseBytes = opts.maxResponseBytes ?? 8 * 1024 * 1024;
  const maxRedirects = opts.method === 'GET' || opts.method === 'HEAD' ? 3 : 0;

  let currentUrl = opts.url;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const res = await performSingleOutboundRequest({
      url: currentUrl,
      method: opts.method,
      headers: opts.headers,
      body: opts.body,
      proxy: opts.proxy,
      allowPrivateIntranet: opts.allowPrivateIntranet,
      skipIpBlockCheck: opts.skipIpBlockCheck,
      timeoutMs,
      maxResponseBytes,
      signal: opts.signal,
      ca: opts.ca,
    });

    if (
      res.status === 301 ||
      res.status === 302 ||
      res.status === 303 ||
      res.status === 307 ||
      res.status === 308
    ) {
      const rawLoc = res.headers.location;
      const location = Array.isArray(rawLoc) ? rawLoc[0] : rawLoc;
      if (!location) {
        throw new CrossOriginRedirectError(`Redirect (${res.status}) missing Location header`);
      }
      let nextUrl: URL;
      try {
        nextUrl = new URL(location, currentUrl);
      } catch {
        throw new CrossOriginRedirectError('Invalid redirect Location URL');
      }

      if (nextUrl.origin !== opts.allowedOrigin) {
        throw new CrossOriginRedirectError(
          `Refused cross-origin redirect from ${opts.allowedOrigin} to ${nextUrl.origin}`,
        );
      }
      if (
        opts.allowedPathPrefix &&
        !pathMatchesAllowedPrefix(nextUrl.pathname, opts.allowedPathPrefix)
      ) {
        throw new CrossOriginRedirectError(
          `Refused redirect outside allowed path prefix ${opts.allowedPathPrefix}`,
        );
      }
      if (hop === maxRedirects) {
        throw new CrossOriginRedirectError(
          `Refused redirect (${res.status}) for ${opts.method} (maxRedirects=${maxRedirects})`,
        );
      }
      currentUrl = nextUrl;
      continue;
    }

    return res;
  }

  throw new CrossOriginRedirectError('Exceeded maximum redirects');
}

/**
 * Direct-only loopback HTTP request using node:http.
 * Strictly binds to 127.0.0.1 / ::1 and NEVER uses $http_proxy or global fetch
 * (immune to Bun's fetch $http_proxy 403 bug on CIDR no_proxy).
 */
export function loopbackRequest(opts: {
  host?: '127.0.0.1' | '::1';
  port: number;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  headers?: Record<string, string>;
  body?: Buffer | string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  signal?: AbortSignal;
}): Promise<HttpResponseResult> {
  const host = opts.host ?? '127.0.0.1';
  if (host !== '127.0.0.1' && host !== '::1') {
    return Promise.reject(new Error(`loopbackRequest refuses non-loopback host: ${host}`));
  }
  if (!Number.isInteger(opts.port) || opts.port < 1 || opts.port > 65535) {
    return Promise.reject(new Error(`loopbackRequest invalid port: ${opts.port}`));
  }

  const timeoutMs = opts.timeoutMs ?? 15_000;
  const maxResponseBytes = opts.maxResponseBytes ?? 4 * 1024 * 1024;
  const bodyBuf =
    opts.body === undefined
      ? undefined
      : Buffer.isBuffer(opts.body)
        ? opts.body
        : Buffer.from(opts.body, 'utf8');

  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (bodyBuf !== undefined) {
    headers['Content-Length'] = String(bodyBuf.length);
  }

  return new Promise<HttpResponseResult>((resolvePromise, reject) => {
    let settled = false;
    const finish = (err: Error | null, res?: HttpResponseResult) => {
      if (settled) return;
      settled = true;
      if (opts.signal) opts.signal.removeEventListener('abort', onAbort);
      if (err) reject(err);
      else resolvePromise(res!);
    };

    const req = http.request(
      {
        host,
        port: opts.port,
        method: opts.method,
        path: opts.path,
        headers,
        agent: false,
        timeout: timeoutMs,
      },
      res => {
        if (res.statusCode === 204 || res.statusCode === 205 || res.statusCode === 304) {
          res.resume();
          finish(null, {
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.alloc(0),
          });
          return;
        }
        readBoundedResponse(res, maxResponseBytes).then(
          r => finish(null, r),
          e => finish(e as Error),
        );
      },
    );

    const onAbort = () => {
      const abortErr = new Error('Loopback request aborted');
      abortErr.name = 'AbortError';
      req.destroy();
      finish(abortErr);
    };
    if (opts.signal) {
      if (opts.signal.aborted) {
        onAbort();
        return;
      }
      opts.signal.addEventListener('abort', onAbort, { once: true });
    }

    req.on('upgrade', (_res, socket) => {
      socket.destroy();
      finish(new Error('Unexpected upgrade on loopback IPC'));
    });
    req.on('timeout', () => {
      req.destroy();
      finish(new Error(`Loopback IPC timed out after ${timeoutMs}ms`));
    });
    req.on('error', err => finish(err));
    if (bodyBuf !== undefined) req.write(bodyBuf);
    req.end();
  });
}
