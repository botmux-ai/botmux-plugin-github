import { constants as fsConstants, existsSync, promises as fsp, readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import os from 'node:os';
import { dirname, basename, join, parse as parsePath, relative, resolve, sep } from 'node:path';
import { randomBytes } from 'node:crypto';

export type SecurityFsErrorCode =
  | 'SYMLINK_REJECTED'
  | 'NON_REGULAR_FILE'
  | 'UID_MISMATCH'
  | 'HARDLINK_REJECTED'
  | 'LOCK_TIMEOUT'
  | 'SIZE_EXCEEDED'
  | 'INVALID_PATH';

export class SecurityFsError extends Error {
  readonly code: SecurityFsErrorCode;

  constructor(code: SecurityFsErrorCode, message: string) {
    super(message);
    this.name = 'SecurityFsError';
    this.code = code;
  }
}

export interface SafeReadOptions {
  maxBytes: number;
  requireMode0600?: boolean;
  rejectHardlinks?: boolean;
}

export interface FileLockHandle {
  readonly lockPath: string;
  readonly nonce: string;
  verifyOwned(): Promise<boolean>;
  renew(): Promise<boolean>;
  release(): Promise<void>;
}

const O_NOFOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const O_NONBLOCK = fsConstants.O_NONBLOCK ?? 0;
const O_DIRECTORY = (fsConstants as Record<string, number>).O_DIRECTORY ?? 0;

function currentUid(): number | null {
  return typeof process.getuid === 'function' ? process.getuid() : null;
}

function isSymlinkErrno(err: unknown): boolean {
  const code = (err as NodeJS.ErrnoException)?.code;
  return code === 'ELOOP' || code === 'EMLINK';
}

function assertCleanPath(p: string): void {
  if (!p || typeof p !== 'string' || p.includes('\0')) {
    throw new SecurityFsError('INVALID_PATH', 'Filesystem path is invalid');
  }
}

function getTrustedRootBoundary(absPath: string): string {
  const candidates = [resolve(os.tmpdir()), resolve(os.homedir())];
  if (process.platform === 'darwin') {
    candidates.push('/tmp', '/var');
  }
  candidates.sort((a, b) => b.length - a.length);
  for (const root of candidates) {
    const prefix = root.endsWith(sep) ? root : `${root}${sep}`;
    if (absPath === root || absPath.startsWith(prefix)) {
      return root;
    }
  }
  return parsePath(absPath).root;
}

/**
 * Walks every path component strictly below the OS/session trusted root boundary
 * (os.tmpdir(), os.homedir(), or filesystem root) and rejects any existing symlink
 * ancestor so writes/reads can never traverse a non-immediate ancestor symlink.
 */
async function assertNoAncestorSymlinks(absTargetPath: string): Promise<void> {
  const abs = resolve(absTargetPath);
  const boundary = getTrustedRootBoundary(abs);
  const rel = relative(boundary, abs);
  if (!rel || rel === '.') return;

  const segments = rel.split(sep).filter(Boolean);
  let cursor = boundary;
  for (const segment of segments) {
    cursor = join(cursor, segment);
    try {
      const lst = await fsp.lstat(cursor);
      if (lst.isSymbolicLink()) {
        throw new SecurityFsError('SYMLINK_REJECTED', `Refusing symlink in path: ${cursor}`);
      }
    } catch (err: unknown) {
      if (err instanceof SecurityFsError) throw err;
      if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') {
        // Remaining segments do not exist yet
        break;
      }
      throw err;
    }
  }
}

/**
 * Ensures a sensitive directory exists with mode 0700, contains no symlink
 * ancestors below the trusted root boundary, and is owned by current UID.
 */
export async function ensureSecureDir(dirPath: string): Promise<void> {
  assertCleanPath(dirPath);
  const abs = resolve(dirPath);

  await assertNoAncestorSymlinks(abs);
  await fsp.mkdir(abs, { recursive: true, mode: 0o700 });
  await assertNoAncestorSymlinks(abs);

  // Open directory with O_NOFOLLOW (+ O_DIRECTORY where available) and fstat/fchmod the fd to avoid TOCTOU
  let dirHandle: fsp.FileHandle | undefined;
  try {
    dirHandle = await fsp.open(abs, fsConstants.O_RDONLY | O_NOFOLLOW | O_DIRECTORY | O_NONBLOCK);
  } catch (err: unknown) {
    if (isSymlinkErrno(err)) {
      throw new SecurityFsError('SYMLINK_REJECTED', `Refusing symlink directory: ${abs}`);
    }
    if ((err as NodeJS.ErrnoException)?.code === 'ENOTDIR') {
      throw new SecurityFsError('NON_REGULAR_FILE', `Expected directory at: ${abs}`);
    }
    // Fallback for platforms that disallow opening directories
    const lst = await fsp.lstat(abs);
    if (lst.isSymbolicLink()) {
      throw new SecurityFsError('SYMLINK_REJECTED', `Refusing symlink directory: ${abs}`);
    }
    if (!lst.isDirectory()) {
      throw new SecurityFsError('NON_REGULAR_FILE', `Expected directory at: ${abs}`);
    }
    const uid = currentUid();
    if (uid !== null && lst.uid !== uid) {
      throw new SecurityFsError('UID_MISMATCH', `Directory UID mismatch at: ${abs}`);
    }
    if ((lst.mode & 0o077) !== 0) {
      await fsp.chmod(abs, 0o700);
    }
    return;
  }

  try {
    const st = await dirHandle.stat();
    if (!st.isDirectory()) {
      throw new SecurityFsError('NON_REGULAR_FILE', `Expected directory at: ${abs}`);
    }
    const uid = currentUid();
    if (uid !== null && st.uid !== uid) {
      throw new SecurityFsError('UID_MISMATCH', `Directory UID mismatch at: ${abs}`);
    }
    if ((st.mode & 0o077) !== 0) {
      await dirHandle.chmod(0o700);
    }
  } finally {
    await dirHandle.close().catch(() => {});
  }
}

/**
 * Opens an existing regular file with O_NOFOLLOW | O_NONBLOCK (preventing FIFO hangs),
 * verifies via fstat(fd) that it is a regular file, owned by current UID, single-linked
 * (unless opted out), and within maxBytes.
 */
export async function readSecureFile(
  filePath: string,
  opts: SafeReadOptions,
): Promise<Buffer> {
  assertCleanPath(filePath);
  const abs = resolve(filePath);
  await assertNoAncestorSymlinks(abs);
  let handle: fsp.FileHandle | undefined;
  try {
    handle = await fsp.open(abs, fsConstants.O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
  } catch (err: unknown) {
    if (isSymlinkErrno(err)) {
      throw new SecurityFsError('SYMLINK_REJECTED', `Refusing symlink file: ${abs}`);
    }
    if ((err as NodeJS.ErrnoException)?.code === 'ENXIO') {
      throw new SecurityFsError('NON_REGULAR_FILE', `Refusing FIFO/special file: ${abs}`);
    }
    throw err;
  }

  try {
    const st = await handle.stat();
    if (!st.isFile()) {
      throw new SecurityFsError('NON_REGULAR_FILE', `Refusing non-regular file: ${abs}`);
    }
    const uid = currentUid();
    if (uid !== null && st.uid !== uid) {
      throw new SecurityFsError('UID_MISMATCH', `File UID mismatch: ${abs}`);
    }
    if (opts.rejectHardlinks !== false && st.nlink > 1) {
      throw new SecurityFsError('HARDLINK_REJECTED', `Refusing hardlinked file: ${abs}`);
    }
    if (st.size > opts.maxBytes) {
      throw new SecurityFsError(
        'SIZE_EXCEEDED',
        `File exceeds maximum allowed size (${opts.maxBytes} bytes): ${abs}`,
      );
    }
    if (opts.requireMode0600 && (st.mode & 0o077) !== 0) {
      await handle.chmod(0o600);
    }
    const buf = Buffer.allocUnsafe(st.size);
    let offset = 0;
    while (offset < st.size) {
      const { bytesRead } = await handle.read(buf, offset, st.size - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    return offset === st.size ? buf : buf.subarray(0, offset);
  } finally {
    await handle.close();
  }
}

export async function readSecureFileIfExists(
  filePath: string,
  opts: SafeReadOptions,
): Promise<Buffer | null> {
  try {
    return await readSecureFile(filePath, opts);
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') {
      return null;
    }
    throw err;
  }
}

async function fsyncDirBestEffort(dirPath: string): Promise<void> {
  let dirHandle: fsp.FileHandle | undefined;
  try {
    dirHandle = await fsp.open(dirPath, fsConstants.O_RDONLY | O_NOFOLLOW);
    await dirHandle.sync();
  } catch {
    // Some filesystems / platforms do not support fsync on directory fds.
  } finally {
    if (dirHandle) {
      await dirHandle.close().catch(() => {});
    }
  }
}

async function assertTargetRegularIfExists(abs: string): Promise<void> {
  try {
    const existing = await fsp.lstat(abs);
    if (existing.isSymbolicLink()) {
      throw new SecurityFsError('SYMLINK_REJECTED', `Refusing to overwrite symlink: ${abs}`);
    }
    if (!existing.isFile()) {
      throw new SecurityFsError('NON_REGULAR_FILE', `Refusing to overwrite non-regular file: ${abs}`);
    }
    const uid = currentUid();
    if (uid !== null && existing.uid !== uid) {
      throw new SecurityFsError('UID_MISMATCH', `Refusing to overwrite file owned by another UID: ${abs}`);
    }
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
      throw err;
    }
  }
}

/**
 * Atomically writes a sensitive file with mode 0600 using an unpredictable
 * same-directory temporary file opened with O_CREAT|O_EXCL|O_NOFOLLOW,
 * refusing to overwrite symlinks or non-regular files.
 */
export async function writeSecureFileAtomic(
  filePath: string,
  content: Buffer | string,
): Promise<void> {
  assertCleanPath(filePath);
  const abs = resolve(filePath);
  const dir = dirname(abs);
  const base = basename(abs);
  await ensureSecureDir(dir);
  await assertTargetRegularIfExists(abs);

  const data = typeof content === 'string' ? Buffer.from(content, 'utf8') : content;
  const tmpName = `.${base}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`;
  const tmpPath = join(dir, tmpName);

  let handle: fsp.FileHandle | undefined;
  try {
    handle = await fsp.open(
      tmpPath,
      fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | O_NOFOLLOW,
      0o600,
    );
    await handle.chmod(0o600);
    await handle.writeFile(data);
    await handle.sync();
    await handle.close();
    handle = undefined;

    await assertTargetRegularIfExists(abs);
    await fsp.rename(tmpPath, abs);
    await fsyncDirBestEffort(dir);
  } catch (err) {
    if (handle) {
      await handle.close().catch(() => {});
    }
    await fsp.unlink(tmpPath).catch(() => {});
    throw err;
  }
}

interface LockPayload {
  pid: number;
  startedAt: number;
  heartbeatAt?: number;
  processIdentity?: string;
  nonce: string;
}

const LINUX_BOOT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
let cachedLinuxBootId: string | null | undefined;

export function readLinuxBootIdentity(): string | undefined {
  if (process.platform !== 'linux') return undefined;
  if (cachedLinuxBootId !== undefined) return cachedLinuxBootId ?? undefined;
  try {
    const raw = readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
    cachedLinuxBootId = LINUX_BOOT_ID_RE.test(raw) ? raw.toLowerCase() : null;
  } catch {
    cachedLinuxBootId = null;
  }
  return cachedLinuxBootId ?? undefined;
}

type ProcIdentityProbe =
  | { status: 'alive'; identity: string }
  | { status: 'dead' }
  | { status: 'unknown' };

function probeLinuxProcIdentity(pid: number): ProcIdentityProbe {
  try {
    const raw = readFileSync(`/proc/${pid}/stat`, 'utf8');
    const closeParen = raw.lastIndexOf(')');
    if (closeParen < 0) return { status: 'unknown' };
    const fields = raw.slice(closeParen + 2).trim().split(/\s+/);
    // Field 3 (index 0) is state; zombie 'Z' and dead 'X'/'x' cannot hold locks
    if (fields[0] === 'Z' || fields[0] === 'X' || fields[0] === 'x') {
      return { status: 'dead' };
    }
    const startTicks = fields[19];
    if (!startTicks || !/^\d+$/.test(startTicks)) {
      return { status: 'unknown' };
    }
    const bootId = readLinuxBootIdentity();
    return { status: 'alive', identity: bootId ? `${bootId}:${startTicks}` : startTicks };
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT' || code === 'ESRCH') {
      return { status: 'dead' };
    }
    // Transient errors (EMFILE, EACCES, etc.) must NOT be misclassified as dead
    return { status: 'unknown' };
  }
}

function probeDurableProcessIdentity(pid: number): ProcIdentityProbe {
  if (!Number.isSafeInteger(pid) || pid <= 0) return { status: 'dead' };
  if (process.platform === 'linux') {
    return probeLinuxProcIdentity(pid);
  }
  if (process.platform === 'darwin' || process.platform === 'freebsd') {
    const psBin = existsSync('/bin/ps') ? '/bin/ps' : existsSync('/usr/bin/ps') ? '/usr/bin/ps' : null;
    if (!psBin) return { status: 'unknown' };
    try {
      const out = execFileSync(psBin, ['-o', 'stat=,lstart=', '-p', String(pid)], {
        encoding: 'utf8',
        timeout: 2_000,
        stdio: ['ignore', 'pipe', 'ignore'],
        env: { PATH: '/usr/bin:/bin', LANG: 'C' },
      }).trim();
      if (!out) return { status: 'dead' };
      const firstSpace = out.search(/\s+/);
      if (firstSpace <= 0) return { status: 'unknown' };
      const stat = out.slice(0, firstSpace).trim();
      const lstart = out.slice(firstSpace).trim();
      if (stat.startsWith('Z')) return { status: 'dead' };
      return lstart ? { status: 'alive', identity: lstart } : { status: 'unknown' };
    } catch {
      return { status: 'unknown' };
    }
  }
  return { status: 'unknown' };
}

/**
 * Returns a durable process-birth + boot identity string for `pid` (including PID 1
 * inside containers) to distinguish the original lock owner from PID reuse or reboot.
 */
export function readDurableProcessIdentity(pid: number): string | undefined {
  const probed = probeDurableProcessIdentity(pid);
  return probed.status === 'alive' ? probed.identity : undefined;
}

function isPidAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === 'ESRCH') return false;
    return true;
  }
}

async function readLockPayload(
  lockPath: string,
): Promise<{ payload: LockPayload | null; mtimeMs: number } | null> {
  let handle: fsp.FileHandle | undefined;
  try {
    handle = await fsp.open(lockPath, fsConstants.O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    const st = await handle.stat();
    if (!st.isFile()) {
      throw new SecurityFsError('NON_REGULAR_FILE', `Lock path is not a regular file: ${lockPath}`);
    }
    const uid = currentUid();
    if (uid !== null && st.uid !== uid) {
      throw new SecurityFsError('UID_MISMATCH', `Lock file UID mismatch: ${lockPath}`);
    }
    if (st.size > 4096) {
      return { payload: null, mtimeMs: st.mtimeMs };
    }
    const raw = await handle.readFile({ encoding: 'utf8' });
    let parsed: Partial<LockPayload>;
    try {
      parsed = JSON.parse(raw) as Partial<LockPayload>;
    } catch {
      // Empty/truncated lockfile from crash mid-write must still be eligible for staleMs recovery
      return { payload: null, mtimeMs: st.mtimeMs };
    }
    if (
      parsed &&
      typeof parsed === 'object' &&
      typeof parsed.pid === 'number' &&
      typeof parsed.startedAt === 'number' &&
      typeof parsed.nonce === 'string'
    ) {
      return {
        payload: {
          pid: parsed.pid,
          startedAt: parsed.startedAt,
          ...(typeof parsed.heartbeatAt === 'number' ? { heartbeatAt: parsed.heartbeatAt } : {}),
          ...(typeof parsed.processIdentity === 'string' && parsed.processIdentity.trim()
            ? { processIdentity: parsed.processIdentity.trim() }
            : {}),
          nonce: parsed.nonce,
        },
        mtimeMs: st.mtimeMs,
      };
    }
    return { payload: null, mtimeMs: st.mtimeMs };
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT') return null;
    if (isSymlinkErrno(err)) {
      throw new SecurityFsError('SYMLINK_REJECTED', `Refusing symlink lockfile: ${lockPath}`);
    }
    if (code === 'ENXIO') {
      throw new SecurityFsError('NON_REGULAR_FILE', `Refusing FIFO lockfile: ${lockPath}`);
    }
    if (err instanceof SecurityFsError) throw err;
    return null;
  } finally {
    if (handle) await handle.close().catch(() => {});
  }
}

/**
 * Acquires an exclusive nonce-tagged lockfile using O_CREAT|O_EXCL|O_NOFOLLOW
 * with durable process-birth + boot identity verification, in-place inode mtime
 * heartbeat renewal, and nonce-verified fencing + release.
 *
 * CRITICAL INVARIANTS:
 * - A lock owned by the SAME LIVE PROCESS (`pid` alive AND durable `processIdentity`
 *   matches) is NEVER stolen solely due to elapsed wall-clock age (`staleMs`)!
 * - A lock whose PID is dead, zombie, or reused by an unrelated process (`processIdentity`
 *   mismatch or reboot) IS immediately reclaimed!
 * - Legacy lockfiles without `processIdentity` or empty/corrupt lockfiles are reclaimed
 *   once older than `staleMs`.
 */
export async function acquireSecureLock(
  lockPath: string,
  opts?: {
    timeoutMs?: number;
    staleMs?: number;
    pollMs?: number;
    heartbeatIntervalMs?: number;
    now?: () => number;
    readProcessIdentity?: (pid: number) => string | undefined;
  },
): Promise<FileLockHandle> {
  assertCleanPath(lockPath);
  const abs = resolve(lockPath);
  const dir = dirname(abs);
  await ensureSecureDir(dir);

  const now = opts?.now ?? (() => Date.now());
  const getProcIdentity = opts?.readProcessIdentity ?? readDurableProcessIdentity;
  const timeoutMs = opts?.timeoutMs ?? 10_000;
  const staleMs = opts?.staleMs ?? 30_000;
  const pollMs = opts?.pollMs ?? 25;
  const heartbeatIntervalMs = opts?.heartbeatIntervalMs ?? Math.max(1_000, Math.min(15_000, Math.floor(staleMs / 3)));
  const nonce = randomBytes(16).toString('hex');
  const waitDeadline = Date.now() + timeoutMs;
  const selfIdentity = getProcIdentity(process.pid);

  while (true) {
    const acquiredAt = now();
    const payload: LockPayload = {
      pid: process.pid,
      startedAt: acquiredAt,
      heartbeatAt: acquiredAt,
      ...(selfIdentity ? { processIdentity: selfIdentity } : {}),
      nonce,
    };
    let handle: fsp.FileHandle | undefined;
    try {
      handle = await fsp.open(
        abs,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | O_NOFOLLOW,
        0o600,
      );
      await handle.chmod(0o600);
      await handle.writeFile(JSON.stringify(payload), 'utf8');
      await handle.sync();
      const heldStat = await handle.stat();
      const heldDev = heldStat.dev;
      const heldIno = heldStat.ino;

      // Keep the exclusive FileHandle open for the lock lifetime and serialize renew/release.
      // Renew updates the held inode's mtime in-place via handle.utimes() — NEVER via rename() —
      // so renew() can NEVER resurrect a released lockfile or overwrite a new holder's lock!
      const lockHandle = handle;
      handle = undefined;
      let released = false;
      let inFlightRenew: Promise<boolean> | null = null;

      const verifyPathMatchesHeldInode = async (): Promise<boolean> => {
        try {
          const lst = await fsp.lstat(abs);
          if (lst.isSymbolicLink() || !lst.isFile()) return false;
          return lst.dev === heldDev && lst.ino === heldIno;
        } catch {
          return false;
        }
      };

      const verifyOwned = async (): Promise<boolean> => {
        if (released) return false;
        if (!(await verifyPathMatchesHeldInode())) return false;
        const current = await readLockPayload(abs).catch(() => null);
        return current?.payload?.nonce === nonce && current.payload.pid === process.pid;
      };

      const renew = async (): Promise<boolean> => {
        if (released) return false;
        if (inFlightRenew) return inFlightRenew;
        inFlightRenew = (async () => {
          try {
            if (released) return false;
            if (!(await verifyPathMatchesHeldInode())) return false;
            const ts = new Date(now());
            await lockHandle.utimes(ts, ts);
            return !released;
          } catch {
            return false;
          } finally {
            inFlightRenew = null;
          }
        })();
        return inFlightRenew;
      };

      const hbTimer =
        heartbeatIntervalMs > 0
          ? setInterval(() => {
              if (!released && !inFlightRenew) {
                void renew();
              }
            }, heartbeatIntervalMs)
          : null;
      hbTimer?.unref?.();

      return {
        lockPath: abs,
        nonce,
        verifyOwned,
        renew,
        async release() {
          if (released) return;
          released = true;
          if (hbTimer) clearInterval(hbTimer);
          if (inFlightRenew) {
            await inFlightRenew.catch(() => {});
          }
          try {
            if (await verifyPathMatchesHeldInode()) {
              const current = await readLockPayload(abs).catch(() => null);
              if (current?.payload?.nonce === nonce) {
                await fsp.unlink(abs).catch(() => {});
              }
            }
          } finally {
            await lockHandle.close().catch(() => {});
          }
        },
      };
    } catch (err: unknown) {
      if (handle) {
        await handle.close().catch(() => {});
      }
      if (isSymlinkErrno(err)) {
        throw new SecurityFsError('SYMLINK_REJECTED', `Refusing symlink lockfile: ${abs}`);
      }
      if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') {
        throw err;
      }

      const existing = await readLockPayload(abs);
      if (existing) {
        let canSteal = false;
        if (existing.payload) {
          if (!isPidAlive(existing.payload.pid)) {
            canSteal = true;
          } else if (existing.payload.processIdentity) {
            // Verify durable process-birth + boot identity to detect zombies, reboots, and PID reuse!
            // On transient probe failure ('unknown'), do NOT prematurely steal a fresh live lock.
            if (opts?.readProcessIdentity) {
              const liveId = getProcIdentity(existing.payload.pid);
              canSteal = !liveId || liveId !== existing.payload.processIdentity;
            } else {
              const probed = probeDurableProcessIdentity(existing.payload.pid);
              if (probed.status === 'dead') {
                canSteal = true;
              } else if (probed.status === 'alive') {
                canSteal = probed.identity !== existing.payload.processIdentity;
              } else {
                canSteal = false;
              }
            }
          } else {
            // Legacy lockfile lacking processIdentity (cannot prove PID wasn't reused): reclaim after staleMs
            const lastSeenMs = Math.max(
              existing.payload.heartbeatAt ?? existing.payload.startedAt,
              existing.mtimeMs,
            );
            canSteal = now() - lastSeenMs > staleMs;
          }
        } else {
          // Empty/corrupt lockfile (e.g. SIGKILL mid-creation): reclaim after staleMs
          const ageMs = now() - existing.mtimeMs;
          canSteal = ageMs > staleMs;
        }
        if (canSteal) {
          const again = await readLockPayload(abs);
          if (
            again &&
            again.payload?.nonce === existing.payload?.nonce &&
            again.mtimeMs === existing.mtimeMs
          ) {
            await fsp.unlink(abs).catch(() => {});
            continue;
          }
        }
      }

      if (Date.now() >= waitDeadline) {
        throw new SecurityFsError('LOCK_TIMEOUT', `Timed out acquiring lock: ${abs}`);
      }
      await new Promise(r => setTimeout(r, pollMs));
    }
  }
}

/**
 * Appends a single redacted JSONL line safely with O_NOFOLLOW | O_NONBLOCK and
 * 0600 permissions, rotating the file when size reaches maxBytes.
 */
export async function appendSecureJsonl(
  filePath: string,
  redactedLine: string,
  opts: { maxBytes?: number; maxBackups?: number; lockPath?: string } = {},
): Promise<void> {
  assertCleanPath(filePath);
  const abs = resolve(filePath);
  const dir = dirname(abs);
  await ensureSecureDir(dir);

  const maxBytes = opts.maxBytes ?? 5 * 1024 * 1024;
  const maxBackups = opts.maxBackups ?? 3;
  const lock = opts.lockPath ? await acquireSecureLock(opts.lockPath) : null;

  try {
    let handle: fsp.FileHandle | undefined;
    try {
      handle = await fsp.open(
        abs,
        fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | O_NOFOLLOW | O_NONBLOCK,
        0o600,
      );
    } catch (err: unknown) {
      if (isSymlinkErrno(err)) {
        throw new SecurityFsError('SYMLINK_REJECTED', `Refusing symlink log file: ${abs}`);
      }
      if ((err as NodeJS.ErrnoException)?.code === 'ENXIO') {
        throw new SecurityFsError('NON_REGULAR_FILE', `Refusing FIFO log file: ${abs}`);
      }
      throw err;
    }

    try {
      const st = await handle.stat();
      if (!st.isFile()) {
        throw new SecurityFsError('NON_REGULAR_FILE', `Refusing non-regular log file: ${abs}`);
      }
      const uid = currentUid();
      if (uid !== null && st.uid !== uid) {
        throw new SecurityFsError('UID_MISMATCH', `Log file UID mismatch: ${abs}`);
      }
      if ((st.mode & 0o077) !== 0) {
        await handle.chmod(0o600);
      }

      const line = redactedLine.endsWith('\n') ? redactedLine : `${redactedLine}\n`;
      if (st.size + Buffer.byteLength(line, 'utf8') > maxBytes && st.size > 0) {
        await handle.close();
        handle = undefined;
        await rotateLogFiles(abs, maxBackups);
        handle = await fsp.open(
          abs,
          fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | O_NOFOLLOW | O_NONBLOCK,
          0o600,
        );
        await handle.chmod(0o600);
      }
      await handle.writeFile(line, 'utf8');
    } finally {
      if (handle) await handle.close().catch(() => {});
    }
  } finally {
    if (lock) await lock.release();
  }
}

async function rotateLogFiles(absPath: string, maxBackups: number): Promise<void> {
  if (maxBackups <= 0) {
    await fsp.unlink(absPath).catch(() => {});
    return;
  }
  for (let i = maxBackups; i >= 1; i--) {
    const src = i === 1 ? absPath : `${absPath}.${i - 1}`;
    const dst = `${absPath}.${i}`;
    try {
      const lst = await fsp.lstat(src);
      if (lst.isSymbolicLink() || !lst.isFile()) continue;
      if (i === maxBackups) {
        await fsp.unlink(dst).catch(() => {});
      }
      await fsp.rename(src, dst);
      let dstHandle: fsp.FileHandle | undefined;
      try {
        dstHandle = await fsp.open(dst, fsConstants.O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
        await dstHandle.chmod(0o600);
      } catch {
        // Best-effort
      } finally {
        if (dstHandle) await dstHandle.close().catch(() => {});
      }
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
        throw err;
      }
    }
  }
}
