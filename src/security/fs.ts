import { constants as fsConstants, promises as fsp } from 'node:fs';
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
  nonce: string;
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
        payload: { pid: parsed.pid, startedAt: parsed.startedAt, nonce: parsed.nonce },
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
 * with stale PID / timeout recovery and nonce-verified release.
 */
export async function acquireSecureLock(
  lockPath: string,
  opts?: { timeoutMs?: number; staleMs?: number; pollMs?: number },
): Promise<FileLockHandle> {
  assertCleanPath(lockPath);
  const abs = resolve(lockPath);
  const dir = dirname(abs);
  await ensureSecureDir(dir);

  const timeoutMs = opts?.timeoutMs ?? 10_000;
  const staleMs = opts?.staleMs ?? 30_000;
  const pollMs = opts?.pollMs ?? 25;
  const nonce = randomBytes(16).toString('hex');
  const deadline = Date.now() + timeoutMs;

  while (true) {
    const payload: LockPayload = {
      pid: process.pid,
      startedAt: Date.now(),
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
      await handle.close();
      handle = undefined;

      let released = false;
      return {
        lockPath: abs,
        async release() {
          if (released) return;
          released = true;
          const current = await readLockPayload(abs).catch(() => null);
          if (current?.payload?.nonce === nonce) {
            await fsp.unlink(abs).catch(() => {});
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
        const ageMs = Date.now() - (existing.payload?.startedAt ?? existing.mtimeMs);
        const dead = existing.payload ? !isPidAlive(existing.payload.pid) : ageMs > staleMs;
        if (dead || ageMs > staleMs) {
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

      if (Date.now() >= deadline) {
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
