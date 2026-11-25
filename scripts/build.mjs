#!/usr/bin/env node
import { build } from 'esbuild';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const distDir = join(rootDir, 'dist');
const stampDirName = 'botmux-build';

function assertNoSymlinks(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const st = lstatSync(full);
    if (st.isSymbolicLink()) {
      throw new Error(`Refusing symlink in build output: ${full}`);
    }
    if (st.isDirectory()) {
      assertNoSymlinks(full);
    }
  }
}

async function bundleNode(entry, outfile) {
  await build({
    entryPoints: [entry],
    outfile,
    bundle: true,
    treeShaking: true,
    platform: 'node',
    format: 'esm',
    target: 'node22',
    packages: 'bundle',
    logLevel: 'silent',
  });
}

async function bundleBrowser(entry, outfile) {
  await build({
    entryPoints: [entry],
    outfile,
    bundle: true,
    treeShaking: true,
    platform: 'browser',
    format: 'esm',
    target: 'es2022',
    packages: 'bundle',
    logLevel: 'silent',
  });
}

function writeJson(filePath, data) {
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, `${JSON.stringify(data, null, 2)}\n`, 'utf8');
}

function swapDistAtomically(stagingDir) {
  mkdirSync(distDir, { recursive: true });
  const backupDir = join(rootDir, `.dist-previous-${process.pid}-${Date.now()}`);
  mkdirSync(backupDir, { recursive: true });

  const movedOut = [];
  const movedIn = [];

  try {
    for (const name of readdirSync(distDir)) {
      if (name === stampDirName) continue;
      renameSync(join(distDir, name), join(backupDir, name));
      movedOut.push(name);
    }

    for (const name of readdirSync(stagingDir)) {
      if (name === stampDirName) continue;
      renameSync(join(stagingDir, name), join(distDir, name));
      movedIn.push(name);
    }

    // Write dist/botmux-build/stamp LAST so Botmux --link supervisor reloads once cleanly
    const stampDir = join(distDir, stampDirName);
    mkdirSync(stampDir, { recursive: true });
    writeFileSync(join(stampDir, 'stamp'), `${Date.now()}\n`, 'utf8');

    // Clean up temporary staging & backup directories
    rmSync(stagingDir, { recursive: true, force: true });
    rmSync(backupDir, { recursive: true, force: true });
  } catch (err) {
    // Rollback on partial swap failure
    for (const name of movedIn) {
      rmSync(join(distDir, name), { recursive: true, force: true });
    }
    for (const name of movedOut) {
      if (existsSync(join(backupDir, name))) {
        renameSync(join(backupDir, name), join(distDir, name));
      }
    }
    rmSync(stagingDir, { recursive: true, force: true });
    rmSync(backupDir, { recursive: true, force: true });
    throw err;
  }
}

async function main() {
  const stagingDir = join(rootDir, `.dist-next-${process.pid}-${Date.now()}`);
  mkdirSync(stagingDir, { recursive: true });

  try {
    // 1. Emit dist/package.json so standalone installed dist/ always resolves ESM
    writeJson(join(stagingDir, 'package.json'), {
      private: true,
      type: 'module',
    });

    // 2. Bundle all Node runtime entrypoints into self-contained ESM
    await Promise.all([
      bundleNode(
        join(rootDir, 'src', 'service', 'index.ts'),
        join(stagingDir, 'service', 'index.js'),
      ),
      bundleNode(
        join(rootDir, 'src', 'service', 'runner.ts'),
        join(stagingDir, 'service', 'runner.js'),
      ),
      bundleNode(
        join(rootDir, 'src', 'server', 'settings.ts'),
        join(stagingDir, 'server', 'settings.js'),
      ),
      bundleNode(
        join(rootDir, 'src', 'cli', 'index.ts'),
        join(stagingDir, 'cli', 'index.js'),
      ),
      bundleBrowser(
        join(rootDir, 'src', 'dashboard', 'index.ts'),
        join(stagingDir, 'dashboard', 'index.js'),
      ),
    ]);

    // 3. Generate dist/cli/commands.json from the compiled CLI bundle
    const cliEntry = join(stagingDir, 'cli', 'index.js');
    const cliMod = await import(pathToFileURL(cliEntry).href);
    const cliMap = cliMod.default ?? cliMod;
    const commands = Object.entries(cliMap)
      .map(([name, handler]) => ({
        name,
        ...(typeof handler === 'object' && handler && typeof handler.description === 'string'
          ? { description: handler.description }
          : {}),
      }))
      .sort((a, b) => a.name.localeCompare(b.name));

    writeJson(join(stagingDir, 'cli', 'commands.json'), {
      schemaVersion: 1,
      commands,
    });

    // 4. Emit dist/webhooks/index.json (compatible with upcoming Botmux core /webhook/plugin/github/*)
    writeJson(join(stagingDir, 'webhooks', 'index.json'), {
      schemaVersion: 1,
      endpoint: '/webhooks/github',
      mountPath: '/webhook/plugin/github',
      routes: [
        {
          id: 'events',
          path: '/webhook/plugin/github/events',
          targetEndpoint: '/webhooks/github',
          methods: ['POST'],
          rawBody: true,
          maxBodyBytes: 1048576,
          forwardHeaders: [
            'x-github-event',
            'x-github-delivery',
            'x-hub-signature-256',
            'content-type',
            'user-agent',
          ],
        },
      ],
    });

    // 5. Verify zero symlinks and swap into dist/ atomically
    assertNoSymlinks(stagingDir);
    swapDistAtomically(stagingDir);

    console.log(
      `Built @botmux-ai/plugin-github into dist/ (${commands.length} CLI commands, atomic stamp updated).`,
    );
  } catch (err) {
    rmSync(stagingDir, { recursive: true, force: true });
    throw err;
  }
}

await main();
