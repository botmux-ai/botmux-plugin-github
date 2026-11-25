#!/usr/bin/env node
import assert from 'node:assert/strict';
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const distDir = join(rootDir, 'dist');

const SEMVER_RE =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const PLUGIN_ID_RE = /^[a-z][a-z0-9._-]{0,63}$/;
const CLI_NAME_RE = /^[a-z][a-z0-9._:-]{0,63}$/;
const CATEGORY_RE = /^[a-z][a-z0-9-]{0,31}$/;

function assertNoSymlinks(dir) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = lstatSync(full);
    assert.ok(!st.isSymbolicLink(), `Symlink forbidden in dist/: ${full}`);
    if (st.isDirectory()) assertNoSymlinks(full);
  }
}

function validatePackageManifest() {
  const pkg = JSON.parse(readFileSync(join(rootDir, 'package.json'), 'utf8'));
  assert.equal(pkg.name, '@botmux-ai/plugin-github');
  assert.match(pkg.version, SEMVER_RE);
  assert.ok(Array.isArray(pkg.keywords) && pkg.keywords.includes('botmux-plugin'));
  assert.ok(Array.isArray(pkg.files) && pkg.files.includes('dist/'));
  assert.equal(pkg.publishConfig?.registry, 'https://registry.npmjs.org/');
  assert.equal(pkg.publishConfig?.access, 'public');
  assert.equal(
    Object.keys(pkg.dependencies ?? {}).length,
    0,
    'Plugin must have zero runtime dependencies',
  );
  assert.equal(pkg.botmux?.schemaVersion, 1);
  assert.equal(pkg.botmux?.id, 'github');
  assert.match(pkg.botmux?.id, PLUGIN_ID_RE);
  assert.equal(pkg.botmux?.service?.mode, 'auto');
}

function validateDistLayout() {
  const requiredFiles = [
    'package.json',
    'service/index.js',
    'service/runner.js',
    'server/settings.js',
    'dashboard/index.js',
    'cli/index.js',
    'cli/commands.json',
    'webhooks/index.json',
    'botmux-build/stamp',
  ];
  for (const rel of requiredFiles) {
    const full = join(distDir, rel);
    assert.ok(existsSync(full) && statSync(full).isFile(), `Missing required dist file: ${rel}`);
  }
  assertNoSymlinks(distDir);

  const distPkg = JSON.parse(readFileSync(join(distDir, 'package.json'), 'utf8'));
  assert.equal(distPkg.private, true);
  assert.equal(distPkg.type, 'module');

  // Ensure zero bun:* imports anywhere in dist/ and zero node:* / react imports in dashboard bundle
  const dashboardSrc = readFileSync(join(distDir, 'dashboard', 'index.js'), 'utf8');
  assert.ok(!/\bfrom\s+["']react["']/.test(dashboardSrc), 'Dashboard must NOT import/bundle react');
  assert.ok(!/\bfrom\s+["']node:/.test(dashboardSrc), 'Dashboard browser bundle must NOT import node:*');
  assert.ok(!/bun:sqlite/.test(dashboardSrc), 'Must not reference bun:sqlite');

  for (const rel of ['service/index.js', 'service/runner.js', 'server/settings.js', 'cli/index.js']) {
    const code = readFileSync(join(distDir, rel), 'utf8');
    assert.ok(!/bun:sqlite/.test(code), `Forbidden bun:sqlite import in dist/${rel}`);
  }

  const commandsJson = JSON.parse(readFileSync(join(distDir, 'cli', 'commands.json'), 'utf8'));
  assert.equal(commandsJson.schemaVersion, 1);
  assert.ok(Array.isArray(commandsJson.commands) && commandsJson.commands.length === 4);
  for (const cmd of commandsJson.commands) {
    assert.match(cmd.name, CLI_NAME_RE);
  }

  const webhooksJson = JSON.parse(readFileSync(join(distDir, 'webhooks', 'index.json'), 'utf8'));
  assert.equal(webhooksJson.schemaVersion, 1);
  assert.equal(webhooksJson.maxBodyBytes, 1048576);
  assert.ok(Array.isArray(webhooksJson.routes) && webhooksJson.routes.length === 1);
  assert.equal(webhooksJson.routes[0].path, '/events');
  assert.equal(webhooksJson.routes[0].endpoint, '/webhooks/github');
  assert.equal(webhooksJson.routes[0].maxBodyBytes, 1048576);
}

function validateMarketEntry() {
  const entryPath = join(rootDir, 'docs', 'plugin-market-entry.json');
  assert.ok(existsSync(entryPath), 'Missing docs/plugin-market-entry.json');
  const entry = JSON.parse(readFileSync(entryPath, 'utf8'));

  // Exact botmux-ai/plugin-market schema (additionalProperties: false)
  const allowedKeys = new Set([
    'id',
    'package',
    'displayName',
    'description',
    'repo',
    'docs',
    'categories',
    'compatibility',
  ]);
  for (const key of Object.keys(entry)) {
    assert.ok(allowedKeys.has(key), `Unexpected market entry key: ${key}`);
  }
  assert.equal(entry.id, 'github');
  assert.equal(entry.package, '@botmux-ai/plugin-github');
  assert.ok(typeof entry.displayName === 'string' && entry.displayName.length >= 1);
  assert.ok(typeof entry.description === 'string' && entry.description.length >= 1);
  assert.ok(typeof entry.repo === 'string' && entry.repo.startsWith('https://'));
  if (entry.docs !== undefined) {
    assert.ok(typeof entry.docs === 'string' && entry.docs.startsWith('https://'));
  }
  assert.ok(Array.isArray(entry.categories) && entry.categories.length >= 1);
  for (const c of entry.categories) {
    assert.match(c, CATEGORY_RE);
  }
  assert.deepEqual(Object.keys(entry.compatibility ?? {}), ['botmux']);
  assert.ok(typeof entry.compatibility.botmux === 'string' && entry.compatibility.botmux.length > 0);
}

async function validateStandaloneDistCopy() {
  const sandbox = mkdtempSync(join(tmpdir(), 'botmux-plugin-github-validate-'));
  const copiedDist = join(sandbox, 'dist');
  const fakeHome = join(sandbox, 'plugin-home');
  try {
    cpSync(distDir, copiedDist, { recursive: true });

    // 1. Service definition dynamic port test
    const svcMod = await import(pathToFileURL(join(copiedDist, 'service', 'index.js')).href);
    assert.equal(typeof svcMod.default, 'function', 'dist/service/index.js must export default factory function');
    const defDefault = svcMod.default();
    assert.equal(defDefault.mode, 'auto');
    assert.equal(defDefault.pm2.script, './service/runner.js');
    assert.equal(defDefault.pm2.env.PORT, String(defDefault.port));

    const defCustom = svcMod.default({
      config: { get: k => (k === 'service.port' ? 19456 : undefined) },
    });
    assert.equal(defCustom.port, 19456);
    assert.equal(defCustom.pm2.env.PORT, '19456');
    const urls = defCustom.urls({ host: '[::1]', env: {}, port: 19456 });
    assert.equal(urls.healthUrl, 'http://[::1]:19456/health');

    // 2. Settings adapter named exports test
    const settingsMod = await import(pathToFileURL(join(copiedDist, 'server', 'settings.js')).href);
    assert.equal(typeof settingsMod.getSettings, 'function');
    assert.equal(typeof settingsMod.saveSettings, 'function');
    let memCfg = {};
    const fakeApi = {
      config: {
        path: join(fakeHome, 'config.json'),
        get: () => memCfg,
        set: () => {},
        replace: v => {
          memCfg = v;
        },
      },
    };
    const initial = await settingsMod.getSettings(fakeApi);
    assert.equal(initial.ok, true);
    assert.equal(initial.service.mode, 'dormant');

    // 3. CLI commands index matches exported handlers
    const commandsJson = JSON.parse(readFileSync(join(copiedDist, 'cli', 'commands.json'), 'utf8'));
    const cliMod = await import(pathToFileURL(join(copiedDist, 'cli', 'index.js')).href);
    const cliMap = cliMod.default ?? cliMod;
    for (const entry of commandsJson.commands) {
      const handler = cliMap[entry.name];
      assert.ok(
        typeof handler === 'function' || (handler && typeof handler.run === 'function'),
        `CLI handler missing for ${entry.name}`,
      );
    }

    // 4. Dashboard default export check
    const dashMod = await import(pathToFileURL(join(copiedDist, 'dashboard', 'index.js')).href);
    assert.equal(typeof dashMod.default, 'function', 'dist/dashboard/index.js must default-export a component function');
  } finally {
    rmSync(sandbox, { recursive: true, force: true });
  }
}

validatePackageManifest();
validateDistLayout();
validateMarketEntry();
await validateStandaloneDistCopy();
console.log('All @botmux-ai/plugin-github build & standalone dist validations passed.');
