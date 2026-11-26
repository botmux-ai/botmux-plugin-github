import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const rootDir = resolve(import.meta.dirname, '..', '..');

describe('Built dist/server/settings.js, dist/dashboard/index.js & dist/cli/index.js end-to-end', () => {
  it('exercises settings.js write-only secrets & actions without BOTMUX_PLUGIN_HOME env, dashboard dual-path rendering, and all 4 CLI commands', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-gh-ui-cli-'));
    const pluginHome = join(tmp, 'plugin-home');
    await fsp.mkdir(pluginHome, { recursive: true, mode: 0o700 });

    const githubServer = http.createServer((req, res) => {
      if (req.url === '/user') {
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'X-OAuth-Scopes': 'repo',
          'X-RateLimit-Resource': 'core',
          'X-RateLimit-Limit': '5000',
          'X-RateLimit-Remaining': '4998',
          'X-RateLimit-Reset': String(Math.floor(Date.now() / 1000) + 3600),
        });
        res.end(JSON.stringify({ login: 'octo-tester' }));
        return;
      }
      if (req.url?.startsWith('/repos/acme/ui-repo/pulls?')) {
        res.writeHead(200, { 'Content-Type': 'application/json', ETag: '"etag-ui-1"' });
        res.end(
          JSON.stringify([
            {
              number: 21,
              title: 'UI Test PR',
              body: 'Testing CLI and settings',
              state: 'open',
              draft: false,
              html_url: 'https://github.com/acme/ui-repo/pull/21',
              user: { login: 'octo-tester' },
              base: { ref: 'main', repo: { full_name: 'acme/ui-repo' } },
              head: { ref: 'feat/ui', sha: 'a'.repeat(40), repo: { full_name: 'acme/ui-repo', fork: false } },
              labels: [],
              maintainer_can_modify: true,
              created_at: '2026-11-25T00:00:00Z',
              updated_at: '2026-11-25T00:00:00Z',
            },
          ]),
        );
        return;
      }
      if (req.url === '/repos/acme/ui-repo/pulls/21') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            number: 21,
            title: 'UI Test PR',
            body: 'Testing CLI and settings',
            state: 'open',
            draft: false,
            html_url: 'https://github.com/acme/ui-repo/pull/21',
            user: { login: 'octo-tester' },
            base: { ref: 'main', repo: { full_name: 'acme/ui-repo' } },
            head: { ref: 'feat/ui', sha: 'a'.repeat(40), repo: { full_name: 'acme/ui-repo', fork: false } },
            labels: [],
            maintainer_can_modify: true,
            created_at: '2026-11-25T00:00:00Z',
            updated_at: '2026-11-25T00:00:00Z',
          }),
        );
        return;
      }
      res.writeHead(404);
      res.end('{}');
    });

    await new Promise<void>(r => githubServer.listen(0, '127.0.0.1', () => r()));
    const ghPort = (githubServer.address() as { port: number }).port;

    const prevAllow = process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API;
    const prevPluginHome = process.env.BOTMUX_PLUGIN_HOME;
    process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API = '1';
    delete process.env.BOTMUX_PLUGIN_HOME;

    try {
      // 1. Test built dist/server/settings.js (named exports, derives pluginHome from api.config.path!)
      const settingsMod = await import(
        pathToFileURL(join(rootDir, 'dist', 'server', 'settings.js')).href
      );
      assert.equal(typeof settingsMod.getSettings, 'function');
      assert.equal(typeof settingsMod.saveSettings, 'function');

      const configPath = join(pluginHome, 'config.json');
      let storedCfg: Record<string, unknown> = {};
      const configApi = {
        path: configPath,
        get: () => storedCfg,
        set: (k: string, v: unknown) => {
          storedCfg[k] = v;
        },
        replace: (v: Record<string, unknown>) => {
          storedCfg = v;
          void fsp.writeFile(configPath, JSON.stringify(v, null, 2), { mode: 0o600 });
        },
      };

      const saved = await settingsMod.saveSettings(
        { config: configApi },
        {
          action: 'saveConfig',
          patch: {
            github: {
              mode: 'pat',
              apiBaseUrl: `http://127.0.0.1:${ghPort}`,
              pat: 'github_pat_secretSettingsToken1234567890',
            },
            repos: [
              {
                repo: 'acme/ui-repo',
                enabled: true,
                creatorBotAppId: 'cli_creator1',
                kickoffBotAppId: 'cli_reviewer2',
              },
            ],
          },
        },
      );
      assert.equal(saved.ok, true);
      assert.equal(saved.config.github.hasPat, true);
      assert.ok(!JSON.stringify(saved).includes('github_pat_secretSettingsToken'), 'PAT must NEVER echo back');

      // Wait briefly for async file write in mock replace()
      await fsp.writeFile(configPath, JSON.stringify(storedCfg, null, 2), { mode: 0o600 });

      const fetched = await settingsMod.getSettings({ config: configApi });
      assert.equal(fetched.ok, true);
      assert.equal(fetched.config.github.hasPat, true);
      assert.ok(!JSON.stringify(fetched).includes('github_pat_secretSettingsToken'));

      const authRes = await settingsMod.saveSettings({ config: configApi }, { action: 'testAuth' });
      assert.equal(authRes.ok, true);
      assert.equal(authRes.identity, '@octo-tester');

      // Security regression test: unsaved testAuth patch changing apiBaseUrl origin MUST NOT exfiltrate stored PAT!
      const exfilAttempt = await settingsMod.saveSettings(
        { config: configApi },
        {
          action: 'testAuth',
          patch: { github: { apiBaseUrl: 'https://attacker.example/api/v3' } },
        },
      );
      assert.equal(exfilAttempt.ok, false);
      assert.ok(String(exfilAttempt.error).includes('explicitly supplying credentials'));

      // Invalid payload must return { ok: false, error } without throwing
      const badRes = await settingsMod.saveSettings({ config: configApi }, 'not-an-object');
      assert.equal(badRes.ok, false);
      assert.ok(typeof badRes.error === 'string');

      // 2. Test built dist/dashboard/index.js renders via api.react (zero bundled React)
      const dashMod = await import(
        pathToFileURL(join(rootDir, 'dist', 'dashboard', 'index.js')).href
      );
      assert.equal(typeof dashMod.default, 'function');

      let serviceFetchCalled = false;
      const effects: Array<() => void> = [];
      const mockReact = {
        createElement: (type: unknown, props: unknown, ...children: unknown[]) => ({
          type,
          props,
          children,
        }),
        useState: <T,>(init: T | (() => T)) => {
          const val = typeof init === 'function' ? (init as () => T)() : init;
          return [val, () => {}] as [T, (next: T | ((prev: T) => T)) => void];
        },
        useEffect: (fn: () => void) => {
          effects.push(fn);
        },
        useCallback: <T,>(fn: T) => fn,
        useMemo: <T,>(fn: () => T) => fn(),
      };

      // Render with new-core api.serviceFetch
      const vdom = dashMod.default({
        pluginId: 'github',
        api: {
          react: mockReact,
          getSettings: async () => fetched,
          saveSettings: async (v: unknown) => settingsMod.saveSettings({ config: configApi }, v),
          listBots: async () => [
            { id: 'cli_creator1', name: 'Creator', plugins: ['github'] },
            { id: 'cli_reviewer2', name: 'Reviewer', plugins: ['github'] },
          ],
          serviceFetch: async () => {
            serviceFetchCalled = true;
            return { ok: true, status: 200, json: async () => fetched };
          },
        },
      });
      assert.ok(vdom && typeof vdom === 'object');
      for (const eff of effects) eff();
      await new Promise(r => setTimeout(r, 30));
      assert.equal(serviceFetchCalled, true, 'Dashboard must prefer api.serviceFetch when provided by new core');

      // 3. Test all 4 CLI commands in built dist/cli/index.js
      const cliMod = await import(
        pathToFileURL(join(rootDir, 'dist', 'cli', 'index.js')).href
      );
      const cli = cliMod.default;
      const cliApi = { config: { path: configPath } };

      const statusJson = await cli['github:status'].run({ args: ['--json'], api: cliApi }, cliApi);
      const parsedStatus = JSON.parse(String(statusJson));
      assert.equal(parsedStatus.config.github.hasPat, true);
      assert.ok(!String(statusJson).includes('github_pat_secretSettingsToken'));

      const authCode = await cli['github:test-auth'].run({ args: ['--json'], api: cliApi }, cliApi);
      assert.equal(authCode, 0);

      const syncCode = await cli['github:sync'].run({ args: ['--dry-run', '--json'], api: cliApi }, cliApi);
      assert.equal(syncCode, 0);

      // Unknown --repo must exit non-zero (1)!
      const unknownRepoSync = await cli['github:sync'].run(
        { args: ['--repo', 'unknown/missing', '--json'], api: cliApi },
        cliApi,
      );
      assert.equal(unknownRepoSync, 1);

      const openPrCode = await cli['github:open-pr'].run(
        { args: ['acme/ui-repo#21', '--dry-run', '--json'], api: cliApi },
        cliApi,
      );
      assert.equal(openPrCode, 0);

      // Invalid PR spec must exit 1
      const badPrCode = await cli['github:open-pr'].run(
        { args: ['invalid-spec', '--json'], api: cliApi },
        cliApi,
      );
      assert.equal(badPrCode, 1);
    } finally {
      if (prevAllow === undefined) delete process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API;
      else process.env.BOTMUX_GITHUB_ALLOW_INSECURE_TEST_API = prevAllow;
      if (prevPluginHome !== undefined) process.env.BOTMUX_PLUGIN_HOME = prevPluginHome;
      await new Promise<void>(r => githubServer.close(() => r()));
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });
});
