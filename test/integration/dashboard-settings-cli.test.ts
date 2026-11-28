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

  it('renders minimalist Dashboard UI with auto-detected gh-cli card, 2-step preset rule creation, custom advanced backfill, and write-only secrets', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-gh-dash-ux-'));
    const pluginHome = join(tmp, 'plugin-home');
    await fsp.mkdir(pluginHome, { recursive: true, mode: 0o700 });

    const prevPluginHome = process.env.BOTMUX_PLUGIN_HOME;
    delete process.env.BOTMUX_PLUGIN_HOME;

    type VNode = { type: unknown; props: Record<string, unknown>; children: unknown[] };
    const findElements = (node: unknown, pred: (el: VNode) => boolean): VNode[] => {
      const out: VNode[] = [];
      if (!node || typeof node !== 'object') return out;
      if (Array.isArray(node)) {
        for (const item of node) out.push(...findElements(item, pred));
        return out;
      }
      const el = node as { type?: unknown; props?: Record<string, unknown>; children?: unknown[] };
      if (el.type !== undefined) {
        const entry: VNode = { type: el.type, props: el.props ?? {}, children: el.children ?? [] };
        if (pred(entry)) out.push(entry);
        for (const ch of entry.children) out.push(...findElements(ch, pred));
      }
      return out;
    };

    const createHarness = (
      Component: (props: { pluginId: string; api: Record<string, unknown> }) => unknown,
      api: Record<string, unknown>,
    ) => {
      const states: unknown[] = [];
      const memos: Array<{ deps: unknown[] | undefined; value: unknown }> = [];
      let effectRan = false;
      const pendingEffects: Array<() => void> = [];

      const render = () => {
        let stateIdx = 0;
        let memoIdx = 0;
        const mockReact = {
          createElement: (type: unknown, props: Record<string, unknown> | null, ...children: unknown[]) => ({
            type,
            props: props ?? {},
            children,
          }),
          useState: <T,>(init: T | (() => T)) => {
            const idx = stateIdx++;
            if (idx >= states.length) {
              states[idx] = typeof init === 'function' ? (init as () => T)() : init;
            }
            const setState = (next: T | ((prev: T) => T)) => {
              states[idx] =
                typeof next === 'function' ? (next as (prev: T) => T)(states[idx] as T) : next;
            };
            return [states[idx] as T, setState] as [T, (next: T | ((prev: T) => T)) => void];
          },
          useEffect: (fn: () => void) => {
            if (!effectRan) {
              effectRan = true;
              pendingEffects.push(fn);
            }
          },
          useCallback: <T,>(fn: T) => fn,
          useMemo: <T,>(factory: () => T, deps?: unknown[]) => {
            const idx = memoIdx++;
            const prev = memos[idx];
            const depsChanged =
              !prev ||
              !deps ||
              !prev.deps ||
              deps.length !== prev.deps.length ||
              deps.some((d, i) => !Object.is(d, prev.deps![i]));
            if (depsChanged) {
              memos[idx] = { deps, value: factory() };
            }
            return memos[idx]!.value as T;
          },
        };
        return Component({ pluginId: 'github', api: { ...api, react: mockReact } });
      };

      const flushEffects = async () => {
        while (pendingEffects.length > 0) {
          const fn = pendingEffects.shift()!;
          fn();
        }
        await new Promise(r => setTimeout(r, 30));
      };

      return { render, flushEffects };
    };

    try {
      const settingsMod = await import(
        pathToFileURL(join(rootDir, 'dist', 'server', 'settings.js')).href
      );
      const dashMod = await import(
        pathToFileURL(join(rootDir, 'dist', 'dashboard', 'index.js')).href
      );

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

      // Scenario 1 + 2: Fresh install -> auto-detect gh-cli -> 2-step preset rule creation
      const botsFixture = [
        { id: 'cli_creator_online', name: '大管家', plugins: ['github'] },
        { id: 'cli_reviewer_a', name: '评审甲', plugins: ['github'] },
        { id: 'cli_reviewer_b', name: '评审乙', plugins: ['github'] },
      ];
      const botStatusFixture = [
        { id: 'cli_creator_online', name: '大管家', brand: 'feishu', online: true, apiOnly: false },
        { id: 'cli_reviewer_a', name: '评审甲', brand: 'feishu', online: true, apiOnly: false },
        { id: 'cli_reviewer_b', name: '评审乙', brand: 'lark', online: true, apiOnly: false },
      ];

      const h1 = createHarness(dashMod.default, {
        getSettings: async () => {
          const base = await settingsMod.getSettings({ config: configApi });
          return { ...base, botStatus: botStatusFixture };
        },
        saveSettings: async (v: Record<string, unknown>) => {
          if (v.action === 'testAuth') {
            return {
              ok: true,
              authMode: 'auto',
              resolvedMethod: 'gh_cli',
              apiBaseUrl: 'https://api.github.com',
              identity: '@shenhan',
              rateLimit: {
                limit: 5000,
                remaining: 4992,
                resetAt: '2026-11-28T16:00:00Z',
                low: false,
              },
            };
          }
          return settingsMod.saveSettings({ config: configApi }, v);
        },
        listBots: async () => botsFixture,
      });

      h1.render();
      await h1.flushEffects();
      const treeInitial = h1.render();
      const serializedInitial = JSON.stringify(treeInitial);

      // Verify minimalist default view & auto-detected gh-cli status card
      assert.ok(
        serializedInitial.includes('已自动识别本机 GitHub 账号 @shenhan（来自 gh），免配置可直接使用'),
        'Must show green auto-detected gh-cli status card on fresh install',
      );
      assert.ok(serializedInitial.includes('休眠等待首条规则'), 'Must clearly indicate dormant state');
      assert.ok(serializedInitial.includes('4992 / 5000'), 'Must surface API quota in top overview');
      assert.ok(serializedInitial.includes('立即同步一次'), 'Must show Sync Now button');
      assert.ok(
        serializedInitial.includes('轮询 60s · Webhook 未开启 · 无代理'),
        'Global advanced settings must collapse to a 1-line summary',
      );
      assert.equal(
        findElements(treeInitial, el => el.props['data-panel'] === 'auth-switch').length,
        0,
        'Auth switch panel must be collapsed by default',
      );
      assert.equal(
        findElements(treeInitial, el => el.props['data-panel'] === 'global-advanced').length,
        0,
        'Global advanced panel must be collapsed by default',
      );

      // Step 0 -> Click "+ 添加监控仓库"
      const addBtn = findElements(treeInitial, el => el.props['data-action'] === 'add-rule')[0]!;
      assert.ok(addBtn);
      (addBtn.props.onClick as () => void)();

      const treeEditor = h1.render();
      const creatorSelect = findElements(treeEditor, el => el.props['data-field'] === 'creator-bot')[0]!;
      assert.equal(creatorSelect.props.value, 'cli_creator_online', 'Creator bot must auto-preselect first available bot');
      assert.equal(
        findElements(treeEditor, el => el.props['data-panel'] === 'rule-advanced').length,
        0,
        'Rule advanced panel must start collapsed',
      );
      assert.equal(
        findElements(treeEditor, el => el.props['data-badge'] === 'rule-customized-count').length,
        0,
        'Fresh preset rule must show zero customized badge',
      );

      // Step 1: Enter repository slug
      const repoInput = findElements(treeEditor, el => el.props['data-field'] === 'repo')[0]!;
      (repoInput.props.onChange as (e: { target: { value: string } }) => void)({
        target: { value: 'deepcoldy/botmux' },
      });

      // Step 2: Check two Reviewer Bots -> first auto-selected as Kickoff Bot, then switch to second
      const treeAfterRepo = h1.render();
      const revACheck = findElements(treeAfterRepo, el => el.props['data-reviewer-bot'] === 'cli_reviewer_a')[0]!;
      (revACheck.props.onChange as (e: { target: { checked: boolean } }) => void)({
        target: { checked: true },
      });

      const treeAfterRevA = h1.render();
      const kickoffAfterA = findElements(treeAfterRevA, el => el.props['data-field'] === 'kickoff-bot')[0]!;
      assert.equal(kickoffAfterA.props.value, 'cli_reviewer_a', 'First checked reviewer must auto-become kickoffBotAppId');

      const revBCheck = findElements(treeAfterRevA, el => el.props['data-reviewer-bot'] === 'cli_reviewer_b')[0]!;
      (revBCheck.props.onChange as (e: { target: { checked: boolean } }) => void)({
        target: { checked: true },
      });

      const treeAfterRevB = h1.render();
      const kickoffSelect = findElements(treeAfterRevB, el => el.props['data-field'] === 'kickoff-bot')[0]!;
      (kickoffSelect.props.onChange as (e: { target: { value: string } }) => void)({
        target: { value: 'cli_reviewer_b' },
      });

      const treeReadySave = h1.render();
      const saveRuleBtn = findElements(treeReadySave, el => el.props['data-action'] === 'save-rule')[0]!;
      (saveRuleBtn.props.onClick as () => void)();
      await new Promise(r => setTimeout(r, 50));
      await fsp.writeFile(configPath, JSON.stringify(storedCfg, null, 2), { mode: 0o600 });

      // Assert valid persisted config & preset defaults
      const savedConfig = storedCfg as {
        github: { mode: string };
        repos: Array<Record<string, unknown>>;
      };
      assert.equal(savedConfig.github.mode, 'gh_cli', 'Auto-detected gh login should persist default gh_cli mode');
      assert.equal(savedConfig.repos.length, 1);
      const createdRule = savedConfig.repos[0]!;
      assert.equal(createdRule.repo, 'deepcoldy/botmux');
      assert.equal(createdRule.enabled, true);
      assert.equal(createdRule.creatorBotAppId, 'cli_creator_online');
      assert.deepEqual(createdRule.memberBotAppIds, ['cli_reviewer_a', 'cli_reviewer_b']);
      assert.equal(createdRule.kickoffBotAppId, 'cli_reviewer_b');
      assert.equal(createdRule.groupNameTemplate, 'pr {{prNumber}} {{title}}');
      assert.deepEqual(createdRule.triggerOn, ['opened', 'ready_for_review']);
      assert.equal(createdRule.ignoreDrafts, true);
      assert.equal(createdRule.setTopNotice, true);
      assert.equal(createdRule.postShareLinkToPr, true);
      assert.equal(createdRule.onNewCommit, false);
      assert.equal(createdRule.onPrClosed, false);

      // Scenario 3 & 4: Pre-populate custom advanced rule + write-only secrets (PAT, proxy password, webhook secret)
      const patSecret = 'github_pat_SUPER_SECRET_NEVER_ECHO_99999';
      const proxySecret = 'proxy_secret_pass_88888';
      const webhookSecret = 'whsec_very_high_entropy_secret_value_0123456789ABCDEF';
      const seededRes = await settingsMod.saveSettings(
        { config: configApi },
        {
          action: 'saveConfig',
          patch: {
            github: { mode: 'pat', pat: patSecret },
            proxy: { url: 'http://proxy.example.com:8080', username: 'alice', password: proxySecret },
            webhook: { enabled: true, secret: webhookSecret, path: '/webhooks/github' },
            repos: [
              {
                repo: 'deepcoldy/botmux',
                enabled: true,
                creatorBotAppId: 'cli_creator_online',
                memberBotAppIds: ['cli_reviewer_a'],
                kickoffBotAppId: 'cli_reviewer_a',
                baseBranches: ['main', 'release'],
                authorDenylist: ['dependabot[bot]'],
                bindWorkingDir: '/srv/botmux',
                groupNameTemplate: 'pr {{prNumber}} {{title}}',
                setTopNotice: true,
                postShareLinkToPr: true,
              },
            ],
          },
        },
      );
      assert.equal(seededRes.ok, true);
      await fsp.writeFile(configPath, JSON.stringify(storedCfg, null, 2), { mode: 0o600 });

      const h2 = createHarness(dashMod.default, {
        getSettings: async () => {
          const base = await settingsMod.getSettings({ config: configApi });
          return { ...base, botStatus: botStatusFixture };
        },
        saveSettings: async (v: Record<string, unknown>) =>
          settingsMod.saveSettings({ config: configApi }, v),
        listBots: async () => botsFixture,
      });

      h2.render();
      await h2.flushEffects();
      const treeCustom = h2.render();

      // Verify PAT configured summary card (without echoing secret)
      const customText = JSON.stringify(treeCustom);
      assert.ok(customText.includes('已配置 Personal Access Token（PAT）鉴权'));
      assert.ok(!customText.includes(patSecret), 'PAT must NEVER appear in rendered Dashboard');
      assert.ok(!customText.includes(proxySecret), 'Proxy password must NEVER appear in rendered Dashboard');
      assert.ok(!customText.includes(webhookSecret), 'Webhook secret must NEVER appear in rendered Dashboard');

      // Click Edit on the customized rule -> verify "已自定义 3 项" badge while collapsed
      const editBtn = findElements(treeCustom, el => el.props['data-action'] === 'edit-rule-0')[0]!;
      (editBtn.props.onClick as () => void)();
      const treeEditCollapsed = h2.render();
      const customBadge = findElements(
        treeEditCollapsed,
        el => el.props['data-badge'] === 'rule-customized-count',
      )[0]!;
      assert.ok(customBadge, 'Editing rule with custom advanced options must show customized badge');
      assert.ok(JSON.stringify(customBadge).includes('已自定义 3 项'));

      // Expand rule advanced panel -> verify all 3 customized fields backfilled accurately
      const toggleRuleAdv = findElements(
        treeEditCollapsed,
        el => el.props['data-toggle'] === 'rule-advanced',
      )[0]!;
      (toggleRuleAdv.props.onClick as () => void)();
      const treeEditExpanded = h2.render();
      const baseBranchesInput = findElements(
        treeEditExpanded,
        el => el.props['data-field'] === 'base-branches',
      )[0]!;
      const authorDenyInput = findElements(
        treeEditExpanded,
        el => el.props['data-field'] === 'author-denylist',
      )[0]!;
      const bindDirInput = findElements(
        treeEditExpanded,
        el => el.props['data-field'] === 'bind-working-dir',
      )[0]!;
      assert.equal(baseBranchesInput.props.value, 'main, release');
      assert.equal(authorDenyInput.props.value, 'dependabot[bot]');
      assert.equal(bindDirInput.props.value, '/srv/botmux');

      // Expand auth switch & global advanced -> verify all secret inputs remain strictly blank (write-only!)
      const toggleAuth = findElements(treeEditExpanded, el => el.props['data-toggle'] === 'auth-switch')[0]!;
      (toggleAuth.props.onClick as () => void)();
      const toggleGlobal = findElements(
        treeEditExpanded,
        el => el.props['data-toggle'] === 'global-advanced',
      )[0]!;
      (toggleGlobal.props.onClick as () => void)();

      const treeAllOpen = h2.render();
      const allOpenText = JSON.stringify(treeAllOpen);
      assert.ok(!allOpenText.includes(patSecret), 'PAT must NEVER echo even when auth panel is open');
      assert.ok(!allOpenText.includes(proxySecret), 'Proxy password must NEVER echo when global panel is open');
      assert.ok(!allOpenText.includes(webhookSecret), 'Webhook secret must NEVER echo when global panel is open');

      const patField = findElements(treeAllOpen, el => el.props['data-field'] === 'pat')[0]!;
      const proxyPassField = findElements(treeAllOpen, el => el.props['data-field'] === 'proxy-password')[0]!;
      const whSecretField = findElements(treeAllOpen, el => el.props['data-field'] === 'webhook-secret')[0]!;
      assert.equal(patField.props.value, '');
      assert.equal(proxyPassField.props.value, '');
      assert.equal(whSecretField.props.value, '');
    } finally {
      if (prevPluginHome !== undefined) process.env.BOTMUX_PLUGIN_HOME = prevPluginHome;
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });
});
