import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promises as fsp } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const rootDir = resolve(import.meta.dirname, '..', '..');

function runCmd(
  bin: string,
  args: string[],
  opts: { cwd: string; env?: NodeJS.ProcessEnv; timeoutMs?: number },
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  return new Promise(resolvePromise => {
    execFile(
      bin,
      args,
      {
        cwd: opts.cwd,
        env: opts.env ?? process.env,
        timeout: opts.timeoutMs ?? 60_000,
        maxBuffer: 4 * 1024 * 1024,
      },
      (err, stdout, stderr) => {
        const exitCode =
          err && typeof (err as { code?: unknown }).code === 'number'
            ? (err as { code: number }).code
            : err
              ? 1
              : 0;
        resolvePromise({
          exitCode,
          stdout: String(stdout ?? ''),
          stderr: String(stderr ?? ''),
        });
      },
    );
  });
}

describe('Tarball packaging, zero-node_modules self-containment, and Node + Bun runtime compatibility', () => {
  it('packs via npm pack, installs with --ignore-scripts into a clean temp dir, and runs standalone dist/ under both Node and Bun', async () => {
    const tmp = await fsp.mkdtemp(join(tmpdir(), 'botmux-gh-pack-test-'));
    try {
      const packRes = await runCmd('npm', ['pack', '--pack-destination', tmp, '--json'], {
        cwd: rootDir,
      });
      assert.equal(packRes.exitCode, 0, `npm pack failed: ${packRes.stderr}`);
      const packInfo = JSON.parse(packRes.stdout) as Array<{ filename: string }>;
      const tgzName = packInfo[0]?.filename;
      assert.ok(tgzName, 'npm pack must emit a tarball filename');
      const tgzPath = join(tmp, tgzName);

      // Verify tarball archive contains package/package.json and complete package/dist/ layout
      const tarList = await runCmd('tar', ['-tzf', tgzPath], { cwd: tmp });
      assert.equal(tarList.exitCode, 0, `tar -tzf failed: ${tarList.stderr}`);
      const tarEntries = tarList.stdout.split(/\r?\n/).filter(Boolean);
      for (const expectedEntry of [
        'package/package.json',
        'package/dist/package.json',
        'package/dist/dashboard/index.js',
        'package/dist/server/settings.js',
        'package/dist/service/index.js',
        'package/dist/service/runner.js',
        'package/dist/cli/index.js',
        'package/dist/cli/commands.json',
        'package/dist/webhooks/index.json',
      ]) {
        assert.ok(
          tarEntries.includes(expectedEntry),
          `Packed tarball must contain ${expectedEntry}`,
        );
      }

      // Verify Node crypto SRI sha512 matches Botmux core GitHub Release integrity contract
      const tgzBytes = await fsp.readFile(tgzPath);
      const sri = `sha512-${createHash('sha512').update(tgzBytes).digest('base64')}`;
      assert.match(sri, /^sha512-[A-Za-z0-9+/]{86}==$/);

      // Install tarball cleanly with --ignore-scripts and --omit=dev
      const installDir = join(tmp, 'install-target');
      await fsp.mkdir(installDir, { recursive: true });
      await fsp.writeFile(
        join(installDir, 'package.json'),
        JSON.stringify({ name: 'tarball-consumer', private: true, version: '1.0.0' }),
      );

      const instRes = await runCmd(
        'npm',
        ['install', '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund', tgzPath],
        { cwd: installDir },
      );
      assert.equal(instRes.exitCode, 0, `npm install tarball failed: ${instRes.stderr}`);

      // Copy ONLY dist/ to an isolated directory (exact simulation of Botmux ~/.botmux/plugins/github/dist/)
      const installedPkgDir = join(installDir, 'node_modules', '@botmux-ai', 'plugin-github');
      const isolatedDist = join(tmp, 'isolated-dist');
      await fsp.cp(join(installedPkgDir, 'dist'), isolatedDist, { recursive: true });

      // Verify zero transitive dependencies were installed in install-target/node_modules
      const topPkgs = await fsp.readdir(join(installDir, 'node_modules'));
      assert.deepEqual(
        topPkgs.filter(p => !p.startsWith('.')),
        ['@botmux-ai'],
        'Installed tarball must pull ZERO runtime dependencies',
      );

      // Verify standalone dist imports and runs under Node 22+
      const svcMod = await import(pathToFileURL(join(isolatedDist, 'service', 'index.js')).href);
      assert.equal(svcMod.default().mode, 'auto');

      const settingsMod = await import(
        pathToFileURL(join(isolatedDist, 'server', 'settings.js')).href
      );
      assert.equal(typeof settingsMod.getSettings, 'function');
      assert.equal(typeof settingsMod.saveSettings, 'function');

      const cliMod = await import(pathToFileURL(join(isolatedDist, 'cli', 'index.js')).href);
      const statusOut = await cliMod.default['github:status'].run(
        { args: ['--json'], api: { config: { path: join(tmp, 'fake-home', 'config.json') } } },
        { config: { path: join(tmp, 'fake-home', 'config.json') } },
      );
      assert.equal(JSON.parse(String(statusOut)).mode, 'dormant');

      // Verify standalone dist ALSO imports & executes cleanly under Bun (when bun is installed)
      const bunCheck = await runCmd('bun', ['--version'], { cwd: tmp });
      if (bunCheck.exitCode === 0) {
        const bunProbe = await runCmd(
          'bun',
          [
            '-e',
            [
              `const svc = (await import(${JSON.stringify(join(isolatedDist, 'service', 'index.js'))})).default();`,
              `const settings = await import(${JSON.stringify(join(isolatedDist, 'server', 'settings.js'))});`,
              `const cli = (await import(${JSON.stringify(join(isolatedDist, 'cli', 'index.js'))})).default;`,
              `const st = JSON.parse(await cli['github:status'].run({ args: ['--json'] }, { config: { path: ${JSON.stringify(join(tmp, 'bun-home', 'config.json'))} } }));`,
              `if (svc.mode !== 'auto' || typeof settings.getSettings !== 'function' || st.mode !== 'dormant') process.exit(2);`,
              `console.log('BUN_OK');`,
            ].join(' '),
          ],
          { cwd: tmp },
        );
        assert.equal(bunProbe.exitCode, 0, `Bun runtime check failed: ${bunProbe.stderr}`);
        assert.ok(bunProbe.stdout.includes('BUN_OK'));
      }
    } finally {
      await fsp.rm(tmp, { recursive: true, force: true });
    }
  });

  it('defines dual-channel publish.yml (independent release-github and publish-npm jobs with npm@^11.5.1 and SRI .sha512)', async () => {
    const workflowPath = join(rootDir, '.github', 'workflows', 'publish.yml');
    const yml = await fsp.readFile(workflowPath, 'utf8');

    // Trigger strictly on v* tags
    assert.match(yml, /tags:\s*\n\s*-\s*['"]v\*['"]/);

    // Split into two independent top-level jobs
    const releaseStart = yml.indexOf('\n  release-github:');
    const npmStart = yml.indexOf('\n  publish-npm:');
    assert.ok(releaseStart > 0, 'publish.yml must define release-github job');
    assert.ok(npmStart > 0, 'publish.yml must define publish-npm job');
    assert.ok(releaseStart < npmStart);

    const releaseSection = yml.slice(releaseStart, npmStart);
    const npmSection = yml.slice(npmStart);

    // Neither job may block the other via needs:
    assert.ok(!/^\s+needs:/m.test(releaseSection), 'release-github must not depend on publish-npm');
    assert.ok(!/^\s+needs:/m.test(npmSection), 'publish-npm must not depend on release-github');

    // release-github invariants
    assert.match(releaseSection, /permissions:\s*\n\s+contents:\s*write/);
    assert.ok(releaseSection.includes('git merge-base --is-ancestor "${GITHUB_SHA}" origin/main'));
    assert.ok(releaseSection.includes("require('./package.json').version"));
    assert.ok(releaseSection.includes('npm ci --no-audit --no-fund'));
    assert.ok(releaseSection.includes('npm test'));
    assert.ok(releaseSection.includes('npm pack'));
    assert.ok(releaseSection.includes('package/package.json'));
    assert.ok(releaseSection.includes('package/dist/'));
    assert.ok(releaseSection.includes('createHash("sha512")'));
    assert.ok(releaseSection.includes('.sha512'));
    assert.ok(releaseSection.includes('gh release create "${GITHUB_REF_NAME}"'));
    assert.ok(releaseSection.includes('gh release upload "${GITHUB_REF_NAME}"'));
    assert.ok(releaseSection.includes('--generate-notes'));

    // publish-npm invariants (OIDC Trusted Publishing + npm@^11.5.1 upgrade)
    assert.match(npmSection, /permissions:\s*\n\s+contents:\s*read\s*\n\s+id-token:\s*write/);
    assert.ok(npmSection.includes('git merge-base --is-ancestor "${GITHUB_SHA}" origin/main'));
    assert.ok(npmSection.includes("require('./package.json').version"));
    assert.ok(npmSection.includes('npm install -g npm@^11.5.1'));
    assert.ok(npmSection.includes('npm ci --no-audit --no-fund'));
    assert.ok(npmSection.includes('npm test'));
    assert.ok(npmSection.includes('npm publish --access public --provenance'));
  });
});
