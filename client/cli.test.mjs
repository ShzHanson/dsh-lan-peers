// dsh-lan-peers · CLI surface tests (help is part of the contract).
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), 'cli.mjs');

function run(args) {
  return execFileSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
}

test('root --help lists every subcommand', () => {
  const out = run(['--help']);
  for (const command of ['code', 'pair', 'peers', 'ask', 'events', 'help']) {
    assert.match(out, new RegExp('\\b' + command + '\\b'));
  }
  assert.match(out, /--state-dir/);
});

test('pair --help documents the two-round flow and the forced legacy switch', () => {
  const out = run(['pair', '--help']);
  assert.match(out, /--url/);
  assert.match(out, /--code/);
  assert.match(out, /--legacy-pair/);
  assert.match(out, /--ecdh-pair/);
  assert.match(out, /confirm/);
});

test('events --help documents the subscription options', () => {
  const out = run(['events', '--help']);
  assert.match(out, /--peer/);
  assert.match(out, /--session/);
  assert.match(out, /--duration/);
  assert.match(out, /events/);
});

test('an unknown subcommand fails with usage on stderr', () => {
  assert.throws(
    () => execFileSync(process.execPath, [CLI, 'nope'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }),
    (error) => error.status === 1 && /未知子命令/.test(String(error.stderr)),
  );
});

test('events without --session fails with usage instead of hanging', () => {
  assert.throws(
    () => execFileSync(process.execPath, [CLI, 'events', '--peer', 'x'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }),
    (error) => error.status === 1 && /--session/.test(String(error.message) + String(error.stderr)),
  );
});
