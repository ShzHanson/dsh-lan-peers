// Resolve @deepseek-ai/dsh-tools whether the plugin declares it as a dependency
// or (for `link:` installs, where pnpm does not install the linked package's
// deps) from the running DSH installation.
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

export async function loadDshTools() {
  try {
    return await import('@deepseek-ai/dsh-tools');
  } catch {
    // fall through: the running DSH always carries it
  }
  // Candidates, in order: the running CLI's own package root, the Electron app's
  // asar root (process.resourcesPath/app.asar/dsh), then the cwd. The first one
  // that resolves wins; every lookup failure is swallowed.
  const roots = [];
  const bin = process.argv[1];
  if (bin) roots.push(join(dirname(bin), '..'));
  if (process.resourcesPath) roots.push(join(process.resourcesPath, 'app.asar', 'dsh'));
  roots.push(process.cwd());
  for (const root of roots) {
    try {
      const require = createRequire(join(root, 'package.json'));
      return require('@deepseek-ai/dsh-tools');
    } catch {}
  }
  throw new Error('cannot resolve @deepseek-ai/dsh-tools from: ' + roots.join(', '));
}
