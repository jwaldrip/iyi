/**
 * Action entry point. The bundle's main is dist/index.js, built from this file.
 *
 * The entry is unconditional. Running a module-level guard such as
 * `import.meta.url === file://argv[1]` is unreliable across symlinked paths:
 * when the guard is false the action exits 0 without doing anything.
 */

import { runAction } from './index.js';

runAction().catch((err) => {
  console.error(`Strict supervisor fatal error: ${err && err.message ? err.message : err}`);
  process.exitCode = 1;
});
