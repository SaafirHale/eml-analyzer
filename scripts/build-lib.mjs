// Library build: tsc emits ESM + .d.ts into dist/, then the stylesheet is copied beside the
// React entry. tsc keeps the "use client" directive at the top of the React files.

import { spawnSync } from "node:child_process";
import { copyFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
rmSync(join(root, "dist"), { recursive: true, force: true });

const tsc = spawnSync(process.execPath, [join(root, "node_modules/typescript/bin/tsc"), "-p", join(root, "tsconfig.build.json")], {
  stdio: "inherit",
});
if (tsc.status !== 0) process.exit(tsc.status ?? 1);

copyFileSync(join(root, "src/react/styles.css"), join(root, "dist/react/styles.css"));
console.log("dist/ built");
