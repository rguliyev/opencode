import path from "node:path"

const root = path.resolve(import.meta.dir, "../..")
const anthropic = process.env.ANTHROPIC_PLUGIN_DIR
const outdir = process.env.PLUGIN_OUTDIR
if (!anthropic || !outdir || !path.isAbsolute(anthropic) || !path.isAbsolute(outdir))
  throw new Error("Set absolute ANTHROPIC_PLUGIN_DIR and PLUGIN_OUTDIR paths; this script never installs packages")
const pkg = await Bun.file(path.join(anthropic, "package.json")).json()
if (pkg.name !== "@ex-machina/opencode-anthropic-auth" || pkg.version !== "1.8.6")
  throw new Error("Expected existing @ex-machina/opencode-anthropic-auth@1.8.6")
const source = Bun.spawnSync(["git", "rev-parse", "HEAD"], { cwd: root })
if (source.exitCode !== 0) throw new Error("Cannot identify plugin source")
const sha = source.stdout.toString().trim()
const version = `${(await Bun.file(path.join(root, "packages/opencode/package.json")).json()).version}-${sha.slice(0, 10)}`

const result = await Bun.build({
  entrypoints: [path.join(import.meta.dir, "openai.ts"), path.join(import.meta.dir, "anthropic.ts")],
  outdir,
  target: "bun",
  format: "esm",
  tsconfig: path.join(root, "packages/opencode/tsconfig.json"),
  minify: false,
  define: { OPENCODE_VERSION: JSON.stringify(version), OPENCODE_CHANNEL: JSON.stringify("dev") },
  plugins: [
    {
      name: "existing-anthropic-auth",
      setup(build) {
        build.onResolve({ filter: /^@ex-machina\/opencode-anthropic-auth$/ }, () => ({
          path: path.join(anthropic, "dist/index.js"),
        }))
      },
    },
  ],
})
if (!result.success) throw new AggregateError(result.logs, "Plugin build failed")
for (const output of result.outputs) console.log(`${output.path}: ${output.size} bytes`)
await Bun.write(
  path.join(outdir, "manifest.json"),
  JSON.stringify(
    {
      source: sha,
      version,
      anthropic: `${pkg.name}@${pkg.version}`,
      artifacts: await Promise.all(
        result.outputs.map(async (file) => ({
          name: path.basename(file.path),
          sha256: new Bun.CryptoHasher("sha256").update(await file.arrayBuffer()).digest("hex"),
        })),
      ),
    },
    null,
    2,
  ) + "\n",
)
