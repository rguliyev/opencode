import path from "node:path"
import { freshAnthropicAuth } from "../../../../contrib/subscription-fallback/anthropic-refresh"
const [file, url, failure] = process.argv.slice(2)
const original = fetch
try {
  const result = await freshAnthropicAuth({
    lockDir: path.join(path.dirname(file), "locks"),
    getAuth: () => Bun.file(file).json(),
    save: async (value) => {
      if (failure === "save-fail") throw new Error("mock save failure")
      await Bun.write(file, JSON.stringify(value))
      return true
    },
    log: async () => {},
    notify: async () => {},
    transport: Object.assign(
      async (_input: unknown, init?: RequestInit) => {
        const response = await original(url, init)
        if (failure === "lost") {
          await response.text()
          throw new Error("mock lost response")
        }
        return response
      },
      {
        preconnect: original.preconnect,
      },
    ) as typeof fetch,
  })
  if (result.type !== "oauth" || result.access !== "new") process.exit(1)
  console.log("ok")
} catch (error) {
  if (!failure) throw error
  console.log("blocked")
}
