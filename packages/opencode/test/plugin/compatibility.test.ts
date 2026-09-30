import { expect, test } from "bun:test"
import { checkPluginCompatibility } from "../../src/plugin/shared"

const plugin = { dir: "/plugin", pkg: "/plugin/package.json", json: { engines: { opencode: ">=1.17.15 <2" } } }

test("fork prerelease builds satisfy a plugin's release range", async () => {
  await expect(checkPluginCompatibility("/plugin", "1.18.33-cb75cd45a8", plugin)).resolves.toBeUndefined()
  await expect(checkPluginCompatibility("/plugin", "1.18.33", plugin)).resolves.toBeUndefined()
})

test("builds outside the range are still rejected", async () => {
  await expect(checkPluginCompatibility("/plugin", "2.0.0-cb75cd45a8", plugin)).rejects.toThrow(
    "Plugin requires opencode >=1.17.15 <2",
  )
  await expect(checkPluginCompatibility("/plugin", "1.16.0", plugin)).rejects.toThrow("Plugin requires opencode")
})
