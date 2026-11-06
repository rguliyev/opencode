import { describe, expect } from "bun:test"
import { LayerNode } from "@opencode-ai/core/effect/layer-node"
import { Effect } from "effect"
import { Auth } from "../../src/auth"
import { testEffect } from "../lib/effect"

const it = testEffect(LayerNode.compile(Auth.node))

describe("Auth", () => {
  it.instance("set normalizes trailing slashes in keys", () =>
    Effect.gen(function* () {
      const auth = yield* Auth.Service
      yield* auth.set("https://example.com/", {
        type: "wellknown",
        key: "TOKEN",
        token: "abc",
      })
      const data = yield* auth.all()
      expect(data["https://example.com"]).toBeDefined()
      expect(data["https://example.com/"]).toBeUndefined()
    }),
  )

  it.instance("set cleans up pre-existing trailing-slash entry", () =>
    Effect.gen(function* () {
      const auth = yield* Auth.Service
      yield* auth.set("https://example.com/", {
        type: "wellknown",
        key: "TOKEN",
        token: "old",
      })
      yield* auth.set("https://example.com", {
        type: "wellknown",
        key: "TOKEN",
        token: "new",
      })
      const data = yield* auth.all()
      const keys = Object.keys(data).filter((key) => key.includes("example.com"))
      expect(keys).toEqual(["https://example.com"])
      const entry = data["https://example.com"]!
      expect(entry.type).toBe("wellknown")
      if (entry.type === "wellknown") expect(entry.token).toBe("new")
    }),
  )

  it.instance("remove deletes both trailing-slash and normalized keys", () =>
    Effect.gen(function* () {
      const auth = yield* Auth.Service
      yield* auth.set("https://example.com", {
        type: "wellknown",
        key: "TOKEN",
        token: "abc",
      })
      yield* auth.remove("https://example.com/")
      const data = yield* auth.all()
      expect(data["https://example.com"]).toBeUndefined()
      expect(data["https://example.com/"]).toBeUndefined()
    }),
  )

  it.instance("set and remove are no-ops on keys without trailing slashes", () =>
    Effect.gen(function* () {
      const auth = yield* Auth.Service
      yield* auth.set("anthropic", {
        type: "api",
        key: "sk-test",
      })
      const data = yield* auth.all()
      expect(data["anthropic"]).toBeDefined()
      yield* auth.remove("anthropic")
      const after = yield* auth.all()
      expect(after["anthropic"]).toBeUndefined()
    }),
  )
})

describe("Auth refresh persistence", () => {
  it.instance("conditional rotation preserves newer login and logout", () =>
    Effect.gen(function* () {
      const auth = yield* Auth.Service
      const original = { type: "oauth" as const, access: "old", refresh: "old", expires: 1 }
      yield* auth.set("rotation-test", original)
      expect(yield* auth.set("rotation-test", { ...original, refresh: "new", refreshExpiresAt: 123456 }, "old")).toBe(
        true,
      )
      expect(yield* auth.set("rotation-test", { ...original, refresh: "stale" }, "old")).toBe(false)
      const current = yield* auth.get("rotation-test")
      expect(current?.type === "oauth" && current.refresh).toBe("new")
      expect(current?.type === "oauth" && current.refreshExpiresAt).toBe(123456)
      yield* auth.remove("rotation-test")
      expect(yield* auth.set("rotation-test", original, "new")).toBe(false)
      expect(yield* auth.get("rotation-test")).toBeUndefined()
    }),
  )

  it.instance("concurrent writers retain all providers", () =>
    Effect.gen(function* () {
      const auth = yield* Auth.Service
      yield* Effect.all(
        Array.from({ length: 12 }, (_, i) => auth.set(`concurrent-${i}`, { type: "api", key: `fake-${i}` })),
        { concurrency: "unbounded" },
      )
      const all = yield* auth.all()
      for (let i = 0; i < 12; i++) expect(all[`concurrent-${i}`]).toEqual({ type: "api", key: `fake-${i}` })
    }),
  )

  it.instance("malformed auth storage fails closed without overwriting it", () =>
    Effect.gen(function* () {
      const { Global } = yield* Effect.promise(() => import("@opencode-ai/core/global"))
      const file = `${Global.Path.data}/auth.json`
      const auth = yield* Auth.Service
      const previous = yield* Effect.promise(() => Bun.file(file).text())
      yield* Effect.promise(() => Bun.write(file, "{broken"))
      yield* Effect.gen(function* () {
        expect(yield* auth.set("unwanted", { type: "api", key: "fake" }).pipe(Effect.isFailure)).toBe(true)
        expect(yield* Effect.promise(() => Bun.file(file).text())).toBe("{broken")
      }).pipe(Effect.ensuring(Effect.promise(() => Bun.write(file, previous))))
    }),
  )
})
