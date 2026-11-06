import { LayerNode } from "@opencode-ai/core/effect/layer-node"
import path from "path"
import { randomUUID } from "node:crypto"
import { Flock } from "@opencode-ai/core/util/flock"
import { Effect, Layer, Record, Result, Schema, Context } from "effect"
import { NonNegativeInt } from "@opencode-ai/core/schema"
import { Global } from "@opencode-ai/core/global"
import { FSUtil } from "@opencode-ai/core/fs-util"

export const OAUTH_DUMMY_KEY = "opencode-oauth-dummy-key"

const file = path.join(Global.Path.data, "auth.json")

const fail = (message: string) => (cause: unknown) => new AuthError({ message, cause })

export class Oauth extends Schema.Class<Oauth>("OAuth")({
  type: Schema.Literal("oauth"),
  refresh: Schema.String,
  access: Schema.String,
  expires: NonNegativeInt,
  refreshExpiresAt: Schema.optional(NonNegativeInt),
  accountId: Schema.optional(Schema.String),
  enterpriseUrl: Schema.optional(Schema.String),
}) {}

export class Api extends Schema.Class<Api>("ApiAuth")({
  type: Schema.Literal("api"),
  key: Schema.String,
  metadata: Schema.optional(Schema.Record(Schema.String, Schema.String)),
}) {}

export class WellKnown extends Schema.Class<WellKnown>("WellKnownAuth")({
  type: Schema.Literal("wellknown"),
  key: Schema.String,
  token: Schema.String,
}) {}

export const Info = Schema.Union([Oauth, Api, WellKnown]).annotate({ discriminator: "type", identifier: "Auth" })
export type Info = Schema.Schema.Type<typeof Info>

// Optional compare-and-set guard for rotated tokens; never stored in auth.json.
export const Update = Schema.Union([
  Schema.Struct({ ...Oauth.fields, expectedRefresh: Schema.optional(Schema.String) }).annotate({ identifier: "OAuth" }),
  Api,
  WellKnown,
]).annotate({ discriminator: "type", identifier: "Auth" })

export class AuthError extends Schema.TaggedErrorClass<AuthError>()("AuthError", {
  message: Schema.String,
  cause: Schema.optional(Schema.Defect()),
}) {}

export interface Interface {
  readonly get: (providerID: string) => Effect.Effect<Info | undefined, AuthError>
  readonly all: () => Effect.Effect<Record<string, Info>, AuthError>
  readonly set: (key: string, info: Info, expectedRefresh?: string) => Effect.Effect<boolean, AuthError>
  readonly remove: (key: string) => Effect.Effect<void, AuthError>
}

export class Service extends Context.Service<Service, Interface>()("@opencode/Auth") {}

const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const fsys = yield* FSUtil.Service
    const decode = Schema.decodeUnknownOption(Info)

    const read = fsys.readJson(file).pipe(
      Effect.catchReason("PlatformError", "NotFound", () => Effect.succeed({})),
      Effect.flatMap((data) =>
        data && typeof data === "object" && !Array.isArray(data)
          ? Effect.succeed(data as Record<string, unknown>)
          : Effect.fail(new AuthError({ message: "Invalid auth data; refusing to overwrite" })),
      ),
      Effect.mapError(() => new AuthError({ message: "Failed to read auth data; refusing to overwrite" })),
    )

    const write = Effect.fn("Auth.write")(function* (data: Record<string, unknown>) {
      const temp = `${file}.${randomUUID()}.tmp`
      yield* fsys
        .writeFileString(temp, JSON.stringify(data, null, 2), { mode: 0o600, flag: "wx" })
        .pipe(
          Effect.andThen(fsys.rename(temp, file)),
          Effect.ensuring(fsys.remove(temp, { force: true }).pipe(Effect.ignore)),
          Effect.mapError(fail("Failed to write auth data")),
        )
    })

    const all = Effect.fn("Auth.all")(function* () {
      if (process.env.OPENCODE_AUTH_CONTENT) {
        try {
          return JSON.parse(process.env.OPENCODE_AUTH_CONTENT)
        } catch (err) {}
      }

      const data = yield* read
      return Record.filterMap(data, (value) => Result.fromOption(decode(value), () => undefined))
    })

    const get = Effect.fn("Auth.get")(function* (providerID: string) {
      return (yield* all())[providerID]
    })

    const set = Effect.fn("Auth.set")(function* (key: string, info: Info, expectedRefresh?: string) {
      return yield* Effect.scoped(
        Effect.gen(function* () {
          yield* Flock.effect(`auth-store:${file}`)
          const norm = key.replace(/\/+$/, "")
          const data = yield* read
          if (expectedRefresh !== undefined) {
            const current = data[norm] as Info | undefined
            if (current?.type !== "oauth" || current.refresh !== expectedRefresh) return false
          }
          if (norm !== key) delete data[key]
          delete data[norm + "/"]
          yield* write({ ...data, [norm]: info })
          return true
        }),
      )
    })

    const remove = Effect.fn("Auth.remove")(function* (key: string) {
      yield* Effect.scoped(
        Effect.gen(function* () {
          yield* Flock.effect(`auth-store:${file}`)
          const norm = key.replace(/\/+$/, "")
          const data = yield* read
          delete data[key]
          delete data[norm]
          yield* write(data)
        }),
      )
    })

    return Service.of({ get, all, set, remove })
  }),
)

export const node = LayerNode.make({ service: Service, layer: layer, deps: [FSUtil.node] })

export * as Auth from "."
