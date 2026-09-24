import { LayerNode } from "@opencode-ai/core/effect/layer-node"
import { ConfigPermissionV1 } from "@opencode-ai/core/v1/config/permission"
import { InstanceState } from "@/effect/instance-state"
import { Wildcard } from "@opencode-ai/core/util/wildcard"
import { Cause, Context, Deferred, Effect, Layer, Schedule } from "effect"
import os from "os"
import { PermissionV1 } from "@opencode-ai/core/v1/permission"
import { EventV2Bridge } from "@/event-v2-bridge"

export const Event = PermissionV1.Event

// A reviewer sees the effective rule decision and may replace it. This is the
// interception point the `permission.ask` plugin hook needs — without it the hook
// is declared in @opencode-ai/plugin but never invoked.
export type PermissionReviewer = (
  input: PermissionV1.Request,
  // `status` is whatever the hook left behind, so it is typed as an unvalidated
  // string rather than the union: plugins are external, untyped JavaScript, and
  // an unrecognised value must not be able to read as a decision.
  output: {
    status: string
    message?: string
    reviewItems?: { index: number; digest: string; command: string | null; reason: string }[]
  },
) => Effect.Effect<void>

/** deny beats ask beats allow; anything else is not a decision at all. */
const strictness = (status: string) => (status === "deny" ? 2 : status === "ask" ? 1 : status === "allow" ? 0 : -1)

/**
 * How often an unanswered request is re-announced. The event stream replays
 * nothing on connect, so a single publish is lost to any client that is not
 * attached at that instant — a reconnect gap is enough to strand a tool call.
 */
const reannounceInterval = "10 seconds"

export interface Interface {
  readonly ask: (input: PermissionV1.AskInput) => Effect.Effect<void, PermissionV1.Error>
  readonly reply: (input: PermissionV1.ReplyInput) => Effect.Effect<void, PermissionV1.NotFoundError>
  readonly list: () => Effect.Effect<ReadonlyArray<PermissionV1.Request>>
  readonly setReviewer: (fn: PermissionReviewer) => Effect.Effect<void>
}

interface PendingEntry {
  info: PermissionV1.Request
  deferred: Deferred.Deferred<void, PermissionV1.RejectedError | PermissionV1.CorrectedError>
}

interface State {
  pending: Map<PermissionV1.ID, PendingEntry>
  approved: PermissionV1.Rule[]
}

export function evaluate(permission: string, pattern: string, ...rulesets: PermissionV1.Ruleset[]): PermissionV1.Rule {
  return (
    rulesets
      .flat()
      .findLast((rule) => Wildcard.match(permission, rule.permission) && Wildcard.match(pattern, rule.pattern)) ?? {
      action: "ask",
      permission,
      pattern: "*",
    }
  )
}

export class Service extends Context.Service<Service, Interface>()("@opencode/Permission") {}

const layer = Layer.effect(
  Service,
  Effect.gen(function* () {
    const events = yield* EventV2Bridge.Service
    let reviewer: PermissionReviewer | undefined // registered once by the plugin layer
    const state = yield* InstanceState.make<State>(
      Effect.fn("Permission.state")(function* (ctx) {
        void ctx
        const state = {
          pending: new Map<PermissionV1.ID, PendingEntry>(),
          approved: [],
        }

        yield* Effect.addFinalizer(() =>
          Effect.gen(function* () {
            for (const item of state.pending.values()) {
              yield* Deferred.fail(item.deferred, new PermissionV1.RejectedError())
            }
            state.pending.clear()
          }),
        )

        return state
      }),
    )

    const ask = Effect.fn("Permission.ask")(function* (input: PermissionV1.AskInput) {
      const { approved, pending } = yield* InstanceState.get(state)
      const { ruleset, ...request } = input
      let needsAsk = false

      for (const pattern of request.patterns) {
        const configured = evaluate(request.permission, pattern, ruleset)
        if (configured.action === "deny") {
          yield* Effect.logInfo("evaluated", { permission: request.permission, pattern, action: configured })
          return yield* new PermissionV1.DeniedError({
            ruleset: ruleset.filter((rule) => Wildcard.match(request.permission, rule.permission)),
          })
        }
        const rule = evaluate(request.permission, pattern, ruleset, approved)
        yield* Effect.logInfo("evaluated", { permission: request.permission, pattern, action: rule })
        if (rule.action === "deny") {
          return yield* new PermissionV1.DeniedError({
            ruleset: ruleset.filter((rule) => Wildcard.match(request.permission, rule.permission)),
          })
        }
        if (rule.action === "allow") continue
        needsAsk = true
      }

      const id = request.id ?? PermissionV1.ID.ascending()
      // The reviewer may replace the effective decision. It sees the id the real
      // request will carry and copies of mutable fields, not the original request.
      const review: {
        status: string
        message?: string
        reviewItems?: { index: number; digest: string; command: string | null; reason: string }[]
      } = { status: needsAsk ? "ask" : "allow" }
      if (reviewer) {
        const before = review.status
        yield* reviewer(
          {
            id,
            sessionID: request.sessionID,
            permission: request.permission,
            patterns: [...request.patterns],
            metadata: { ...request.metadata },
            always: [...request.always],
            tool: request.tool,
          },
          review,
        ).pipe(
          // A hook that throws must not take the permission check down with it:
          // `trigger` runs hooks through Effect.promise, so a rejection arrives as a
          // defect. Treat it like a hook that answered nonsense — keep the rules'
          // decision, discarding whatever the hook wrote before it failed.
          Effect.catchCause((cause) =>
            Cause.hasInterrupts(cause)
              ? Effect.failCause(cause)
              : Effect.gen(function* () {
                  // Every hook shares one `review`, so a failure can follow a decision an
                  // earlier hook already made. Discard what the failing hook left behind
                  // only when keeping it would be more permissive than the rules were.
                  if (strictness(review.status) <= strictness(before)) {
                    review.status = before
                    review.message = undefined
                  }
                  // A failed hook cannot provide trustworthy command identities.
                  review.reviewItems = undefined
                  yield* Effect.logWarning("permission.ask hook failed; keeping the safer decision", {
                    cause: Cause.pretty(cause),
                    permission: request.permission,
                  })
                }),
          ),
        )
        if (review.status === "deny") {
          // No rule matched: inventing one here would send the user looking
          // through their config for something that is not there. The reason
          // carries the explanation instead.
          return yield* new PermissionV1.DeniedError({
            ruleset: [],
            reason: review.message ?? "A plugin denied this permission request.",
          })
        }
        // An unknown status is not a decision; retain the configured result.
        if (review.status === "ask" || review.status === "allow") needsAsk = review.status === "ask"
        else {
          review.message = undefined
          review.reviewItems = undefined
          yield* Effect.logWarning("permission.ask hook returned an unknown status; keeping the rule decision", {
            status: review.status,
            permission: request.permission,
          })
        }
      }

      if (!needsAsk) return

      const metadata = { ...request.metadata }
      delete metadata.reviewReason
      delete metadata.reviewItems
      if (typeof review.message === "string") metadata.reviewReason = review.message.slice(0, 2_000)
      if (review.status === "ask" && review.reviewItems) metadata.reviewItems = review.reviewItems
      const info: PermissionV1.Request = {
        id,
        sessionID: request.sessionID,
        permission: request.permission,
        patterns: request.patterns,
        // Review details come from the permission hook, not tool-supplied metadata.
        metadata,
        always: request.always,
        tool: request.tool,
      }
      yield* Effect.logInfo("asking", { id, permission: info.permission, patterns: info.patterns })

      const deferred = yield* Deferred.make<void, PermissionV1.RejectedError | PermissionV1.CorrectedError>()
      pending.set(id, { info, deferred })
      yield* events.publish(Event.Asked, info)
      return yield* Effect.scoped(
        Effect.gen(function* () {
          // Consumers key on request id and reconcile in place, so repeats update
          // the existing prompt instead of stacking duplicates. The fiber dies with
          // the scope as soon as the request is answered, rejected, or interrupted.
          yield* Effect.forkScoped(
            Effect.gen(function* () {
              yield* Effect.sleep(reannounceInterval)
              yield* events.publish(Event.Asked, info).pipe(Effect.repeat(Schedule.spaced(reannounceInterval)))
            }),
          )
          return yield* Effect.ensuring(
            Deferred.await(deferred),
            Effect.sync(() => {
              pending.delete(id)
            }),
          )
        }),
      )
    })

    const reply = Effect.fn("Permission.reply")(function* (input: PermissionV1.ReplyInput) {
      const { approved, pending } = yield* InstanceState.get(state)
      const existing = pending.get(input.requestID)
      if (!existing) return yield* new PermissionV1.NotFoundError({ requestID: input.requestID })

      const expected = Array.isArray(existing.info.metadata.reviewItems)
        ? existing.info.metadata.reviewItems.filter(
            (item: unknown): item is { index: number; digest: string } =>
              !!item &&
              typeof item === "object" &&
              "index" in item &&
              "digest" in item &&
              typeof item.index === "number" &&
              Number.isInteger(item.index) &&
              typeof item.digest === "string" &&
              /^[a-f0-9]{64}$/.test(item.digest),
          )
        : []
      const submitted = input.commandFeedback
      const feedback = submitted?.filter(
        (item, index) =>
          Number.isInteger(item.index) &&
          /^[a-f0-9]{64}$/.test(item.digest) &&
          submitted.findIndex((other) => other.index === item.index) === index &&
          expected.some((candidate) => candidate.index === item.index && candidate.digest === item.digest),
      )
      const valid = !submitted || feedback?.length === submitted.length
      const complete = !submitted || (valid && expected.length === feedback?.length)
      const reply =
        submitted && (feedback?.some((item) => item.decision === "reject") || (!complete && input.reply !== "reject"))
          ? "reject"
          : input.reply

      pending.delete(input.requestID)
      yield* events.publish(Event.Replied, {
        sessionID: existing.info.sessionID,
        requestID: existing.info.id,
        reply,
        origin: input.origin ?? "unknown",
        direct: true,
        commandFeedback: valid ? feedback : undefined,
      })

      if (reply === "reject") {
        yield* Deferred.fail(
          existing.deferred,
          input.message
            ? new PermissionV1.CorrectedError({ feedback: input.message })
            : new PermissionV1.RejectedError(),
        )

        for (const [id, item] of pending.entries()) {
          if (item.info.sessionID !== existing.info.sessionID) continue
          pending.delete(id)
          yield* events.publish(Event.Replied, {
            sessionID: item.info.sessionID,
            requestID: item.info.id,
            reply: "reject",
            origin: "cascade",
            direct: false,
          })
          yield* Deferred.fail(item.deferred, new PermissionV1.RejectedError())
        }
        return
      }

      yield* Deferred.succeed(existing.deferred, undefined)
      if (reply === "once") return

      for (const pattern of existing.info.always) {
        approved.push({
          permission: existing.info.permission,
          pattern,
          action: "allow",
        })
      }

      for (const [id, item] of pending.entries()) {
        if (item.info.sessionID !== existing.info.sessionID) continue
        const ok = item.info.patterns.every(
          (pattern) => evaluate(item.info.permission, pattern, approved).action === "allow",
        )
        if (!ok) continue
        pending.delete(id)
        yield* events.publish(Event.Replied, {
          sessionID: item.info.sessionID,
          requestID: item.info.id,
          reply: "always",
          origin: "cascade",
          direct: false,
        })
        yield* Deferred.succeed(item.deferred, undefined)
      }
    })

    const list = Effect.fn("Permission.list")(function* () {
      const pending = (yield* InstanceState.get(state)).pending
      return Array.from(pending.values(), (item) => item.info)
    })

    const setReviewer = (fn: PermissionReviewer) =>
      Effect.sync(() => {
        reviewer = fn
      })
    return Service.of({ ask, reply, list, setReviewer })
  }),
)

function expand(pattern: string): string {
  if (pattern.startsWith("~/")) return os.homedir() + pattern.slice(1)
  if (pattern === "~") return os.homedir()
  if (pattern.startsWith("$HOME/")) return os.homedir() + pattern.slice(5)
  if (pattern.startsWith("$HOME")) return os.homedir() + pattern.slice(5)
  return pattern
}

export function fromConfig(permission: ConfigPermissionV1.Info) {
  const ruleset: PermissionV1.Rule[] = []
  for (const [key, value] of Object.entries(permission)) {
    if (typeof value === "string") {
      ruleset.push({ permission: key, action: value, pattern: "*" })
      continue
    }
    ruleset.push(
      ...Object.entries(value).map(([pattern, action]) => ({ permission: key, pattern: expand(pattern), action })),
    )
  }
  return ruleset
}

export function merge(...rulesets: PermissionV1.Ruleset[]): PermissionV1.Rule[] {
  return rulesets.flat()
}

export function disabled(tools: string[], ruleset: PermissionV1.Ruleset): Set<string> {
  const edits = ["edit", "write", "apply_patch"]
  const reads = ["list_mcp_resources", "list_mcp_resource_templates", "read_mcp_resource"]
  return new Set(
    tools.filter((tool) => {
      const permission = edits.includes(tool) ? "edit" : reads.includes(tool) ? "read" : tool
      const rule = ruleset.findLast((rule) => Wildcard.match(permission, rule.permission))
      return rule?.pattern === "*" && rule.action === "deny"
    }),
  )
}

export function visibleTools<T>(tools: Record<string, T>, ruleset: PermissionV1.Ruleset): Record<string, T> {
  const hidden = disabled(Object.keys(tools), ruleset)
  return Object.fromEntries(Object.entries(tools).filter(([name]) => !hidden.has(name)))
}

export const node = LayerNode.make({ service: Service, layer: layer, deps: [EventV2Bridge.node] })

export * as Permission from "."
