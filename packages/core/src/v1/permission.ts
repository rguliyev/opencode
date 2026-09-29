export * as PermissionV1 from "./permission"

import { Schema } from "effect"
export * from "@opencode-ai/schema/permission-v1"
import { ID } from "@opencode-ai/schema/permission-v1"

export class RejectedError extends Schema.TaggedErrorClass<RejectedError>()("PermissionRejectedError", {}) {
  override get message() {
    return "The user rejected permission to use this specific tool call."
  }
}

export class CorrectedError extends Schema.TaggedErrorClass<CorrectedError>()("PermissionCorrectedError", {
  feedback: Schema.String,
}) {
  override get message() {
    // The reply is often an instruction ("just push it"), not a refusal; the
    // old "rejected ... feedback" wording made agents stop and wait instead.
    return `The user answered this tool call's permission request with a message instead of approving it: ${this.feedback}\n\nThat message is the user's direct instruction for your next step. If it tells you to go ahead, retry the same action; otherwise change course as it says.`
  }
}

export class DeniedError extends Schema.TaggedErrorClass<DeniedError>()("PermissionDeniedError", {
  ruleset: Schema.Any,
  // Set when the denial did not come from a rule the user wrote — a plugin's
  // `permission.ask` hook, for instance. Without it the model is told the user
  // authored a rule that does not exist.
  reason: Schema.optional(Schema.String),
}) {
  override get message() {
    if (this.reason) return this.reason
    return `The user has specified a rule which prevents you from using this specific tool call. Here are some of the relevant rules ${JSON.stringify(this.ruleset)}`
  }
}

export class NotFoundError extends Schema.TaggedErrorClass<NotFoundError>()("Permission.NotFoundError", {
  requestID: ID,
}) {}

export type Error = DeniedError | RejectedError | CorrectedError
