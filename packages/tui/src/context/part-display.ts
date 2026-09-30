import type { Part } from "@opencode-ai/sdk/v2"
import { oversizedDiff } from "../util/diff-preview"

export function partForDisplay(part: Part): Part {
  if (part.type !== "tool" || part.tool !== "apply_patch" || part.state.status !== "completed") return part
  const files = part.state.metadata.files
  const diff = part.state.metadata.diff
  if (!Array.isArray(files) || files.length === 0) return part
  if (!files.every((file) => file && typeof file === "object" && "type" in file && file.type === "delete")) return part
  const large =
    (typeof diff === "string" && oversizedDiff(diff)) ||
    files.some((file) => typeof file.patch === "string" && oversizedDiff(file.patch))
  if (!large) return part

  // Deleted-file patches are already displayed as a line count. Keep their full text
  // on the server, but do not feed megabytes of unused strings into Solid's store.
  return {
    ...part,
    state: {
      ...part.state,
      metadata: {
        ...part.state.metadata,
        diff: "",
        files: files.map((file) => ({ ...file, patch: "" })),
      },
    },
  }
}
