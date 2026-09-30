export const MAX_DIFF_PREVIEW_CHARACTERS = 128_000
export const MAX_DIFF_PREVIEW_LINES = 2_000

export function oversizedDiff(diff: string) {
  if (diff.length > MAX_DIFF_PREVIEW_CHARACTERS) return true
  return diff.split("\n").length > MAX_DIFF_PREVIEW_LINES
}
