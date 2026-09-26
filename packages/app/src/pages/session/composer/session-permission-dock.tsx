import { For, Show, createMemo, createSignal } from "solid-js"
import type { PermissionRequest } from "@opencode-ai/sdk/v2"
import { Button } from "@opencode-ai/ui/button"
import { DockPrompt } from "@opencode-ai/session-ui/dock-prompt"
import { Icon } from "@opencode-ai/ui/icon"
import { useLanguage } from "@/context/language"

type CommandFeedback = { index: number; digest: string; decision: "allow" | "reject" }
type ReviewItem = { index: number; digest: string; command: string | null; reason: string }

export function SessionPermissionDock(props: {
  request: PermissionRequest
  responding: boolean
  onDecide: (response: "once" | "always" | "reject", message?: string, commandFeedback?: CommandFeedback[]) => void
}) {
  const language = useLanguage()
  const [correcting, setCorrecting] = createSignal(false)
  const [feedback, setFeedback] = createSignal("")
  const [reviewIndex, setReviewIndex] = createSignal(0)
  const [reviewFeedback, setReviewFeedback] = createSignal<CommandFeedback[]>([])

  const reviewItems = createMemo((): ReviewItem[] => {
    if (props.request.permission !== "bash") return []
    const raw = props.request.metadata?.reviewItems
    if (!Array.isArray(raw)) return []
    return raw.filter(
      (item): item is ReviewItem =>
        !!item &&
        typeof item === "object" &&
        Number.isInteger(item.index) &&
        typeof item.digest === "string" &&
        /^[a-f0-9]{64}$/.test(item.digest) &&
        (typeof item.command === "string" || item.command === null) &&
        typeof item.reason === "string",
    )
  })
  const multiCommand = createMemo(() => {
    if (props.request.permission !== "bash") return false
    const count = props.request.metadata?.commandCount
    return props.request.patterns.length > 1 || (typeof count === "number" && Number.isInteger(count) && count > 1)
  })

  const respondToReview = (decision: "allow" | "reject", message?: string) => {
    const item = reviewItems()[reviewIndex()]
    if (!item) return
    const decisions: CommandFeedback[] = [...reviewFeedback(), { index: item.index, digest: item.digest, decision }]
    if (decision === "allow" && reviewIndex() + 1 < reviewItems().length) {
      setReviewFeedback(decisions)
      setReviewIndex(reviewIndex() + 1)
      return
    }
    props.onDecide(decision === "allow" ? "once" : "reject", message, decisions)
  }

  const correct = () => {
    const message = feedback().trim()
    if (!message) return
    if (reviewItems().length) return respondToReview("reject", message)
    props.onDecide("reject", message)
  }

  const toolDescription = () => {
    const key = `settings.permissions.tool.${props.request.permission}.description`
    const value = language.t(key as Parameters<typeof language.t>[0])
    if (value === key) return ""
    return value
  }

  const taskDescription = () => {
    if (props.request.permission !== "task") return ""
    const value = props.request.metadata?.description
    return typeof value === "string" ? value.trim() : ""
  }

  const purpose = () => {
    const value = props.request.metadata?.purpose
    return typeof value === "string" ? value : ""
  }

  const reviewReason = () => {
    const value = props.request.metadata?.reviewReason
    return typeof value === "string" ? value : ""
  }

  return (
    <DockPrompt
      kind="permission"
      header={
        <div data-slot="permission-row" data-variant="header">
          <span data-slot="permission-icon">
            <Icon name="warning" size="normal" />
          </span>
          <div data-slot="permission-header-title">{language.t("notification.permission.title")}</div>
        </div>
      }
      footer={
        <>
          <div />
          <div data-slot="permission-footer-actions">
            <Show
              when={correcting()}
              fallback={
                <Show
                  when={reviewItems().length > 0}
                  fallback={
                    <>
                      <Button
                        variant="ghost"
                        size="normal"
                        onClick={() => props.onDecide("reject")}
                        disabled={props.responding}
                      >
                        {language.t("ui.permission.deny")}
                      </Button>
                      <Button
                        variant="ghost"
                        size="normal"
                        onClick={() => setCorrecting(true)}
                        disabled={props.responding}
                      >
                        {language.t("permission.doDifferently")}
                      </Button>
                      <Button
                        variant="secondary"
                        size="normal"
                        onClick={() => props.onDecide("always")}
                        disabled={props.responding}
                      >
                        {language.t("ui.permission.allowAlways")}
                      </Button>
                      <Button
                        variant="primary"
                        size="normal"
                        onClick={() => props.onDecide("once")}
                        disabled={props.responding}
                      >
                        {language.t(multiCommand() ? "permission.review.allowAll" : "ui.permission.allowOnce")}
                      </Button>
                    </>
                  }
                >
                  <Button
                    variant="ghost"
                    size="normal"
                    onClick={() => respondToReview("reject")}
                    disabled={props.responding}
                  >
                    {language.t("permission.review.rejectWhole")}
                  </Button>
                  <Button variant="ghost" size="normal" onClick={() => setCorrecting(true)} disabled={props.responding}>
                    {language.t("permission.doDifferently")}
                  </Button>
                  <Show when={multiCommand()}>
                    <Button
                      variant="secondary"
                      size="normal"
                      onClick={() =>
                        props.onDecide(
                          "once",
                          undefined,
                          reviewItems().map((item) => ({ index: item.index, digest: item.digest, decision: "allow" })),
                        )
                      }
                      disabled={props.responding}
                    >
                      {language.t("permission.review.allowAll")}
                    </Button>
                  </Show>
                  <Button
                    variant="primary"
                    size="normal"
                    onClick={() => respondToReview("allow")}
                    disabled={props.responding}
                  >
                    {language.t("permission.review.allowCommand")}
                  </Button>
                </Show>
              }
            >
              <Button variant="ghost" size="normal" onClick={() => setCorrecting(false)} disabled={props.responding}>
                {language.t("permission.doDifferently.cancel")}
              </Button>
              <Button
                variant="primary"
                size="normal"
                onClick={correct}
                disabled={props.responding || !feedback().trim()}
              >
                {language.t("permission.doDifferently.send")}
              </Button>
            </Show>
          </div>
        </>
      }
    >
      <Show when={reviewItems().length > 0}>
        <div data-slot="permission-row">
          <span data-slot="permission-spacer" aria-hidden="true" />
          <div class="flex min-w-0 flex-col gap-2">
            <div data-slot="permission-hint">
              {language.t("permission.review.progress", { current: reviewIndex() + 1, total: reviewItems().length })}
            </div>
            <For each={reviewItems()}>
              {(item, position) => (
                <div
                  class="flex min-w-0 flex-col gap-1 border-l-2 pl-2"
                  classList={{
                    "border-border-weak-base": position() === reviewIndex(),
                    "border-transparent": position() !== reviewIndex(),
                  }}
                >
                  <code class="break-all text-12-regular text-text-base">
                    {item.command ?? language.t("permission.review.withheld")}
                  </code>
                  <div data-slot="permission-hint">{item.reason}</div>
                </div>
              )}
            </For>
          </div>
        </div>
      </Show>
      <Show when={correcting()}>
        <div data-slot="permission-row">
          <span data-slot="permission-spacer" aria-hidden="true" />
          <textarea
            aria-label={language.t("permission.doDifferently.prompt")}
            placeholder={language.t("permission.doDifferently.prompt")}
            class="min-h-20 w-full resize-y rounded-md border border-border-weak-base bg-background-base p-2 text-text-base"
            value={feedback()}
            disabled={props.responding}
            onInput={(event) => setFeedback(event.currentTarget.value)}
            onKeyDown={(event) => {
              if (event.key !== "Escape") return
              event.preventDefault()
              setCorrecting(false)
            }}
          />
        </div>
      </Show>
      <Show when={taskDescription()}>
        <div data-slot="permission-row">
          <span data-slot="permission-spacer" aria-hidden="true" />
          <div data-slot="permission-hint">{taskDescription()}</div>
        </div>
      </Show>

      <Show when={toolDescription()}>
        <div data-slot="permission-row">
          <span data-slot="permission-spacer" aria-hidden="true" />
          <div data-slot="permission-hint">{toolDescription()}</div>
        </div>
      </Show>

      <Show when={reviewReason()}>
        <div data-slot="permission-row">
          <span data-slot="permission-spacer" aria-hidden="true" />
          <div data-slot="permission-hint">
            <strong>{language.t("permission.reason.review")}</strong>: {reviewReason()}
          </div>
        </div>
      </Show>

      <Show when={purpose()}>
        <div data-slot="permission-row">
          <span data-slot="permission-spacer" aria-hidden="true" />
          <div data-slot="permission-hint">
            <strong>{language.t("permission.reason.agent")}</strong>: {purpose()}
          </div>
        </div>
      </Show>

      <Show when={props.request.patterns.length > 0}>
        <div data-slot="permission-row">
          <span data-slot="permission-spacer" aria-hidden="true" />
          <div data-slot="permission-patterns">
            <For each={props.request.patterns}>
              {(pattern) => <code class="text-12-regular text-text-base break-all">{pattern}</code>}
            </For>
          </div>
        </div>
      </Show>
    </DockPrompt>
  )
}
