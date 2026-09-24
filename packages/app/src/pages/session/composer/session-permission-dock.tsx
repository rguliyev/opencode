import { For, Show, createSignal } from "solid-js"
import type { PermissionRequest } from "@opencode-ai/sdk/v2"
import { Button } from "@opencode-ai/ui/button"
import { DockPrompt } from "@opencode-ai/session-ui/dock-prompt"
import { Icon } from "@opencode-ai/ui/icon"
import { useLanguage } from "@/context/language"

export function SessionPermissionDock(props: {
  request: PermissionRequest
  responding: boolean
  onDecide: (response: "once" | "always" | "reject", message?: string) => void
}) {
  const language = useLanguage()
  const [correcting, setCorrecting] = createSignal(false)
  const [feedback, setFeedback] = createSignal("")

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
                <>
                  <Button variant="ghost" size="normal" onClick={() => props.onDecide("reject")} disabled={props.responding}>
                    {language.t("ui.permission.deny")}
                  </Button>
                  <Button variant="ghost" size="normal" onClick={() => setCorrecting(true)} disabled={props.responding}>
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
                  <Button variant="primary" size="normal" onClick={() => props.onDecide("once")} disabled={props.responding}>
                    {language.t("ui.permission.allowOnce")}
                  </Button>
                </>
              }
            >
              <Button variant="ghost" size="normal" onClick={() => setCorrecting(false)} disabled={props.responding}>
                {language.t("permission.doDifferently.cancel")}
              </Button>
              <Button
                variant="primary"
                size="normal"
                onClick={() => props.onDecide("reject", feedback().trim())}
                disabled={props.responding || !feedback().trim()}
              >
                {language.t("permission.doDifferently.send")}
              </Button>
            </Show>
          </div>
        </>
      }
    >
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
