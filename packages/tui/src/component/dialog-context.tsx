import { createMemo, createSignal, Show } from "solid-js"
import { MouseEvent, type RGBA } from "@opentui/core"
import { useRenderer } from "@opentui/solid"
import { MIN_CONTEXT_BUDGET, parseContextBudget } from "@opencode-ai/core/session/context-budget"
import { useLocal } from "../context/local"
import { useTheme } from "../context/theme"
import { useDialog } from "../ui/dialog"
import { DialogSelect, type DialogSelectOption } from "../ui/dialog-select"
import { DialogPrompt } from "../ui/dialog-prompt"
import { useToast } from "../ui/toast"
import { Locale } from "../util/locale"

export function ModelContextControl(props: { color: RGBA }) {
  const local = useLocal()
  const dialog = useDialog()
  const renderer = useRenderer()
  return (
    <Show when={local.model.context.info()}>
      {(info) => (
        <text
          fg={props.color}
          onMouseUp={(event: MouseEvent) => {
            if (event.button !== 0 || renderer.getSelection()?.getSelectedText()) return
            event.stopPropagation()
            dialog.replace(() => <DialogContextBudget />)
          }}
        >
          Context: {info().effective ? Locale.number(info().effective) : "unknown"}
          {info().auto ? "" : " (auto off)"}
        </text>
      )}
    </Show>
  )
}

export function DialogContextBudget(props: { custom?: boolean } = {}) {
  const local = useLocal()
  const dialog = useDialog()
  const toast = useToast()
  const { theme } = useTheme()
  const [busy, setBusy] = createSignal(false)
  const info = () => local.model.context.info()

  async function save(value?: number): Promise<void> {
    if (busy()) return
    setBusy(true)
    try {
      await local.model.context.set(value)
      dialog.clear()
      toast.show({ variant: "success", message: "Context budget saved for this session and model" })
    } catch (error) {
      toast.show({
        variant: "error",
        message: error instanceof Error ? error.message : "Could not save context budget",
      })
    } finally {
      setBusy(false)
    }
  }

  const description = () => (
    <text fg={theme.textMuted}>
      Model window: {Locale.number(info()?.window ?? 0)} tokens. Default compaction budget:{" "}
      {Locale.number(info()?.maximum ?? 0)}.{"\n"}Affects this session/model only, at the next compaction check; does
      not interrupt a response.
      {"\n"}This is an early-compaction budget, not a larger model window or a hard request-size cap.
      <Show when={!info()?.auto}>{"\n"}Automatic compaction is disabled on the server.</Show>
    </text>
  )

  const options = createMemo<DialogSelectOption<number>[]>(() => [
    {
      title: "Default",
      value: 0,
      description: `${Locale.number(info()?.maximum ?? 0)} tokens`,
      onSelect: () => void save(),
    },
    ...[
      ...new Set([
        32_000,
        64_000,
        128_000,
        256_000,
        512_000,
        1_000_000,
        ...(info()?.selected ? [info()!.selected!] : []),
      ]),
    ]
      .filter((value) => value <= (info()?.maximum ?? 0))
      .sort((a, b) => a - b)
      .map((value) => ({ title: `${Locale.number(value)} tokens`, value, onSelect: () => void save(value) })),
    { title: "Custom…", value: -1, onSelect: () => dialog.replace(() => <DialogContextBudget custom />) },
  ])

  if (!props.custom)
    return (
      <DialogSelect<number>
        title="Context size / compaction budget"
        options={options()}
        flat={true}
        current={info()?.selected ?? 0}
        locked={busy()}
        footer={description()}
      />
    )

  return (
    <DialogPrompt
      title="Custom context budget"
      description={description}
      busy={busy()}
      busyText="Saving…"
      value={String(info()?.selected ?? info()?.effective ?? "")}
      placeholder="e.g. 256k, 0.5m, or 256000"
      onCancel={() => dialog.replace(() => <DialogContextBudget />)}
      onConfirm={(text) => {
        const value = parseContextBudget(text)
        if (value === undefined || value > (info()?.maximum ?? 0)) {
          toast.show({
            variant: "error",
            message: `Enter ${MIN_CONTEXT_BUDGET}–${info()?.maximum ?? 0} tokens (k/m accepted)`,
          })
          return
        }
        void save(value)
      }}
    />
  )
}
