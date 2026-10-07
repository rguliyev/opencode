import { createMemo } from "solid-js"
import { useLocal } from "../context/local"
import { DialogSelect } from "../ui/dialog-select"
import { useDialog } from "../ui/dialog"
import { useTheme } from "../context/theme"
import { MouseEvent, type RGBA } from "@opentui/core"
import { useRenderer } from "@opentui/solid"

export function ModelVariantControl(props: { color: RGBA }) {
  const local = useLocal()
  const dialog = useDialog()
  const renderer = useRenderer()

  return (
    <text
      onMouseUp={(event: MouseEvent) => {
        if (event.button !== 0 || renderer.getSelection()?.getSelectedText()) return
        event.stopPropagation()
        dialog.replace(() => <DialogVariant />)
      }}
    >
      <span style={{ fg: props.color, bold: true }}>
        {local.model.parsed().reasoning ? "Reasoning" : "Variant"}: {local.model.variant.current() ?? "default"}
      </span>
    </text>
  )
}

export function DialogVariant() {
  const local = useLocal()
  const dialog = useDialog()
  const { theme } = useTheme()

  const options = createMemo(() => {
    return [
      {
        value: "default",
        title: "Default",
        onSelect: () => {
          dialog.clear()
          local.model.variant.set(undefined)
        },
      },
      ...local.model.variant.list().map((variant) => ({
        value: variant,
        title: variant,
        onSelect: () => {
          dialog.clear()
          local.model.variant.set(variant)
        },
      })),
    ]
  })

  return (
    <DialogSelect<string>
      options={options()}
      title={local.model.parsed().reasoning ? "Select reasoning level" : "Select model variant"}
      current={local.model.variant.current() ?? "default"}
      flat={true}
      footer={
        <text fg={theme.textMuted} paddingLeft={4} paddingRight={4}>
          Applies to your next prompt. Does not interrupt the current run.
        </text>
      }
    />
  )
}
