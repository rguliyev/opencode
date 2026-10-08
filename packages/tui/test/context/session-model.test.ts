import { expect, test } from "bun:test"
import path from "node:path"
import { createSessionModels } from "../../src/context/session-model"
import { tmpdir } from "../fixture/fixture"

const reasoner = { model: { providerID: "test", modelID: "reasoner" }, variants: { "test/reasoner": "high" } }
const plain = { model: { providerID: "test", modelID: "plain" }, variants: { "test/plain": "default" } }

function noError() {
  throw new Error("unexpected persistence error")
}

test("separate client stores do not overwrite different sessions, and rapid saves remain ordered", async () => {
  await using tmp = await tmpdir()
  const first = createSessionModels(tmp.path, noError)
  const second = createSessionModels(tmp.path, noError)
  await Promise.all([first.set("ses_a", reasoner), second.set("ses_b", plain)])
  await Promise.all([first.set("ses_a", plain), second.set("ses_a", reasoner), first.set("ses_a", plain)])
  const reopened = createSessionModels(tmp.path, noError)
  await Promise.all([reopened.load("ses_a"), reopened.load("ses_b")])
  expect(reopened.get("ses_a")).toEqual(plain)
  expect(reopened.get("ses_b")).toEqual(plain)
})

test("a choice during loading wins, malformed state is ignored, and session names cannot traverse paths", async () => {
  await using tmp = await tmpdir()
  const store = createSessionModels(tmp.path, noError)
  await store.set("ses_race", reasoner)
  const reopened = createSessionModels(tmp.path, noError)
  const pending = reopened.load("ses_race")
  await reopened.set("ses_race", plain)
  await pending
  expect(reopened.get("ses_race")).toEqual(plain)
  await Bun.write(path.join(tmp.path, "session-model", "session-ses_bad.json"), '{"model":123}')
  await reopened.load("ses_bad")
  expect(reopened.ready("ses_bad")).toBe(true)
  expect(reopened.get("ses_bad")).toBeUndefined()
  await reopened.set("../escape", reasoner)
  expect(await Bun.file(path.join(tmp.path, "session-model", "session-..%2Fescape.json")).exists()).toBe(true)
})
