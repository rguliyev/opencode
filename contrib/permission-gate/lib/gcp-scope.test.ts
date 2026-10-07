import { expect, test } from "bun:test"
import { targetsOnlyDefaultProject } from "./gcp-scope"

const dev = "e2b-dev-rauf-guliyev"

test("a worktree apply with no project flag is the default dev project", () => {
  expect(targetsOnlyDefaultProject("terraform apply -auto-approve")).toBe(true)
  expect(targetsOnlyDefaultProject(`terraform apply -var project=${dev}`)).toBe(true)
})

test("an apply that names another project is not local dev", () => {
  expect(targetsOnlyDefaultProject("terraform apply -var project=e2b-juliett-europe")).toBe(false)
  expect(targetsOnlyDefaultProject("terragrunt apply --terragrunt-working-dir=live")).toBe(true)
  expect(targetsOnlyDefaultProject("CLOUDSDK_CORE_PROJECT=e2b-staging terraform apply")).toBe(false)
})

test("projects/ paths in non-Google URLs are not GCP projects", () => {
  expect(
    targetsOnlyDefaultProject("curl -s 'https://gitlab.com/api/v4/projects/torvalds%2Flinux/repository/commits?path=fs'"),
  ).toBe(true)
  expect(targetsOnlyDefaultProject("curl https://github.com/projects/other-team-board")).toBe(true)
  expect(
    targetsOnlyDefaultProject("google-api-get 'https://monitoring.googleapis.com/v3/projects/e2b-staging/timeSeries'"),
  ).toBe(false)
  expect(targetsOnlyDefaultProject("echo projects/e2b-staging")).toBe(false)
})
