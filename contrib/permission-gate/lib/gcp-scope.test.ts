import { expect, test } from "bun:test"
import { gcpScopeReviewMessageInLoop, targetsOnlyDefaultProject } from "./gcp-scope"

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

test("a for loop over allowed projects is resolved, not a dynamic project switch", () => {
  const loop = (projects: string) =>
    `for project in ${projects}; do google-api-get "https://monitoring.googleapis.com/v3/projects/$project/timeSeries"; done`
  const segment = 'google-api-get "https://monitoring.googleapis.com/v3/projects/$project/timeSeries"'
  expect(gcpScopeReviewMessageInLoop(segment, loop("e2b-staging e2b-foxtrot"))).toBeUndefined()
  expect(gcpScopeReviewMessageInLoop('gcloud container clusters list --project="$p"', 'for p in e2b-staging e2b-tango; do gcloud container clusters list --project="$p"; done')).toBeUndefined()
  // An unlisted project, a reassigned variable, or no loop still asks.
  expect(gcpScopeReviewMessageInLoop(segment, loop("e2b-staging some-other-project"))).toContain("some-other-project")
  expect(gcpScopeReviewMessageInLoop(segment, `${loop("e2b-staging")}; project=evil-project`)).toBeDefined()
  expect(gcpScopeReviewMessageInLoop(segment, segment)).toBeDefined()
  expect(gcpScopeReviewMessageInLoop(segment, 'for project in $(cat list); do x; done')).toBeDefined()
})

test("only well-formed unlisted project IDs are a hard gate; other captures are a dynamic choice", async () => {
  const { gcpScopeFinding } = await import("./gcp-scope")
  expect(gcpScopeFinding("gcloud compute instances list --project=some-unlisted-project")?.kind).toBe("unlisted_projects")
  expect(gcpScopeFinding('cmd = ["gcloud", "logging", "read", "--project=" + project, "--limit=5"]')?.kind).toBe("dynamic_project")
  expect(gcpScopeFinding('gcloud run services list --project="$proj"')?.kind).toBe("dynamic_project")
  expect(gcpScopeFinding("gcloud compute instances list --project=Not_A_Project")?.kind).toBe("dynamic_project")
  expect(gcpScopeFinding("gcloud compute instances list --account=x@example.test")?.kind).toBe("credential_switch")
  expect(gcpScopeFinding("gcloud compute instances list --project=e2b-staging")).toBeUndefined()
})

test("printing the gcloud config variable selects no credentials; setting it or printing a substitution does", async () => {
  const { gcpScopeFinding } = await import("./gcp-scope")
  expect(gcpScopeFinding('echo "CLOUDSDK_CONFIG=$CLOUDSDK_CONFIG"')).toBeUndefined()
  expect(gcpScopeFinding('mkdir -p /data/rguliyev/tmp/opencode/x && echo "CLOUDSDK_CONFIG=$CLOUDSDK_CONFIG"')).toBeUndefined()
  expect(gcpScopeFinding("printf 'CLOUDSDK_CONFIG=%s\\n' \"$CLOUDSDK_CONFIG\"")).toBeUndefined()
  expect(gcpScopeFinding("echo ok; CLOUDSDK_CONFIG=/tmp/other gcloud projects list")?.kind).toBe("credential_switch")
  expect(gcpScopeFinding('echo "$(CLOUDSDK_CONFIG=/tmp/other gcloud auth print-access-token)"')?.kind).toBe("credential_switch")
})
