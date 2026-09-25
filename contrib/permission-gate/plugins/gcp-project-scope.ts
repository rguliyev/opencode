import { loadPolicy } from "../lib/gcp-scope"

type PermissionInput = {
  permission: string
  metadata?: Record<string, unknown>
}

type PermissionOutput = {
  status: "allow" | "ask" | "deny"
  message?: string
}

type ShellEnvironmentOutput = {
  env: Record<string, string>
}

export default async function GcpProjectScope() {
  return {
    "shell.env": async (_input: unknown, output: ShellEnvironmentOutput) => {
      try {
        const policy = loadPolicy()
        output.env.CLOUDSDK_CORE_PROJECT = policy.default_project
        output.env.CLOUDSDK_CORE_BILLING_PROJECT = policy.default_project
        output.env.GOOGLE_CLOUD_PROJECT = policy.default_project
        output.env.GOOGLE_CLOUD_QUOTA_PROJECT = policy.default_project
        output.env.GCLOUD_PROJECT = policy.default_project
      } catch (error) {
        throw new Error(`GCP scope policy failed to load before shell execution: ${error instanceof Error ? error.message : String(error)}`)
      }
    },
  }
}
