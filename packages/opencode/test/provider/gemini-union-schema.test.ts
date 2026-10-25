import { describe, expect, test } from "bun:test"
import { createGoogleGenerativeAI } from "@ai-sdk/google"
import { ProviderTransform } from "@/provider/transform"
import type { Provider } from "@/provider/provider"
import type { JSONSchema7 } from "@ai-sdk/provider"

describe("Gemini union schemas on the wire", () => {
  for (const id of ["gemini-3.8-flash", "gemini-4-argon"]) {
    test(`${id} keeps type-specific keywords only on matching union branches`, async () => {
      const schema: JSONSchema7 = {
        type: "object",
        properties: {
          // Exact Grafana exec_gcx schema that caused the production rejection.
          nullableArgs: {
            type: ["null", "array"],
            items: { type: "string" },
            description: "gcx arguments, without the program name",
          },
          args: {
            type: ["array", "object", "string", "null"],
            items: { type: "string" },
            properties: { name: { type: "string" } },
            required: ["name"],
            description: "Arguments",
          },
        },
      }
      const original = structuredClone(schema)
      const model = { providerID: "google", api: { id } } as Provider.Model
      const transformed = ProviderTransform.schema(model, schema)
      const requests: Request[] = []
      const google = createGoogleGenerativeAI({
        apiKey: "test-key",
        fetch: Object.assign(
          async (...args: Parameters<typeof fetch>) => {
            requests.push(new Request(...args))
            return Response.json({
              candidates: [{ content: { role: "model", parts: [{ text: "OK" }] }, finishReason: "STOP" }],
              usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1, totalTokenCount: 2 },
            })
          },
          { preconnect: () => undefined },
        ),
      })
      await google(id).doGenerate({
        prompt: [{ role: "user", content: [{ type: "text", text: "Reply OK, do not call tools." }] }],
        tools: [{ type: "function", name: "probe", inputSchema: transformed }],
        toolChoice: { type: "none" },
      })
      expect(requests).toHaveLength(1)
      const body = await requests[0].json()
      const args = body.tools[0].functionDeclarations[0].parameters.properties.args
      expect(args).not.toHaveProperty("items")
      expect(args).not.toHaveProperty("properties")
      expect(args).not.toHaveProperty("required")
      expect(args.anyOf).toEqual([
        { type: "array", items: { type: "string" } },
        { type: "object", properties: { name: { type: "string" } }, required: ["name"] },
        { type: "string" },
      ])
      expect(args.description).toBe("Arguments")
      expect(body.tools[0].functionDeclarations[0].parameters.properties.nullableArgs).toEqual({
        description: "gcx arguments, without the program name",
        anyOf: [{ type: "array", items: { type: "string" } }],
      })
      expect(body.toolConfig.functionCallingConfig.mode).toBe("NONE")
      expect(ProviderTransform.schema(model, transformed)).toEqual(transformed)
      expect(schema).toEqual(original)
    })
  }
})
