import { sql } from "drizzle-orm"
import { Schema } from "effect"
import { NonNegativeInt, optional } from "@opencode-ai/core/schema"
import { MessageID, SessionID } from "./schema"

export const Match = Schema.Struct({
  kind: Schema.Literals(["title", "prompt"]),
  sessionID: SessionID,
  messageID: optional(MessageID),
  agent: optional(Schema.String),
  excerpt: Schema.String,
  time: NonNegativeInt,
}).annotate({ identifier: "SessionSearchMatch" })
export type Match = typeof Match.Type

export function decode(value: string | null): Match | undefined {
  if (!value) return
  const match = Schema.decodeUnknownSync(Match)(JSON.parse(value))
  return {
    ...match,
    excerpt: match.excerpt
      .replace(/[\x00-\x1f\x7f-\x9f]/g, " ")
      .replace(/\s+/g, " ")
      .trim(),
  }
}

// Read only user text, not large tool results, reasoning, or synthetic summaries.
// CROSS JOIN and INDEXED BY keep message -> parts and parent -> children lookups
// indexed. SQLite otherwise chooses the session index for every message and
// scans entire session histories repeatedly (including large tool results).
// Explicit outer qualifiers survive Drizzle's single-table select rewriting.
// Search before limiting sessions, so old prompts are not lost behind a recent page.
export function match(query: string, descendants: boolean) {
  const text = sql`json_extract(p.data, '$.text')`
  const start = sql`max(1, instr(lower(${text}), lower(${query})) - 20)`
  const excerpt = sql`(case when ${start} > 1 then '…' else '' end)
    || substr(${text}, ${start}, 236)
    || (case when length(${text}) >= ${start} + 236 then '…' else '' end)`
  const prompt = sql`json_extract(m.data, '$.role') = 'user'
    and json_extract(p.data, '$.type') = 'text'
    and coalesce(json_extract(p.data, '$.synthetic'), 0) = 0
    and coalesce(json_extract(p.data, '$.ignored'), 0) = 0
    and instr(lower(${text}), lower(${query})) > 0`
  return sql<string | null>`coalesce(
    case when instr(lower("session"."title"), lower(${query})) > 0 then
      json_object('kind', 'title', 'sessionID', "session"."id",
        'excerpt', substr("session"."title", 1, 240), 'time', "session"."time_updated") end,
    (select json_object('kind', 'prompt', 'sessionID', m.session_id,
        'messageID', m.id, 'excerpt', ${excerpt}, 'time', m.time_created)
      from message m cross join part p indexed by part_message_id_id_idx on p.message_id = m.id and p.session_id = m.session_id
      where m.session_id = "session"."id" and ${prompt}
      order by m.time_created desc, m.id desc, p.id desc limit 1),
    ${
      descendants
        ? sql`(with recursive children(id) as (
            select child.id from session child where child.parent_id = "session"."id" and child.project_id = "session"."project_id"
            union
            select s.id from children c cross join session s indexed by session_parent_idx on s.parent_id = c.id
              where s.project_id = "session"."project_id" and s.id != "session"."id"
          )
          select hit from (
            select json_object('kind', 'title', 'sessionID', s.id, 'agent', coalesce(s.agent, 'subagent'),
              'excerpt', substr(s.title, 1, 240), 'time', s.time_updated) as hit, s.time_updated as time, s.id as id
              from children c join session s on s.id = c.id
              where instr(lower(s.title), lower(${query})) > 0
            union all
            select json_object('kind', 'prompt', 'sessionID', s.id, 'messageID', m.id,
              'agent', coalesce(s.agent, 'subagent'), 'excerpt', ${excerpt}, 'time', m.time_created),
              m.time_created, m.id
              from children c cross join session s on s.id = c.id
              cross join message m on m.session_id = s.id
              cross join part p indexed by part_message_id_id_idx on p.message_id = m.id and p.session_id = m.session_id
              where ${prompt}
          ) order by time desc, id desc limit 1)`
        : sql`null`
    }
  )`
}

export * as SessionSearch from "./search"
