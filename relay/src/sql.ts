// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// The small part of a SQLite database the relay state uses. In the Worker it
// is a Durable Object's `ctx.storage.sql`; the unit tests use Node's
// `node:sqlite`, so the same statements are tested with a controlled clock.

/** A BLOB is a `Uint8Array` on this side (the Durable Object wrapper converts to and from `ArrayBuffer`). */
export type SqlValue = string | number | null | Uint8Array;
export type SqlRow = Record<string, SqlValue>;

export interface Sql {
  /** Runs one statement and returns its rows (none for a write). */
  exec(query: string, ...bindings: SqlValue[]): SqlRow[];
}
