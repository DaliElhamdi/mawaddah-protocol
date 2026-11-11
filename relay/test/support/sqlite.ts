// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// An in-memory SQLite database from Node (`node:sqlite`) behind the relay's
// `Sql` interface, so the Durable Object statements run in unit tests.

import { DatabaseSync } from 'node:sqlite';
import type { Sql, SqlRow, SqlValue } from '../../src/sql';

export function memorySql(): Sql & { close(): void } {
  const db = new DatabaseSync(':memory:');
  return {
    exec: (query: string, ...bindings: SqlValue[]) =>
      db.prepare(query).all(...bindings).map((row) => ({ ...row }) as SqlRow),
    close: () => {
      if (db.isOpen) db.close();
    },
  };
}
