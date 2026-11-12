// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// wrangler.toml does not inherit Durable Object bindings or migrations into an
// environment, so staging and production repeat them. This test fails when an
// environment drifts from the top level (a class added in one place only would
// otherwise deploy a Worker without it, or without its migration).

import { describe, expect, it } from 'vitest';
import { unstable_readConfig as readConfig } from 'wrangler';

const configPath = new URL('../wrangler.toml', import.meta.url).pathname;

function config(env?: string) {
  return readConfig({ config: configPath, env });
}

describe('wrangler.toml environments', () => {
  const top = config();

  it('names the Workers as the owner chose', () => {
    expect(top.name).toBe('mawaddah-relay');
    expect(config('staging').name).toBe('mawaddah-relay-staging');
    expect(config('production').name).toBe('mawaddah-relay');
  });

  for (const env of ['staging', 'production']) {
    describe(env, () => {
      const c = config(env);

      it('has the same Durable Object bindings as the top level', () => {
        expect(c.durable_objects.bindings.length).toBeGreaterThan(0);
        expect(c.durable_objects.bindings).toEqual(top.durable_objects.bindings);
      });

      it('has the same migrations as the top level', () => {
        expect(c.migrations.length).toBeGreaterThan(0);
        expect(c.migrations).toEqual(top.migrations);
      });

      it('keeps request logs off (spec 4.5)', () => {
        expect(c.observability?.enabled).toBe(false);
      });

      it('uses the same entry point and compatibility date', () => {
        expect(c.main).toBe(top.main);
        expect(c.compatibility_date).toBe(top.compatibility_date);
      });

      it('sets no variables, routes, tail consumers or log push', () => {
        expect(c.vars).toEqual({});
        expect(c.routes ?? []).toEqual([]);
        expect(c.tail_consumers ?? []).toEqual([]);
        expect(c.logpush ?? false).toBe(false);
      });
    });
  }

  it('gives staging and production different Workers (separate storage)', () => {
    expect(config('staging').name).not.toBe(config('production').name);
  });
});
