// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['node_modules/', '.wrangler/', 'dist/'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
);
