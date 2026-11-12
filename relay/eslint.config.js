// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['node_modules/', '.wrangler/', 'dist/'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    // loadtest/*.mjs is plain Node (no build step): declare the Node globals it uses.
    files: ['loadtest/**/*.mjs'],
    languageOptions: {
      globals: {
        process: 'readonly',
        console: 'readonly',
        fetch: 'readonly',
        crypto: 'readonly',
        performance: 'readonly',
        Buffer: 'readonly',
        URL: 'readonly',
      },
    },
  },
);
