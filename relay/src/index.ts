// Copyright 2026 The Mawaddah authors
// SPDX-License-Identifier: Apache-2.0

// Blind relay skeleton (Phase 0): only a health route. The real endpoints
// (spec 4.5) arrive in Phase 1. Nothing here logs requests, bodies or IPs.

const JSON_HEADERS = { 'content-type': 'application/json', 'cache-control': 'no-store' };

export function handleRequest(request: Request): Response {
  const url = new URL(request.url);
  if (url.pathname === '/health') {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return new Response(null, { status: 405, headers: { allow: 'GET, HEAD' } });
    }
    return new Response(request.method === 'HEAD' ? null : JSON.stringify({ ok: true }), {
      status: 200,
      headers: JSON_HEADERS,
    });
  }
  return new Response(JSON.stringify({ error: 'not_found' }), { status: 404, headers: JSON_HEADERS });
}

export default {
  fetch(request: Request): Response {
    return handleRequest(request);
  },
};
