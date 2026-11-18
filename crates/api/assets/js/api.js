// The API client of the AEGIS console.
//
// The console sends requests only to its own origin. The bearer token stays in
// sessionStorage: it is gone when the tab closes.

import { SseParser } from './sse.js';

const TOKEN_KEY = 'aegis.token';
const BASE = '/api/v1';

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

export function getToken() {
  try {
    return window.sessionStorage.getItem(TOKEN_KEY) || '';
  } catch {
    return '';
  }
}

export function setToken(token) {
  window.sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken() {
  window.sessionStorage.removeItem(TOKEN_KEY);
}

function options(method, signal, extraHeaders) {
  return {
    method,
    headers: { Authorization: `Bearer ${getToken()}`, ...extraHeaders },
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal,
  };
}

async function errorOf(response) {
  let code = 'error';
  let message = `The server answered with the status ${response.status}.`;
  try {
    const body = await response.json();
    if (body && body.error) {
      code = String(body.error.code);
      message = String(body.error.message);
    }
  } catch {
    // The body is not JSON. Keep the default message.
  }
  return new ApiError(response.status, code, message);
}

async function send(path, init) {
  try {
    return await fetch(BASE + path, init);
  } catch (error) {
    if (error.name === 'AbortError') {
      throw error;
    }
    throw new ApiError(0, 'network', 'The server did not answer.');
  }
}

// Returns one path segment for a value.
export function segment(value) {
  return encodeURIComponent(String(value));
}

function withQuery(path, query) {
  const parameters = new URLSearchParams();
  for (const [name, value] of Object.entries(query || {})) {
    if (value !== undefined && value !== null && value !== '') {
      parameters.set(name, String(value));
    }
  }
  const text = parameters.toString();
  return text ? `${path}?${text}` : path;
}

// Sends a GET request. Returns the JSON document of the answer.
export async function get(path, query, signal) {
  const response = await send(withQuery(path, query), options('GET', signal, { Accept: 'application/json' }));
  if (!response.ok) {
    throw await errorOf(response);
  }
  return response.json();
}

// Sends a POST request with a JSON body. Returns the JSON document of the answer.
export async function post(path, body, signal) {
  const init = options('POST', signal, { Accept: 'application/json', 'Content-Type': 'application/json' });
  init.body = JSON.stringify(body);
  const response = await send(path, init);
  if (!response.ok) {
    throw await errorOf(response);
  }
  return response.json();
}

// Reads the live feed until the signal aborts or the server ends the feed.
// Calls `onEvent` with { type, data } for each event. `data` is the parsed JSON document.
export async function readStream(signal, onEvent) {
  const response = await send('/stream', options('GET', signal, { Accept: 'text/event-stream' }));
  if (!response.ok) {
    throw await errorOf(response);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const parser = new SseParser();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) {
      return;
    }
    for (const event of parser.push(decoder.decode(value, { stream: true }))) {
      let data = null;
      try {
        data = JSON.parse(event.data);
      } catch {
        continue;
      }
      onEvent({ type: event.type, data });
    }
  }
}
