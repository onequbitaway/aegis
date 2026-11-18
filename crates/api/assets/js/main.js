// The entry point of the AEGIS console: the session, the tabs, and the view router.

import * as api from './api.js';
import { clear, el, field } from './dom.js';
import { label } from './format.js';
import { activityView } from './views/activity.js';
import { approvalsView } from './views/approvals.js';
import { auditView } from './views/audit.js';
import { graphView } from './views/graph.js';
import { incidentView, incidentsView } from './views/incidents.js';

const ROUTES = [
  { pattern: /^#\/incidents$/, tab: 'incidents', view: incidentsView },
  { pattern: /^#\/incidents\/([^/]+)$/, tab: 'incidents', view: incidentView },
  { pattern: /^#\/activity$/, tab: 'activity', view: activityView },
  { pattern: /^#\/approvals$/, tab: 'approvals', view: approvalsView },
  { pattern: /^#\/graph(?:\/(.+))?$/, tab: 'graph', view: graphView },
  { pattern: /^#\/audit$/, tab: 'audit', view: auditView },
];
const DEFAULT_ROUTE = '#/incidents';

const main = document.getElementById('main');
const notice = document.getElementById('notice');
const sessionBox = document.getElementById('session');
const tabs = document.getElementById('tabs');

let current = null;

// Shows one line of status text. `kind` is "error", "ok", or nothing.
function notify(text, kind) {
  notice.textContent = text || '';
  notice.className = kind ? `notice ${kind}` : 'notice';
}

// Shows the error of a request. An invalid token opens the token form.
function fail(error) {
  if (error && error.name === 'AbortError') {
    return;
  }
  if (error instanceof api.ApiError && error.status === 401) {
    api.clearToken();
    renderSession(null);
    showSignIn('The token is not valid. Enter a token.');
    return;
  }
  notify(error && error.message ? error.message : 'The operation failed.', 'error');
}

function decode(part) {
  if (part === undefined) {
    return undefined;
  }
  try {
    return decodeURIComponent(part);
  } catch {
    return part;
  }
}

function stopCurrent() {
  if (current) {
    current.controller.abort();
    if (typeof current.cleanup === 'function') {
      current.cleanup();
    }
    current = null;
  }
}

function showSignIn(message) {
  stopCurrent();
  clear(main).append(
    el('h1', { text: 'Sign in' }),
    el('p', { text: 'Enter your API token in the form at the top of the page.' }),
    el('p', { class: 'muted', text: 'The console keeps the token until you close this tab.' }),
  );
  notify(message || '', message ? 'error' : undefined);
}

function route() {
  const hash = window.location.hash || DEFAULT_ROUTE;
  const match = ROUTES.map((entry) => ({ entry, found: entry.pattern.exec(hash) })).find((item) => item.found);
  if (!match) {
    window.location.hash = DEFAULT_ROUTE;
    return;
  }
  for (const link of tabs.querySelectorAll('a')) {
    if (link.dataset.tab === match.entry.tab) {
      link.setAttribute('aria-current', 'page');
    } else {
      link.removeAttribute('aria-current');
    }
  }
  if (!api.getToken()) {
    showSignIn();
    return;
  }
  stopCurrent();
  notify('');
  clear(main);
  const controller = new AbortController();
  const context = { main, notify, fail, signal: controller.signal };
  const view = { controller, cleanup: null };
  current = view;
  try {
    view.cleanup = match.entry.view(context, ...match.found.slice(1).map(decode));
  } catch (error) {
    fail(error);
  }
}

function renderSession(session) {
  clear(sessionBox);
  if (session) {
    const roles = (session.principal.roles || []).join(', ') || 'no roles';
    sessionBox.append(
      el('span', { text: `${session.principal.id} (${label(session.principal.kind)}; ${roles})` }),
      el('button', {
        type: 'button',
        text: 'Forget the token',
        on: {
          click: () => {
            api.clearToken();
            renderSession(null);
            showSignIn();
          },
        },
      }),
    );
    return;
  }
  const input = el('input', {
    type: 'password',
    name: 'token',
    autocomplete: 'off',
    spellcheck: 'false',
    required: true,
    size: '28',
  });
  const form = el(
    'form',
    {
      on: {
        submit: (event) => {
          event.preventDefault();
          const token = input.value.trim();
          if (token) {
            api.setToken(token);
            start();
          }
        },
      },
    },
    field('API token', input),
    el('button', { type: 'submit', class: 'primary', text: 'Use the token' }),
  );
  sessionBox.append(form);
}

async function start() {
  if (!api.getToken()) {
    renderSession(null);
    route();
    return;
  }
  try {
    renderSession(await api.get('/session'));
    route();
    main.focus();
  } catch (error) {
    renderSession(null);
    fail(error);
  }
}

window.addEventListener('hashchange', route);
start();
