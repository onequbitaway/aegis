// Live agent activity: the agent runtime and the live feed.

import * as api from '../api.js';
import { clear, el, facts, table } from '../dom.js';
import { badge, entityLabel, incidentRoute, label, severityBadge, short, time } from '../format.js';

const MAX_FEED_ITEMS = 200;

// Returns the nodes that describe one event of the live feed.
function describe(type, payload) {
  if (!payload || typeof payload !== 'object') {
    return [String(payload)];
  }
  switch (type) {
    case 'detection':
      return [severityBadge(payload.severity), ` ${payload.title} (${label(payload.verdict)}, ${label(payload.tier)})`];
    case 'incident':
      return [
        severityBadge(payload.severity),
        ' ',
        badge(payload.status),
        ' ',
        el('a', { href: incidentRoute(payload.id), text: payload.title || '(no title)' }),
      ];
    case 'action_result':
      if (payload.executed) {
        return [`Action ${label(payload.executed.status)} by ${payload.executed.connector}: ${payload.executed.message}`];
      }
      if (payload.pending_approval) {
        return ['An action waits for approval. ', el('a', { href: '#/approvals', text: 'Open the approvals' })];
      }
      if (payload.denied) {
        return [`Policy denied an action. ${(payload.denied.reasons || []).join(' ')}`];
      }
      return ['An action result.'];
    case 'approval':
      return [
        badge(payload.status),
        ` ${label(payload.action && payload.action.kind)} on ${payload.action ? entityLabel(payload.action.target) : ''}`,
      ];
    case 'audit':
      return [`#${payload.sequence} ${label(payload.kind)} by ${payload.actor}: ${payload.summary}`];
    default:
      return [short(JSON.stringify(payload), 200)];
  }
}

export function activityView(context) {
  const agents = el('div', { class: 'panel' }, el('p', { class: 'muted', text: 'Loading the agents.' }));
  const feedState = el('p', { class: 'muted', role: 'status', text: 'The live feed is not connected.' });
  const feed = el('ul', { class: 'feed', 'aria-label': 'Live feed events, newest first' });
  const reconnect = el('button', { type: 'button', text: 'Connect again', hidden: true });
  let streamController = null;

  async function loadAgents() {
    try {
      const data = await api.get('/agents', { limit: 25 }, context.signal);
      const stats = data.stats;
      clear(agents).append(
        el('h2', { text: 'Agent runtime' }),
        facts([
          ['State', badge(data.state)],
          ['Mode', data.dry_run ? 'Dry run: the agents change nothing.' : 'Live: actions can change the environment.'],
          ['Tasks in the queue', String(data.queued)],
          ['Tasks completed', String(stats.tasks_completed)],
          ['Tasks failed', String(stats.tasks_failed)],
          ['Tasks rejected', String(stats.tasks_rejected)],
          ['Actions dispatched', String(stats.actions_dispatched)],
          ['Actions rejected', String(stats.actions_rejected)],
          ['Dispatch failures', String(stats.dispatch_failures)],
          ['Audit failures', String(stats.audit_failures)],
          ['Agents', data.roster.map((role) => label(role)).join(', ')],
        ]),
        data.recent_tasks.length === 0
          ? el('p', { class: 'muted', text: 'No task ended yet.' })
          : table(
              'The last tasks that ended, oldest first',
              ['Agent', 'Result', 'Incident', 'Detail'],
              data.recent_tasks.map((task) => [
                label(task.role),
                badge(task.state, task.state === 'completed' ? 'good' : 'bad'),
                task.incident_id ? el('a', { href: incidentRoute(task.incident_id), text: short(task.incident_id, 13) }) : '',
                task.detail || '',
              ]),
            ),
      );
    } catch (error) {
      context.fail(error);
    }
  }

  function add(type, data) {
    const item = el(
      'li',
      null,
      el('span', { class: 'muted', text: `${new Date().toLocaleTimeString()} ` }),
      badge(type),
      ' ',
      describe(type, data.payload),
    );
    feed.prepend(item);
    while (feed.children.length > MAX_FEED_ITEMS) {
      feed.lastElementChild.remove();
    }
  }

  async function connect() {
    reconnect.hidden = true;
    feedState.textContent = 'Connecting to the live feed.';
    streamController = new AbortController();
    context.signal.addEventListener('abort', () => streamController.abort(), { once: true });
    try {
      await api.readStream(streamController.signal, (event) => {
        if (event.type === 'ready') {
          feedState.textContent = `The live feed is connected: ${(event.data.feeds || []).map((name) => label(name)).join(', ')}.`;
        } else if (event.type === 'error') {
          feedState.textContent = `The live feed reported an error: ${event.data.message}`;
        } else {
          add(event.type, event.data);
          if (event.type === 'action_result') {
            loadAgents();
          }
        }
      });
      feedState.textContent = 'The server closed the live feed.';
      reconnect.hidden = false;
    } catch (error) {
      if (error.name === 'AbortError') {
        return;
      }
      feedState.textContent = 'The live feed stopped.';
      reconnect.hidden = false;
      context.fail(error);
    }
  }

  reconnect.addEventListener('click', connect);
  context.main.append(
    el('h1', { text: 'Activity' }),
    el('div', { class: 'toolbar' }, el('button', { type: 'button', text: 'Refresh the agents', on: { click: loadAgents } })),
    agents,
    el('h2', { text: 'Live feed' }),
    feedState,
    reconnect,
    el('div', { class: 'panel' }, feed),
  );
  loadAgents();
  connect();
  return () => {
    if (streamController) {
      streamController.abort();
    }
  };
}
