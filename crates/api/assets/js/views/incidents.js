// The incident list and the incident detail.

import * as api from '../api.js';
import { clear, el, facts, field, table } from '../dom.js';
import { badge, entityLabel, entityNodeId, graphRoute, incidentRoute, label, severityBadge, short, time } from '../format.js';

const STATUSES = ['open', 'investigating', 'contained', 'resolved', 'false_positive'];

export function incidentsView(context) {
  const select = el(
    'select',
    { name: 'status' },
    el('option', { value: '', text: 'All states' }),
    STATUSES.map((status) => el('option', { value: status, text: label(status) })),
  );
  const results = el('div');

  async function load() {
    context.notify('Loading the incidents.');
    try {
      const page = await api.get('/incidents', { status: select.value, limit: 100 }, context.signal);
      clear(results);
      if (page.items.length === 0) {
        results.append(el('p', { text: 'There are no incidents in this state.' }));
      } else {
        results.append(
          table(
            'Incidents, newest first',
            ['Severity', 'State', 'Title', 'Tenant', 'Last change'],
            page.items.map((incident) => [
              severityBadge(incident.severity),
              badge(incident.status),
              el('a', { href: incidentRoute(incident.id), text: incident.title || '(no title)' }),
              incident.tenant || '',
              time(incident.updated_at),
            ]),
          ),
        );
      }
      context.notify(`${page.items.length} incidents.`);
    } catch (error) {
      context.fail(error);
    }
  }

  select.addEventListener('change', load);
  context.main.append(
    el('h1', { text: 'Incidents' }),
    el(
      'div',
      { class: 'toolbar' },
      field('State', select),
      el('button', { type: 'button', text: 'Refresh', on: { click: load } }),
    ),
    results,
  );
  load();
}

function evidenceText(evidence) {
  return (evidence || []).map((item) => `${label(item.kind)} ${short(item.id, 13)}`).join(', ');
}

function detectionRows(detections) {
  return detections.map((detection) => [
    time(detection.time),
    severityBadge(detection.severity),
    label(detection.verdict),
    label(detection.tier),
    el('span', null, el('strong', { text: detection.title }), el('br'), detection.description),
    el('span', { class: 'mono', text: detection.rule_id }),
  ]);
}

function renderActions(target, explanation) {
  clear(target);
  target.append(
    table(
      'Audit records of the incident and its actions',
      ['Sequence', 'Time', 'Type', 'Actor', 'Summary', 'Evidence'],
      explanation.records.map((record) => [
        String(record.sequence),
        time(record.time),
        badge(record.kind),
        record.actor,
        record.summary,
        evidenceText(record.evidence),
      ]),
    ),
  );
}

export function incidentView(context, id) {
  const body = el('div');
  context.main.append(el('p', null, el('a', { href: '#/incidents', text: 'All incidents' })), body);

  async function load() {
    context.notify('Loading the incident.');
    let incident;
    try {
      incident = await api.get(`/incidents/${api.segment(id)}`, null, context.signal);
    } catch (error) {
      context.fail(error);
      return;
    }
    const actions = el('div', null, el('p', { class: 'muted', text: 'Loading the audit records.' }));
    clear(body).append(
      el('h1', { text: incident.title || '(no title)' }),
      el('p', null, severityBadge(incident.severity), ' ', badge(incident.status)),
      el('p', { text: incident.summary }),
      facts([
        ['Identifier', el('span', { class: 'mono', text: incident.id })],
        ['Tenant', incident.tenant],
        ['Created', time(incident.created_at)],
        ['Last change', time(incident.updated_at)],
        ['Graph', el('a', { href: graphRoute(`incident:${incident.id}`), text: 'Show the incident in the graph' })],
      ]),

      el('h2', { text: 'ATT&CK techniques' }),
      incident.attack.length === 0
        ? el('p', { class: 'muted', text: 'No technique.' })
        : el(
            'ul',
            { class: 'plain' },
            incident.attack.map((technique) =>
              el('li', null, el('span', { class: 'mono', text: technique.technique_id }), ` ${technique.name} (${technique.tactic})`),
            ),
          ),

      el('h2', { text: 'Entities' }),
      incident.entities.length === 0
        ? el('p', { class: 'muted', text: 'No entity.' })
        : el(
            'ul',
            { class: 'plain' },
            incident.entities.map((entity) =>
              el('li', null, el('a', { href: graphRoute(entityNodeId(entity)), text: entityLabel(entity) })),
            ),
          ),

      el('h2', { text: 'Timeline' }),
      incident.timeline.length === 0
        ? el('p', { class: 'muted', text: 'No entry.' })
        : el(
            'ol',
            { class: 'timeline' },
            incident.timeline.map((entry) =>
              el(
                'li',
                null,
                el('strong', { text: time(entry.time) }),
                ` ${entry.author}: ${entry.description}`,
                entry.evidence && entry.evidence.length > 0
                  ? el('span', { class: 'muted', text: ` Evidence: ${evidenceText(entry.evidence)}` })
                  : null,
              ),
            ),
          ),

      el('h2', { text: 'Detections' }),
      incident.detections.length === 0
        ? el('p', { class: 'muted', text: 'No detection.' })
        : table('Detections of the incident', ['Time', 'Severity', 'Verdict', 'Tier', 'Detection', 'Rule'], detectionRows(incident.detections)),

      el('h2', { text: 'Actions' }),
      actions,
    );
    context.notify('');

    try {
      const explanation = await api.get(`/incidents/${api.segment(id)}/explanation`, null, context.signal);
      renderActions(actions, explanation);
    } catch (error) {
      if (error instanceof api.ApiError && (error.status === 403 || error.status === 404)) {
        clear(actions).append(
          el('p', {
            class: 'muted',
            text: error.status === 403 ? 'You do not have the permission to read the audit records.' : 'No audit record links to this incident.',
          }),
        );
      } else {
        context.fail(error);
      }
    }
  }

  load();
}
