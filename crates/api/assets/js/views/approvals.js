// The approvals queue: approve or reject a gated action with a note.

import * as api from '../api.js';
import { clear, el, facts, field } from '../dom.js';
import { entityLabel, incidentRoute, label, time } from '../format.js';

function dispositionText(disposition) {
  if (!disposition) {
    return '';
  }
  if (disposition.executed) {
    return `The action result is ${label(disposition.executed.status)}: ${disposition.executed.message}`;
  }
  if (disposition.pending_approval) {
    return 'The action waits for one more approval.';
  }
  if (disposition.denied) {
    return `Policy denied the action. ${(disposition.denied.reasons || []).join(' ')}`;
  }
  return '';
}

export function approvalsView(context) {
  const list = el('div', { class: 'cards' });
  const count = el('p', { class: 'muted' });

  function card(request) {
    const noteId = `note-${request.id}`;
    const note = el('textarea', { id: noteId, maxlength: '1000', rows: '2' });
    const approve = el('button', { type: 'button', class: 'primary', text: 'Approve' });
    const reject = el('button', { type: 'button', class: 'danger', text: 'Reject' });
    const result = el('p', { role: 'status' });

    async function decide(approved) {
      if (approved && !window.confirm('Approve this action? AEGIS runs the action after the approval.')) {
        return;
      }
      approve.disabled = true;
      reject.disabled = true;
      try {
        const decision = await api.post(`/approvals/${api.segment(request.id)}/decision`, { approve: approved, note: note.value }, context.signal);
        result.textContent = `${approved ? 'Approved' : 'Rejected'}. ${dispositionText(decision.disposition)}`;
        note.disabled = true;
        context.notify(`The decision is recorded: ${label(decision.request.status)}.`, 'ok');
      } catch (error) {
        approve.disabled = false;
        reject.disabled = false;
        context.fail(error);
      }
    }

    approve.addEventListener('click', () => decide(true));
    reject.addEventListener('click', () => decide(false));
    const action = request.action;
    return el(
      'section',
      { class: 'panel', 'aria-label': `Approval request for ${label(action.kind)}` },
      el('h2', { text: `${label(action.kind)}${action.dry_run ? ' (dry run)' : ''}` }),
      facts([
        ['Target', entityLabel(action.target)],
        ['Reason', action.reason],
        ['Requested by', `${request.requested_by.id} (${label(request.requested_by.kind)})`],
        ['Requested', time(request.requested_at)],
        ['Policy', (request.decision.reasons || []).join(' ')],
        ['Incident', action.incident_id ? el('a', { href: incidentRoute(action.incident_id), text: action.incident_id }) : null],
        ['Identifier', el('span', { class: 'mono', text: request.id })],
      ]),
      field('Note (optional)', note),
      el('div', { class: 'actions' }, approve, reject),
      result,
    );
  }

  async function load() {
    context.notify('Loading the approval requests.');
    try {
      const page = await api.get('/approvals', { limit: 100 }, context.signal);
      clear(list);
      for (const request of page.items) {
        list.append(card(request));
      }
      count.textContent =
        page.total === 0 ? 'No action waits for approval.' : `${page.total} actions wait for approval. The oldest request is first.`;
      context.notify('');
    } catch (error) {
      context.fail(error);
    }
  }

  context.main.append(
    el('h1', { text: 'Approvals' }),
    el('div', { class: 'toolbar' }, el('button', { type: 'button', text: 'Refresh', on: { click: load } })),
    count,
    list,
  );
  load();
}
