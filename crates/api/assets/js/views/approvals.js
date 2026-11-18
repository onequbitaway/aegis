// The approvals queue: approve or reject a gated action with a note.
// The timed reverts: confirm a containment action, or revert it now.

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

// One timed revert: an action that AEGIS reverts at a set time, unless a person confirms it.
function revertCard(context, pending, reload) {
  const confirm = el('button', { type: 'button', class: 'primary', text: 'Confirm the action' });
  const revertNow = el('button', { type: 'button', class: 'danger', text: 'Revert now' });
  const result = el('p', { role: 'status' });

  async function decide(operation, question, done) {
    if (!window.confirm(question)) {
      return;
    }
    confirm.disabled = true;
    revertNow.disabled = true;
    try {
      const answer = await api.post(`/reverts/${api.segment(pending.action_id)}/${operation}`, {}, context.signal);
      result.textContent = done(answer);
      context.notify('The decision is recorded.', 'ok');
      reload();
    } catch (error) {
      confirm.disabled = false;
      revertNow.disabled = false;
      context.fail(error);
    }
  }

  confirm.addEventListener('click', () =>
    decide('confirm', 'Confirm this action? The containment stays. AEGIS does not revert it.', () => 'Confirmed. The containment stays.'),
  );
  revertNow.addEventListener('click', () =>
    decide('cancel', 'Revert this action now? The revert goes through the policy.', (answer) => `Revert requested. ${dispositionText(answer.disposition)}`),
  );
  return el(
    'section',
    { class: 'panel', 'aria-label': `Timed revert of ${label(pending.kind)}` },
    el('h2', { text: `${label(pending.kind)}: revert at ${time(pending.due_at)}` }),
    facts([
      ['Target', entityLabel(pending.target)],
      ['Requested by', pending.requested_by],
      ['Revert time', time(pending.due_at)],
      ['State', label(pending.state)],
      ['Failed attempts', pending.attempts ? String(pending.attempts) : null],
      ['Last error', pending.last_error],
      ['Waits for approval', pending.approval_id ? el('span', { class: 'mono', text: pending.approval_id }) : null],
      ['Incident', pending.incident_id ? el('a', { href: incidentRoute(pending.incident_id), text: pending.incident_id }) : null],
      ['Action', el('span', { class: 'mono', text: pending.action_id })],
    ]),
    el('div', { class: 'actions' }, confirm, revertNow),
    result,
  );
}

export function approvalsView(context) {
  const list = el('div', { class: 'cards' });
  const count = el('p', { class: 'muted' });
  const reverts = el('div', { class: 'cards' });
  const revertCount = el('p', { class: 'muted' });

  async function loadReverts() {
    try {
      const page = await api.get('/reverts', { limit: 100 }, context.signal);
      clear(reverts);
      for (const pending of page.items) {
        reverts.append(revertCard(context, pending, loadReverts));
      }
      if (!page.enabled) {
        revertCount.textContent = 'The timed revert is off in this process.';
      } else if (page.total === 0) {
        revertCount.textContent = 'No action waits for a timed revert.';
      } else {
        revertCount.textContent = `${page.total} actions have a timed revert. The earliest revert time is first. AEGIS reverts an action at its time, unless a person confirms it.`;
      }
    } catch (error) {
      context.fail(error);
    }
  }

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
    await loadReverts();
  }

  context.main.append(
    el('h1', { text: 'Approvals' }),
    el('div', { class: 'toolbar' }, el('button', { type: 'button', text: 'Refresh', on: { click: load } })),
    count,
    list,
    el('h2', { text: 'Timed reverts' }),
    revertCount,
    reverts,
  );
  load();
}
