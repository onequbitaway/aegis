// The audit log: the records and the state of the hash chain.

import * as api from '../api.js';
import { clear, el, facts, table } from '../dom.js';
import { badge, label, pretty, short, time } from '../format.js';

const PAGE_SIZE = 50;

export function auditView(context) {
  const chain = el('div', { class: 'panel' }, el('p', { class: 'muted', text: 'The chain is not checked yet.' }));
  const records = el('div');
  const older = el('button', { type: 'button', text: 'Older records' });
  const newer = el('button', { type: 'button', text: 'Newer records' });
  const position = el('span', { class: 'muted' });
  let first = 1;
  let head = 0;

  async function verify() {
    clear(chain).append(el('p', { class: 'muted', text: 'Checking the hash chain.' }));
    try {
      const report = await api.get('/audit/verification', null, context.signal);
      clear(chain).append(
        el('h2', { text: 'Hash chain' }),
        facts([
          ['State', report.valid ? badge('valid', 'good') : badge('not valid', 'bad')],
          ['Records checked', String(report.checked)],
          ['First record that is not correct', report.first_invalid_sequence === undefined ? null : String(report.first_invalid_sequence)],
          ['Reason', report.reason],
        ]),
      );
    } catch (error) {
      clear(chain).append(el('p', { class: 'muted', text: 'The check did not complete.' }));
      context.fail(error);
    }
  }

  function row(record) {
    const detail = el(
      'details',
      null,
      el('summary', { text: record.summary }),
      facts([
        ['Identifier', el('span', { class: 'mono', text: record.id })],
        ['Hash', el('span', { class: 'mono', text: record.hash })],
        ['Previous hash', el('span', { class: 'mono', text: record.prev_hash })],
        ['Evidence', (record.evidence || []).map((item) => `${label(item.kind)} ${item.id}`).join(', ')],
      ]),
      record.payload === null || record.payload === undefined ? null : el('pre', { text: pretty(record.payload) }),
    );
    return [String(record.sequence), time(record.time), badge(record.kind), record.actor, detail, el('span', { class: 'mono', text: short(record.hash) })];
  }

  async function load() {
    context.notify('Loading the audit records.');
    try {
      const page = await api.get('/audit', { from_sequence: first, limit: PAGE_SIZE }, context.signal);
      clear(records);
      if (page.items.length === 0) {
        records.append(el('p', { text: 'The audit log has no record in this range.' }));
        position.textContent = '';
      } else {
        // The API gives the oldest record first. The table shows the newest record first.
        records.append(table('Audit records, newest first', ['Sequence', 'Time', 'Type', 'Actor', 'Summary', 'Hash'], page.items.slice().reverse().map(row)));
        const range = `Records ${page.items[0].sequence} to ${page.items[page.items.length - 1].sequence}`;
        position.textContent = head > 0 ? `${range} of ${head}.` : `${range}.`;
      }
      older.disabled = first <= 1;
      // A full page can have a next page.
      newer.disabled = page.next_sequence === null;
      context.notify('');
    } catch (error) {
      context.fail(error);
    }
  }

  async function loadNewest() {
    try {
      const status = await api.get('/status', null, context.signal);
      head = status.audit.head ? status.audit.head.sequence : 0;
    } catch (error) {
      // A principal that cannot read the status still can read the log from the start.
      if (!(error instanceof api.ApiError && error.status === 403)) {
        context.fail(error);
        return;
      }
      head = 0;
    }
    first = Math.max(1, head - PAGE_SIZE + 1);
    await load();
  }

  older.addEventListener('click', () => {
    first = Math.max(1, first - PAGE_SIZE);
    load();
  });
  newer.addEventListener('click', () => {
    first += PAGE_SIZE;
    load();
  });

  context.main.append(
    el('h1', { text: 'Audit log' }),
    el(
      'div',
      { class: 'toolbar' },
      el('button', { type: 'button', text: 'Check the chain', on: { click: verify } }),
      el('button', { type: 'button', text: 'Show the newest records', on: { click: loadNewest } }),
      older,
      newer,
      position,
    ),
    chain,
    records,
  );
  verify();
  loadNewest();
}
