// The Defensive Graph: start at a node and walk its neighbors.

import * as api from '../api.js';
import { clear, el, facts, field, svg } from '../dom.js';
import { badge, graphRoute, label, pretty, short, time, token } from '../format.js';

const KINDS = ['incident', 'identity', 'asset', 'alert', 'finding'];
const DIRECTIONS = ['both', 'outgoing', 'incoming'];
const MAX_DRAWN = 24;
const WIDTH = 720;
const HEIGHT = 460;

function open(nodeId) {
  window.location.hash = graphRoute(nodeId);
}

// Makes one node of the drawing. A node that is not the center is a link to its own view.
function drawNode(node, x, y, isCenter) {
  const group = svg(
    'g',
    {
      class: `node kind-${token(node.kind)}${isCenter ? ' center' : ''}`,
      transform: `translate(${x.toFixed(1)} ${y.toFixed(1)})`,
    },
    svg('title', { text: `${label(node.kind)}: ${node.label} (${node.id})` }),
    svg('circle', { r: isCenter ? 22 : 16 }),
    svg('text', { y: isCenter ? 40 : 32, text: short(node.label, 22) }),
  );
  if (!isCenter) {
    group.setAttribute('tabindex', '0');
    group.setAttribute('role', 'link');
    group.setAttribute('aria-label', `Open ${label(node.kind)} ${node.label}`);
    group.addEventListener('click', () => open(node.id));
    group.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        open(node.id);
      }
    });
  }
  return group;
}

// Draws the node in the middle and its neighbors on an ellipse around it.
function draw(center, neighbors) {
  const drawn = neighbors.slice(0, MAX_DRAWN);
  const cx = WIDTH / 2;
  const cy = HEIGHT / 2 - 10;
  const lines = [];
  const nodes = [];
  drawn.forEach((node, index) => {
    const angle = (2 * Math.PI * index) / drawn.length - Math.PI / 2;
    // Two rings keep the labels of many neighbors apart.
    const ring = drawn.length > 12 && index % 2 === 1 ? 0.62 : 1;
    const x = cx + Math.cos(angle) * (WIDTH / 2 - 90) * ring;
    const y = cy + Math.sin(angle) * (HEIGHT / 2 - 60) * ring;
    lines.push(svg('line', { x1: cx, y1: cy, x2: x.toFixed(1), y2: y.toFixed(1) }));
    nodes.push(drawNode(node, x, y, false));
  });
  return svg(
    'svg',
    {
      class: 'graph',
      viewBox: `0 0 ${WIDTH} ${HEIGHT}`,
      role: 'group',
      'aria-label': `Node ${center.label} and ${drawn.length} of its neighbors`,
    },
    lines,
    nodes,
    drawNode(center, cx, cy, true),
  );
}

export function graphView(context, nodeId) {
  const idInput = el('input', { type: 'text', name: 'node', size: '36', autocomplete: 'off', spellcheck: 'false', value: nodeId || '' });
  const kindSelect = el('select', { name: 'kind' }, KINDS.map((kind) => el('option', { value: kind, text: label(kind) })));
  const directionSelect = el('select', { name: 'direction' }, DIRECTIONS.map((direction) => el('option', { value: direction, text: label(direction) })));
  const relationInput = el('input', { type: 'text', name: 'relation', size: '18', autocomplete: 'off', spellcheck: 'false' });
  const results = el('div');

  function nodeButton(node) {
    return el('button', { type: 'button', class: 'link', text: `${label(node.kind)}: ${node.label}`, on: { click: () => open(node.id) } });
  }

  async function listKind() {
    context.notify('Loading the nodes.');
    try {
      const page = await api.get('/graph/nodes', { kind: kindSelect.value, limit: 100 }, context.signal);
      clear(results).append(
        el('h2', { text: `Nodes of the type ${label(kindSelect.value)}, newest first` }),
        page.items.length === 0
          ? el('p', { class: 'muted', text: 'The graph has no node of this type.' })
          : el('ul', { class: 'plain' }, page.items.map((node) => el('li', null, nodeButton(node), el('span', { class: 'muted', text: ` ${time(node.updated_at)}` })))),
      );
      context.notify(`${page.items.length} nodes.`);
    } catch (error) {
      context.fail(error);
    }
  }

  async function showNode() {
    context.notify('Loading the node.');
    try {
      const data = await api.get(
        `/graph/nodes/${api.segment(nodeId)}/neighbors`,
        { direction: directionSelect.value, relation: relationInput.value.trim(), limit: 100 },
        context.signal,
      );
      const node = data.node;
      const properties = node.properties && Object.keys(node.properties).length > 0 ? el('pre', { text: pretty(node.properties) }) : null;
      clear(results).append(
        el('h2', null, badge(node.kind), ` ${node.label}`),
        facts([
          ['Identifier', el('span', { class: 'mono', text: node.id })],
          ['Last change', time(node.updated_at)],
          ['Properties', properties],
        ]),
        draw(node, data.items),
        el('h3', { text: `Neighbors: ${data.items.length} of ${data.total}` }),
        data.items.length === 0
          ? el('p', { class: 'muted', text: 'The node has no neighbor with these filters.' })
          : el('ul', { class: 'plain' }, data.items.map((neighbor) => el('li', null, nodeButton(neighbor)))),
      );
      context.notify(data.items.length > MAX_DRAWN ? `The drawing shows the first ${MAX_DRAWN} neighbors. The list shows all.` : '');
    } catch (error) {
      if (error instanceof api.ApiError && error.status === 404) {
        clear(results).append(el('p', { text: 'The graph has no node with this identifier.' }));
        context.notify('');
      } else {
        context.fail(error);
      }
    }
  }

  context.main.append(
    el('h1', { text: 'Defensive Graph' }),
    el(
      'form',
      {
        class: 'toolbar',
        on: {
          submit: (event) => {
            event.preventDefault();
            const value = idInput.value.trim();
            if (!value) {
              return;
            }
            if (value === nodeId) {
              showNode();
            } else {
              open(value);
            }
          },
        },
      },
      field('Node identifier', idInput),
      field('Direction', directionSelect),
      field('Relation (optional)', relationInput),
      el('button', { type: 'submit', class: 'primary', text: 'Open the node' }),
    ),
    el(
      'form',
      {
        class: 'toolbar',
        on: {
          submit: (event) => {
            event.preventDefault();
            listKind();
          },
        },
      },
      field('Node type', kindSelect),
      el('button', { type: 'submit', text: 'List the nodes' }),
    ),
    results,
  );

  if (nodeId) {
    showNode();
  } else {
    results.append(
      el('p', {
        class: 'muted',
        text: 'Open a node by its identifier, list the nodes of one type, or start from an incident or an entity on the incident page.',
      }),
    );
  }
}
