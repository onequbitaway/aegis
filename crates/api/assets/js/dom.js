// DOM helpers of the AEGIS console.
//
// All data from the API is untrusted. These helpers make each node with createElement
// and set each text with textContent. They never read markup from a string.

const SVG_NAMESPACE = 'http://www.w3.org/2000/svg';

function setProperties(node, properties) {
  for (const [name, value] of Object.entries(properties || {})) {
    if (value === undefined || value === null || value === false) {
      continue;
    }
    if (name === 'text') {
      node.textContent = String(value);
    } else if (name === 'on') {
      for (const [event, handler] of Object.entries(value)) {
        node.addEventListener(event, handler);
      }
    } else if (/^on/i.test(name)) {
      throw new Error('Use the "on" property for event handlers.');
    } else if (name === 'href' && !String(value).startsWith('#')) {
      // The console links only to its own views.
      throw new Error('A link must point to a view of the console.');
    } else {
      node.setAttribute(name, value === true ? '' : String(value));
    }
  }
}

function appendChildren(node, children) {
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) {
      continue;
    }
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
}

// Makes an HTML element. `properties.text` sets the text. `properties.on` adds listeners.
export function el(tag, properties, ...children) {
  const node = document.createElement(tag);
  setProperties(node, properties);
  appendChildren(node, children);
  return node;
}

// Makes an SVG element.
export function svg(tag, properties, ...children) {
  const node = document.createElementNS(SVG_NAMESPACE, tag);
  setProperties(node, properties);
  appendChildren(node, children);
  return node;
}

// Removes all children of a node.
export function clear(node) {
  node.replaceChildren();
  return node;
}

// Makes a table. `columns` are header texts. `rows` are arrays of cell contents.
export function table(caption, columns, rows) {
  return el(
    'div',
    { class: 'table-wrap' },
    el(
      'table',
      null,
      el('caption', { text: caption }),
      el('thead', null, el('tr', null, columns.map((column) => el('th', { scope: 'col', text: column })))),
      el('tbody', null, rows.map((cells) => el('tr', null, cells.map((cell) => el('td', null, cell))))),
    ),
  );
}

// Makes a list of label and value pairs. A pair with no value is left out.
export function facts(pairs) {
  const list = el('dl', { class: 'facts' });
  for (const [label, value] of pairs) {
    if (value === undefined || value === null || value === '') {
      continue;
    }
    list.append(el('dt', { text: label }), el('dd', null, value));
  }
  return list;
}

// Makes a labelled form control.
export function field(label, control) {
  return el('label', { class: 'field' }, el('span', { text: label }), control);
}
