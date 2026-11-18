// Text formats of the AEGIS console.

import { el } from './dom.js';

// Returns the display text of an enumeration value, for example "false positive".
// A plugin value is an object with one key, for example { custom: "name" }.
export function label(value) {
  if (value === undefined || value === null) {
    return '';
  }
  if (typeof value === 'object') {
    const [key, inner] = Object.entries(value)[0] || ['unknown', ''];
    return `${key}: ${typeof inner === 'object' ? JSON.stringify(inner) : inner}`;
  }
  return String(value).replaceAll('_', ' ');
}

// Returns a value as a CSS class token. Other characters are removed.
export function token(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9_-]/g, '');
}

// Returns a time in the format of the browser, or the original text if it is not a time.
export function time(value) {
  if (!value) {
    return '';
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

// Returns the first characters of a hash or an identifier.
export function short(value, length = 12) {
  const text = String(value || '');
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

// Returns a JSON document with indentation.
export function pretty(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

// Returns the type and the name of an entity.
export function entityLabel(entity) {
  const name = entity.name && entity.name !== entity.id ? `${entity.name} (${entity.id})` : entity.id;
  return `${label(entity.kind)} ${name}`;
}

// Returns the Defensive Graph identifier of an entity: "<kind>:<id>".
export function entityNodeId(entity) {
  return `${entity.kind}:${entity.id}`;
}

// Makes a badge. `kind` selects the color, for example "severity-high".
export function badge(text, kind) {
  return el('span', { class: kind ? `badge ${token(kind)}` : 'badge', text: label(text) });
}

// Makes the badge for a severity.
export function severityBadge(severity) {
  return badge(severity, `severity-${token(severity)}`);
}

// Returns the route of a graph node.
export function graphRoute(nodeId) {
  return `#/graph/${encodeURIComponent(nodeId)}`;
}

// Returns the route of an incident.
export function incidentRoute(id) {
  return `#/incidents/${encodeURIComponent(id)}`;
}
