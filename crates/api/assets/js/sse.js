// A parser for server-sent events.
//
// The console reads the live feed with fetch, because EventSource cannot send the bearer
// token in a header. This parser turns the text of the response into events.

const MAX_BUFFER_CHARACTERS = 4 * 1024 * 1024;

export class SseParser {
  constructor() {
    this.buffer = '';
    this.type = '';
    this.data = [];
  }

  // Adds a part of the response. Returns the events that are complete.
  push(chunk) {
    this.buffer += chunk;
    const events = [];
    for (;;) {
      const match = /\r\n|\n|\r/.exec(this.buffer);
      if (!match) {
        break;
      }
      // A carriage return at the end can be the first half of a line end.
      if (match[0] === '\r' && match.index === this.buffer.length - 1) {
        break;
      }
      const line = this.buffer.slice(0, match.index);
      this.buffer = this.buffer.slice(match.index + match[0].length);
      const event = this.line(line);
      if (event) {
        events.push(event);
      }
    }
    if (this.buffer.length > MAX_BUFFER_CHARACTERS) {
      // A line that is too long is not an event of AEGIS. Drop it.
      this.buffer = '';
      this.type = '';
      this.data = [];
    }
    return events;
  }

  line(line) {
    if (line === '') {
      const event = this.data.length > 0 ? { type: this.type || 'message', data: this.data.join('\n') } : null;
      this.type = '';
      this.data = [];
      return event;
    }
    if (line.startsWith(':')) {
      return null;
    }
    const colon = line.indexOf(':');
    const name = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? '' : line.slice(colon + 1);
    if (value.startsWith(' ')) {
      value = value.slice(1);
    }
    if (name === 'event') {
      this.type = value;
    } else if (name === 'data') {
      this.data.push(value);
    }
    return null;
  }
}
