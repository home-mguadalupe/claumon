// Parser for FortiOS configuration files (backup format).
//
// Produces a tree of plain objects:
//   config node : { type: 'config', path, settings: {}, entries: [], configs: [] }
//   edit entry  : { type: 'edit', name, settings: {}, configs: [] }
// `settings` maps each `set` key to an array of its values (strings).

// Splits the file into statements (arrays of words). Quoted values may span lines.
function* statements(text) {
  let words = [];
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i];
    if (c === '\n') {
      if (words.length) yield words;
      words = [];
      i++;
    } else if (c === ' ' || c === '\t' || c === '\r') {
      i++;
    } else if (c === '#' && words.length === 0) {
      // Header / comment lines (#config-version=..., #buildno=...).
      const end = text.indexOf('\n', i);
      yield ['#', text.slice(i + 1, end === -1 ? n : end)];
      i = end === -1 ? n : end + 1;
    } else if (c === '"') {
      let s = '';
      i++;
      while (i < n && text[i] !== '"') {
        if (text[i] === '\\' && i + 1 < n) i++;
        s += text[i++];
      }
      words.push(s);
      i++;
    } else {
      let j = i;
      while (j < n && !' \t\r\n'.includes(text[j])) j++;
      words.push(text.slice(i, j));
      i = j;
    }
  }
  if (words.length) yield words;
}

const newConfig = (path) => ({ type: 'config', path, settings: {}, entries: [], configs: [] });

function parse(text) {
  const root = newConfig('');
  const header = [];
  const stack = [root];
  const top = () => stack[stack.length - 1];

  for (const [kw, ...args] of statements(text)) {
    const cur = top();
    switch (kw) {
      case '#':
        header.push(args[0]);
        break;
      case 'config': {
        const node = newConfig(args.join(' '));
        cur.configs.push(node);
        stack.push(node);
        break;
      }
      case 'edit': {
        const entry = { type: 'edit', name: args[0], settings: {}, configs: [] };
        cur.entries.push(entry);
        stack.push(entry);
        break;
      }
      case 'next':
        if (cur.type === 'edit') stack.pop();
        break;
      case 'end':
        // `config vdom` / `edit X` blocks are closed by `end` without a `next`.
        if (cur.type === 'edit' && stack.length > 2) stack.pop();
        if (stack.length > 1) stack.pop();
        break;
      case 'set':
        cur.settings[args[0]] = args.slice(1);
        break;
      // `unset`, `append`, etc. carry no value worth keeping in a backup.
    }
  }
  return { header, root };
}

// Flattens an entry/config node into a plain object (single values unwrapped,
// nested config blocks keyed by path) - convenient for jsonb storage.
function toPlain(node) {
  const out = {};
  for (const [k, v] of Object.entries(node.settings)) out[k] = v.length === 1 ? v[0] : v;
  for (const c of node.configs) {
    out[c.path] = c.entries.length
      ? Object.fromEntries(c.entries.map((e) => [e.name, toPlain(e)]))
      : toPlain(c);
  }
  return out;
}

module.exports = { parse, toPlain };
