// Full-text search over backup .conf files. Every match is reported with its
// line number and the config path it sits in (config X › edit "y" › ...).
// Secret values are redacted before matching, so they can neither be shown nor found.
const fs = require('node:fs');
const { SECRET_KEY } = require('./extract');

const MAX_LINE = 400;

// Counts unescaped double quotes; an odd count opens or closes a multi-line value.
function quoteCount(s) {
  let n = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\') i++;
    else if (s[i] === '"') n++;
  }
  return n;
}

const unquote = (s) => s.replace(/^"(.*)"$/, '$1');

const MAX_AFTER = 100;

// Cuts very long lines (base64 images, certificates) to a window around the first match.
function clip(text, ranges) {
  if (text.length <= MAX_LINE) return { text, ranges };
  const start = ranges.length ? Math.max(0, ranges[0][0] - 80) : 0;
  const end = start + MAX_LINE;
  const pre = start ? '…' : '';
  return {
    text: pre + text.slice(start, end) + (end < text.length ? '…' : ''),
    ranges: ranges
      .filter(([s]) => s >= start && s < end)
      .map(([s, e]) => [s - start + pre.length, Math.min(e, end) - start + pre.length]),
  };
}

// Builds a function returning [start, end] ranges of every match in a line.
function matcher(q, { regex, caseSensitive }) {
  if (regex) {
    if (q.length > 200) throw new Error('Regex too long');
    let re;
    try {
      re = new RegExp(q, caseSensitive ? 'g' : 'gi');
    } catch (err) {
      throw new Error(`Invalid regex: ${err.message}`);
    }
    return (line) => {
      const out = [];
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(line))) {
        if (m[0] === '') { re.lastIndex++; continue; }
        out.push([m.index, m.index + m[0].length]);
      }
      return out;
    };
  }
  // Literal search: every character, including " / * $ \ and spaces, matches itself.
  const needle = caseSensitive ? q : q.toLowerCase();
  return (line) => {
    const hay = caseSensitive ? line : line.toLowerCase();
    const out = [];
    for (let i = hay.indexOf(needle); i !== -1; i = hay.indexOf(needle, i + needle.length)) {
      out.push([i, i + needle.length]);
    }
    return out;
  };
}

// Searches one file. `within` limits matches to config paths containing that text;
// `after` adds that many following lines to each shown match (like grep -A).
function searchFile(file, match, { within, limit, after }) {
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  const texts = []; // lines after redaction, for context
  const stack = [];
  const matches = [];
  let count = 0;
  let inQuote = false;
  let secretCont = false;

  for (let i = 0; i < lines.length; i++) {
    let text = lines[i].replace(/\r$/, '');
    let popAfter = 0;

    if (inQuote) {
      // Continuation of a multi-line quoted value (certificates, scripts, ...).
      if (quoteCount(text) % 2) inQuote = false;
      if (secretCont) text = '    <redacted>';
      if (!inQuote) secretCont = false;
    } else {
      const t = text.trim();
      const sp = t.indexOf(' ');
      const kw = sp === -1 ? t : t.slice(0, sp);
      const rest = sp === -1 ? '' : t.slice(sp + 1);
      if (kw === 'config') stack.push({ t: 'config', v: rest });
      else if (kw === 'edit') stack.push({ t: 'edit', v: unquote(rest) });
      else if (kw === 'next') popAfter = stack.at(-1)?.t === 'edit' ? 1 : 0;
      else if (kw === 'end') {
        // `config vdom` / `edit X` blocks are closed by `end` without a `next`.
        popAfter = stack.at(-1)?.t === 'edit' && stack.length > 1 ? 2 : stack.length ? 1 : 0;
      } else if (kw === 'set') {
        const [key, ...val] = rest.split(' ');
        const isSecret = SECRET_KEY.test(key) || /^"?ENC /.test(val.join(' '));
        if (quoteCount(t) % 2) inQuote = true;
        if (isSecret) {
          text = `${text.slice(0, text.indexOf('set'))}set ${key} <redacted>`;
          secretCont = inQuote;
        }
      } else if (quoteCount(t) % 2) {
        inQuote = true;
      }
    }

    texts.push(text);
    const ranges = match(text);
    if (ranges.length) {
      const pathText = stack.map((p) => p.v).join(' ').toLowerCase();
      if (!within || pathText.includes(within)) {
        count++;
        if (matches.length < limit) matches.push({ line: i + 1, ...clip(text, ranges), path: stack.map((p) => ({ ...p })) });
      }
    }
    stack.length -= Math.min(popAfter, stack.length);
  }
  // Context stops before the next shown match, so no line is listed twice.
  if (after) matches.forEach((m, k) => {
    const end = Math.min(texts.length, m.line + after, k + 1 < matches.length ? matches[k + 1].line - 1 : Infinity);
    m.after = [];
    for (let j = m.line; j < end; j++) m.after.push({ line: j + 1, ...clip(texts[j], match(texts[j])) });
  });
  return { count, matches };
}

// Searches the given files; stops collecting (but keeps counting) after `limit` matches.
function search(files, q, { regex = false, caseSensitive = false, within = '', after = 0, limit = 500 } = {}) {
  if (!q) throw new Error('Search text is required');
  const match = matcher(q, { regex, caseSensitive });
  after = Math.min(MAX_AFTER, Math.max(0, Math.floor(after) || 0));
  const results = [];
  let total = 0;
  let shown = 0;
  for (const f of files) {
    const r = searchFile(f.path, match, { within: within.toLowerCase(), limit: limit - shown, after });
    total += r.count;
    shown += r.matches.length;
    if (r.count) results.push({ file: f.name, count: r.count, matches: r.matches });
  }
  return { total, shown, truncated: shown < total, scanned: files.length, files: results };
}

module.exports = { search };
