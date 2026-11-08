// Explains how to fix the risky firewall policies the audit found in a backup and which to
// fix first. Read-only guidance; nothing here touches a firewall.
const { parse } = require('./fgtparse');
const { SEVERITIES, entriesOf, one, list, parseHeader, splitVdoms } = require('./audit');

const POLICY_CHECKS = new Set(['policy-any-any', 'policy-service-all', 'policy-wan-inbound-any', 'policy-nolog',
  'policy-shadowed', 'policy-wan-noprofile', 'policy-outbound-noprofile']);
const EXPOSED_CHECKS = new Set(['policy-wan-inbound-any', 'policy-wan-noprofile']);

// Each field is mentioned only where the policy really has the wildcard.
const BROAD_FIELDS = [
  { key: 'srcaddr', any: 'all', label: 'Source', placeholder: '<source addresses>' },
  { key: 'srcaddr6', any: 'all', label: 'Source (IPv6)', placeholder: '<IPv6 source addresses>' },
  { key: 'dstaddr', any: 'all', label: 'Destination', placeholder: '<destination addresses>' },
  { key: 'dstaddr6', any: 'all', label: 'Destination (IPv6)', placeholder: '<IPv6 destination addresses>' },
  { key: 'service', any: 'ALL', label: 'Service', placeholder: '<required services>' },
];
const NARROW_SCOPE = {
  'policy-any-any': ['srcaddr', 'srcaddr6', 'dstaddr', 'dstaddr6', 'service'],
  'policy-service-all': ['service'],
  'policy-wan-inbound-any': ['srcaddr', 'srcaddr6'],
};

const PROFILES = {
  'ips-sensor': { label: 'IPS sensor', path: 'ips sensor' },
  'av-profile': { label: 'Antivirus', path: 'antivirus profile' },
  'webfilter-profile': { label: 'Web filter', path: 'webfilter profile' },
  'dnsfilter-profile': { label: 'DNS filter', path: 'dnsfilter profile' },
  'application-list': { label: 'Application control', path: 'application list' },
};

const editing = (id, ...lines) => ['config firewall policy', `edit ${id}`, ...lines, 'next', 'end'];
const cliValue = (v) => (/\s/.test(v) ? `"${v}"` : v);
// The command that puts a setting back as it is in the backup.
const restore = (p, key) => (p.settings[key] ? `set ${key} ${p.settings[key].map(cliValue).join(' ')}` : `unset ${key}`);

// How to fix one policy. A shadowed policy gets no traffic until that is settled, so that
// comes first; then the steps run from least to most likely to disturb traffic.
function stepsFor(p, findings, node) {
  const id = p.name;
  const openPolicy = `Go to **Policy & Objects › Firewall Policy** and open policy ${id}.`;
  const hitCount = `the **Hit Count** and **Last Used** columns for policy ${id} in **Policy & Objects › Firewall Policy**`;
  const sessions = `\`diagnose sys session filter policy ${id}\` then \`diagnose sys session list\``;
  const has = (check) => findings.some((f) => f.check === check);
  const steps = [];

  const by = findings.find((f) => f.check === 'policy-shadowed')?.detail.match(/#(\d+)/)?.[1];
  if (by) {
    const order = entriesOf(node, 'firewall policy').map((e) => e.name);
    const prev = order[order.indexOf(id) - 1];
    steps.push({
      title: 'If this policy is not needed: disable it', impact: 'safe',
      note: `Policy #${by} above already takes all of its traffic, so traffic should not change. Delete it later once you are sure.`,
      before: [`Confirm it really gets no traffic: ${hitCount} should show no recent hits.`, 'Ask the owner why it exists. It may record an intent that the rule order defeats.'],
      gui: ['Go to **Policy & Objects › Firewall Policy**.', `Right-click policy ${id}, then **Set Status › Disable**.`],
      commands: editing(id, 'set status disable'),
      verify: [`Policy ${id} shows as disabled.`, 'Applications that use this path keep working.'],
      undo: editing(id, restore(p, 'status')),
    });
    steps.push({
      title: `If this policy should apply: move it above #${by}`, impact: 'risky', alternative: true,
      note: `It starts matching traffic that policy #${by} handles today.`,
      before: [`Compare both policies: action, NAT, security profiles and logging can all differ once traffic moves from #${by} to #${id}.`, `Fix any other issue on policy ${id} first, because it will start carrying traffic.`],
      gui: ['Go to **Policy & Objects › Firewall Policy**, in the **By Sequence** view.', `Drag policy ${id} above policy ${by}.`],
      commands: ['config firewall policy', `move ${id} before ${by}`, 'end'],
      verify: [`The hit count of policy ${id} starts rising.`, `Sessions match it: ${sessions}.`],
      undo: ['config firewall policy', `move ${id} after ${prev}`, 'end'],
    });
  }

  if (has('policy-nolog')) {
    steps.push({
      title: 'Turn on traffic logging', impact: 'safe',
      note: 'No effect on traffic, only more log volume. Do this early: the logs show what the policy really carries.',
      before: ['Check there is room for the extra logs on the disk, FortiAnalyzer or syslog server.'],
      gui: [openPolicy, 'Under **Logging Options**, enable **Log Allowed Traffic** and choose **All Sessions**.', 'Click **OK**.'],
      commands: editing(id, 'set logtraffic all'),
      verify: [`New entries for policy ${id} appear in **Log & Report › Forward Traffic**.`],
      undo: editing(id, restore(p, 'logtraffic')),
    });
  }

  const keys = has('policy-outbound-noprofile') ? Object.keys(PROFILES) : has('policy-wan-noprofile') ? ['ips-sensor'] : [];
  if (keys.length) {
    steps.push({
      title: 'Add security profiles', impact: 'review',
      note: 'Inspection can block traffic and adds CPU load. Consider a monitor-only profile first.',
      before: ['Check CPU and memory headroom with `get system performance status`.', 'Check the licences and signatures are current in **System › FortiGuard**.', 'Encrypted traffic is only partly inspected without deep inspection: decide which SSL inspection profile this policy needs.'],
      gui: [openPolicy, 'Under **Security Profiles**, enable the profiles you need and select one for each.', 'Choose the **SSL Inspection** profile, then click **OK**.'],
      commands: editing(id, 'set utm-status enable', ...keys.map((k) => `set ${k} <profile>`)),
      available: keys.map((k) => ({ label: PROFILES[k].label, names: entriesOf(node, PROFILES[k].path).map((e) => e.name) })),
      verify: [`\`show firewall policy ${id}\` lists the profiles.`, 'Events appear in **Log & Report › Security Events**.', 'Applications behind this policy still work, and CPU stays at normal levels.'],
      undo: editing(id, restore(p, 'utm-status'), ...keys.map((k) => restore(p, k))),
    });
  }

  const scope = new Set(findings.flatMap((f) => NARROW_SCOPE[f.check] || []));
  const broad = BROAD_FIELDS.filter((f) => scope.has(f.key) && list(p, f.key).includes(f.any));
  if (broad.length) {
    steps.push({
      title: 'Narrow the scope', impact: 'risky',
      note: 'Traffic outside the new scope stops matching this policy.',
      before: [
        `Collect a representative period of logs, long enough to include monthly or rare jobs. In **Log & Report › Forward Traffic**, filter on policy ID ${id}.`,
        'List the real sources, destinations and services, and create objects or groups for them.',
        `Safer rollout: add a narrow policy above this one, then watch ${hitCount}. When it stops rising, narrow or disable this policy.`,
      ],
      gui: [openPolicy, `Replace the wildcard in: ${broad.map((f) => f.label).join(', ')}.`, 'Click **OK**.'],
      commands: editing(id, ...broad.map((f) => `set ${f.key} ${f.placeholder}`)),
      verify: [`Only the expected traffic matches: ${sessions}.`, 'Look for new denies from the affected networks in **Log & Report › Forward Traffic**.', 'Sessions that were already open may continue until they end, so retest with new connections.'],
      undo: editing(id, ...broad.map((f) => restore(p, f.key))),
    });
  }
  return steps;
}

// Higher comes first: severity, then exposure to the internet, then how many problems it has.
function priorityOf(severity, exposed, findingCount) {
  return (SEVERITIES.length - SEVERITIES.indexOf(severity)) * 100 + (exposed ? 50 : 0) + Math.min(findingCount, 49);
}

// Risky policies of a backup, most urgent first. `result` is its audit.
function analyze(text, result) {
  const { header, root } = parse(text);
  const { multiVdom } = parseHeader(header);
  const { vdoms } = splitVdoms(root, multiVdom);
  const byVdom = new Map(vdoms.map((v) => [v.name, v.node]));

  const grouped = new Map();
  for (const f of result.findings) {
    if (!POLICY_CHECKS.has(f.check)) continue;
    const id = String(f.object).match(/^#(\d+)/)?.[1];
    if (!id) continue;
    const key = `${f.vdom}|${id}`;
    if (!grouped.has(key)) grouped.set(key, { vdom: f.vdom, id, findings: [] });
    grouped.get(key).findings.push({ check: f.check, severity: f.severity, title: f.title, detail: f.detail });
  }

  const inVdom = (vdom, commands) => ['config vdom', `edit ${vdom}`, ...commands, 'end'];
  const policies = [];
  for (const g of grouped.values()) {
    const node = byVdom.get(g.vdom);
    const p = entriesOf(node, 'firewall policy').find((e) => e.name === g.id);
    if (!p) continue;
    const addr = (k) => [...list(p, k), ...list(p, `${k}6`)];
    const severity = SEVERITIES.find((s) => g.findings.some((f) => f.severity === s));
    const exposed = g.findings.some((f) => EXPOSED_CHECKS.has(f.check));
    policies.push({
      vdom: g.vdom,
      id: g.id,
      name: one(p, 'name'),
      srcintf: list(p, 'srcintf'),
      dstintf: list(p, 'dstintf'),
      srcaddr: addr('srcaddr'),
      dstaddr: addr('dstaddr'),
      service: list(p, 'service'),
      severity,
      exposed,
      priority: priorityOf(severity, exposed, g.findings.length),
      findings: g.findings,
      steps: stepsFor(p, g.findings, node).map((s) => (multiVdom ? {
        ...s,
        commands: inVdom(g.vdom, s.commands),
        undo: inVdom(g.vdom, s.undo),
        verify: [`Run CLI checks inside the VDOM: \`config vdom\`, then \`edit ${g.vdom}\`.`, ...s.verify],
      } : s)),
    });
  }
  policies.sort((a, b) => b.priority - a.priority || a.vdom.localeCompare(b.vdom) || Number(a.id) - Number(b.id));
  return { policies };
}

module.exports = { analyze };
