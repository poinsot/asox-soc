// Jev state builder (docs/jev-implementation.md section 6). Stage 0, draft.
//
// buildState(alert, enrichment, config) -> state
//   alert       raw Wazuh alert, as received over C1
//   enrichment  what the playbook gathered; every part is optional:
//                 observable      { dataType, data }                      primary observable
//                 seen_before     { count, first_seen, last_seen,
//                                   top_rules: [{ rule_id, level }] }     C13
//                 misp            { events: [{ date, threat_level_id, info }] }   C7
//                 warninglists    ["list name", ...]                      C10
//                 cortex_reports  [{ analyzer, summary: { taxonomies }, full }]   C6
//   config      { policy, assets, benignPatterns, untrustedFields, intelFields,
//                 pathClasses, userAgentClasses, textClasses, ipLists, now }
//               the parsed JSON files of this folder (ipLists maps a list's
//               path in this folder to its parsed file); `now` is an ISO date
//               or epoch milliseconds, passed in so the function stays pure.
//
// The returned state has five sections that may be sent to Jev: alert, facts,
// intel, context, untrusted. It also carries `derived_facts`, the names of
// the facts computed from untrusted fields: lib/request.js removes them for
// the strict ablation and never sends the list itself. Values used only by
// code (buildCodeCtx) are never part of the state.
//
// Pure: no I/O, no clock, no require. A fact whose input is missing is the
// string "unknown"; nothing here throws on a missing or malformed input.

const UNKNOWN = 'unknown';

// Facts computed from untrusted fields. This is the one list: a new class
// fact is added here, and the strict ablation and the tests follow.
const DERIVED_FACTS = ['request_path_class', 'user_agent_class', 'untrusted_text_class'];

// Category labels of doc 6.2, written once. lib/decide.js compares against
// policy values, never against these strings directly.
const SEEN_BEFORE = {
  never: 'never',
  low: '1–5 times',
  mid: '6–50 times',
  high: 'more than 50 times',
};
const AGE = {
  never: 'never',
  day: 'less than 24 hours ago',
  week: '1–7 days ago',
  month: '8–30 days ago',
  older: 'more than 30 days ago',
};
const OBSERVABLE_TYPES = {
  ip: 'ip',
  domain: 'domain',
  fqdn: 'domain',
  hash: 'hash',
  hostname: 'hostname',
  'user-account': 'user-account',
};
const CRITICALITIES = ['low', 'medium', 'high', 'protected'];
const INTEL_LEVELS = ['info', 'safe', 'suspicious', 'malicious'];
// MISP threat_level_id: 1 high, 2 medium, 3 low, 4 undefined.
const MISP_THREAT_LEVELS = { 1: 'high', 2: 'medium', 3: 'low' };
const HOUR_MS = 3600 * 1000;
const DAY_MS = 24 * HOUR_MS;
const CLOCK_SKEW_MS = 5 * 60 * 1000;

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// Read a dotted path ("data.srcip", "results.0.info"); undefined when absent.
function get(source, path) {
  let current = source;
  for (const part of String(path).split('.')) {
    if (current === null || current === undefined) return undefined;
    current = current[part];
  }
  return current;
}

// A printable, bounded string, or undefined for anything that is not a
// string or a number.
function clean(value, maxChars) {
  if (typeof value !== 'string' && typeof value !== 'number') return undefined;
  const text = String(value).replace(/[\u0000-\u001f\u007f]+/g, ' ').trim();
  return text.slice(0, maxChars);
}

function cleanOrUnknown(value, maxChars) {
  const text = clean(value, maxChars);
  return text === undefined || text === '' ? UNKNOWN : text;
}

function positiveInt(value, fallback) {
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

// ---------------------------------------------------------------- addresses

function parseIpv4(text) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!match) return null;
  let value = 0n;
  for (let i = 1; i <= 4; i += 1) {
    const octet = Number(match[i]);
    if (octet > 255) return null;
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

function parseIpv6(text) {
  let address = text;
  const zone = address.indexOf('%');
  if (zone !== -1) address = address.slice(0, zone);
  if (!/^[0-9a-fA-F:.]+$/.test(address) || address.indexOf(':') === -1) return null;
  const halves = address.split('::');
  if (halves.length > 2) return null;
  const toGroups = (part) => {
    if (part === '') return [];
    const groups = [];
    const pieces = part.split(':');
    for (let i = 0; i < pieces.length; i += 1) {
      const piece = pieces[i];
      if (piece.indexOf('.') !== -1) {
        // Embedded IPv4, only valid as the last piece.
        if (i !== pieces.length - 1) return null;
        const v4 = parseIpv4(piece);
        if (v4 === null) return null;
        groups.push(Number(v4 >> 16n), Number(v4 & 0xffffn));
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(piece)) return null;
        groups.push(parseInt(piece, 16));
      }
    }
    return groups;
  };
  const head = toGroups(halves[0]);
  const tail = halves.length === 2 ? toGroups(halves[1]) : [];
  if (head === null || tail === null) return null;
  let groups;
  if (halves.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null;
    groups = head.concat(new Array(missing).fill(0), tail);
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  let value = 0n;
  for (const group of groups) value = (value << 16n) | BigInt(group);
  return value;
}

// { family: 4 | 6, value: BigInt } or null. IPv4-mapped IPv6 counts as IPv4.
function parseIp(text) {
  if (typeof text !== 'string') return null;
  const trimmed = text.trim();
  const v4 = parseIpv4(trimmed);
  if (v4 !== null) return { family: 4, value: v4 };
  const v6 = parseIpv6(trimmed);
  if (v6 === null) return null;
  if (v6 >> 32n === 0xffffn) return { family: 4, value: v6 & 0xffffffffn };
  return { family: 6, value: v6 };
}

function parseCidr(text) {
  if (typeof text !== 'string') return null;
  const slash = text.indexOf('/');
  const ip = parseIp(slash === -1 ? text : text.slice(0, slash));
  if (!ip) return null;
  const bits = ip.family === 4 ? 32 : 128;
  let prefix = bits;
  if (slash !== -1) {
    const raw = text.slice(slash + 1);
    if (!/^\d{1,3}$/.test(raw)) return null;
    prefix = Number(raw);
    if (prefix > bits) return null;
  }
  return { family: ip.family, value: ip.value, prefix, bits };
}

function ipInCidr(ip, cidr) {
  if (!ip || !cidr || ip.family !== cidr.family) return false;
  const shift = BigInt(cidr.bits - cidr.prefix);
  return ip.value >> shift === cidr.value >> shift;
}

function inAnyRange(ip, ranges) {
  if (!Array.isArray(ranges)) return false;
  return ranges.some((range) => ipInCidr(ip, parseCidr(range)));
}

// public | private | soc_internal | documentation | unknown
function ipScope(text, networks) {
  const ip = parseIp(text);
  if (!ip) return UNKNOWN;
  const nets = isObject(networks) ? networks : {};
  if (inAnyRange(ip, nets.soc_internal)) return 'soc_internal';
  if (inAnyRange(ip, nets.documentation)) return 'documentation';
  if (inAnyRange(ip, nets.private)) return 'private';
  return 'public';
}

function isOurs(scope) {
  return scope === 'soc_internal' || scope === 'private';
}

// inbound | outbound | internal | unknown. With only one address in the
// alert, the monitored agent is the other end.
function direction(srcIp, dstIp, networks) {
  const src = ipScope(srcIp, networks);
  const dst = ipScope(dstIp, networks);
  if (src === UNKNOWN && dst === UNKNOWN) return UNKNOWN;
  if (src === UNKNOWN) return isOurs(dst) ? UNKNOWN : 'outbound';
  if (dst === UNKNOWN) return isOurs(src) ? 'internal' : 'inbound';
  if (isOurs(src)) return isOurs(dst) ? 'internal' : 'outbound';
  return isOurs(dst) ? 'inbound' : UNKNOWN;
}

// ------------------------------------------------------------ dates, counts

// Epoch milliseconds, or null. Accepts Wazuh's "+0000" offset.
function toMillis(value) {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value !== 'string' || value.trim() === '') return null;
  const text = value.trim().replace(/([+-]\d{2})(\d{2})$/, '$1:$2');
  const millis = Date.parse(text);
  return Number.isNaN(millis) ? null : millis;
}

function ageBucket(value, nowMs) {
  const then = toMillis(value);
  if (then === null || nowMs === null) return UNKNOWN;
  let age = nowMs - then;
  if (age < 0) {
    if (age < -CLOCK_SKEW_MS) return UNKNOWN;
    age = 0;
  }
  if (age < DAY_MS) return AGE.day;
  if (age < 8 * DAY_MS) return AGE.week;
  if (age < 31 * DAY_MS) return AGE.month;
  return AGE.older;
}

function countBucket(count) {
  if (!Number.isInteger(count) || count < 0) return UNKNOWN;
  if (count === 0) return SEEN_BEFORE.never;
  if (count <= 5) return SEEN_BEFORE.low;
  if (count <= 50) return SEEN_BEFORE.mid;
  return SEEN_BEFORE.high;
}

// ---------------------------------------------------------------- the facts

function primaryObservable(alert, enrichment) {
  const given = enrichment.observable;
  if (isObject(given) && typeof given.dataType === 'string') {
    return { type: OBSERVABLE_TYPES[given.dataType] || UNKNOWN, value: given.data };
  }
  // Fallback: the first field of the C13 field map present in the alert.
  const candidates = [
    ['ip', 'data.srcip'], ['ip', 'data.src_ip'], ['ip', 'data.dstip'], ['ip', 'data.dest_ip'],
    ['hostname', 'data.hostname'],
    ['user-account', 'data.srcuser'], ['user-account', 'data.dstuser'],
    ['hash', 'syscheck.sha256_after'], ['hash', 'syscheck.sha1_after'], ['hash', 'syscheck.md5_after'],
  ];
  for (const [type, path] of candidates) {
    const value = get(alert, path);
    if (typeof value === 'string' && value !== '') return { type, value };
  }
  return { type: UNKNOWN, value: undefined };
}

function seenBeforeFacts(seen, policyState, nowMs) {
  const facts = {
    seen_before: UNKNOWN,
    first_seen: UNKNOWN,
    last_seen: UNKNOWN,
    related_high_alerts: UNKNOWN,
  };
  if (!isObject(seen)) return facts;
  facts.seen_before = countBucket(seen.count);
  if (facts.seen_before === SEEN_BEFORE.never) {
    facts.first_seen = AGE.never;
    facts.last_seen = AGE.never;
  } else if (facts.seen_before !== UNKNOWN) {
    facts.first_seen = ageBucket(seen.first_seen, nowMs);
    facts.last_seen = ageBucket(seen.last_seen, nowMs);
  }
  if (Array.isArray(seen.top_rules)) {
    const minLevel = positiveInt(policyState.related_high_alert_level, 10);
    const readable = seen.top_rules.every((rule) => isObject(rule) && Number.isFinite(Number(rule.level)));
    if (!readable) return facts;
    facts.related_high_alerts = seen.top_rules.some((rule) => Number(rule.level) >= minLevel) ? 'some' : 'none';
  }
  return facts;
}

function mispMatch(misp, policyState, nowMs) {
  if (!isObject(misp) || !Array.isArray(misp.events)) return UNKNOWN;
  if (misp.events.length === 0) return 'none';
  const manyMin = positiveInt(policyState.misp_events_many_min, 6);
  let newest = null;
  let allDated = true;
  let worst = null; // lowest threat_level_id = highest threat
  let allLevelled = true;
  for (const event of misp.events) {
    const date = isObject(event) ? toMillis(event.date) : null;
    if (date === null) allDated = false;
    else if (newest === null || date > newest) newest = date;
    const level = isObject(event) ? Number(event.threat_level_id) : NaN;
    if (!MISP_THREAT_LEVELS[level]) allLevelled = false;
    else if (worst === null || level < worst) worst = level;
  }
  return {
    events: misp.events.length >= manyMin ? 'many' : 'few',
    // An undated event could be the newest one, so its age stays unknown.
    newest_event_age: allDated ? ageBucket(newest, nowMs) : UNKNOWN,
    // "high" is certain as soon as one event says so; otherwise an event
    // without a level could be the worst one.
    threat_level: worst === 1 || (allLevelled && worst !== null) ? MISP_THREAT_LEVELS[worst] : UNKNOWN,
  };
}

function warninglistNames(lists, policyState) {
  if (!Array.isArray(lists)) return UNKNOWN;
  const names = [];
  for (const entry of lists) {
    const name = clean(isObject(entry) ? entry.name : entry, 120);
    if (name && names.indexOf(name) === -1) names.push(name);
  }
  return names.slice(0, positiveInt(policyState.max_warninglists, 10));
}

// Class of an untrusted value, from an ordered class file. The result is one
// of the class names of that file, its default class, or "unknown": never
// any part of the input.
function classify(value, classFile) {
  if (typeof value !== 'string' || !isObject(classFile) || !Array.isArray(classFile.classes)) return UNKNOWN;
  const text = value.toLowerCase().slice(0, positiveInt(classFile.max_input_chars, 1024));
  for (const entry of classFile.classes) {
    if (!isObject(entry) || typeof entry.class !== 'string' || !Array.isArray(entry.patterns)) continue;
    for (const pattern of entry.patterns) {
      let regex;
      try {
        regex = new RegExp(pattern);
      } catch (error) {
        continue; // a broken pattern never matches; the unit tests compile every pattern
      }
      if (regex.test(text)) return entry.class;
    }
  }
  return typeof classFile.default_class === 'string' ? classFile.default_class : UNKNOWN;
}

function requestPathClass(url, classFile) {
  if (typeof url !== 'string') return UNKNOWN;
  let path = url.split(/[?#]/)[0];
  try {
    path = decodeURIComponent(path);
  } catch (error) {
    // Malformed escapes: classify the path as it was sent.
  }
  return classify(path, classFile);
}

// Class of the untrusted text that has no class of its own (user names,
// commands, file names, the log line, the rule description).
function untrustedTextClass(untrusted, classFile) {
  if (!isObject(classFile)) return UNKNOWN;
  const exclude = Array.isArray(classFile.exclude_keys) ? classFile.exclude_keys : [];
  const values = Object.keys(untrusted).filter((key) => exclude.indexOf(key) === -1).map((key) => untrusted[key]);
  return values.length === 0 ? UNKNOWN : classify(values.join('\n'), classFile);
}

function userAgentClass(userAgent, classFile) {
  if (typeof userAgent !== 'string') return UNKNOWN;
  const maxPlain = isObject(classFile) ? positiveInt(classFile.max_plain_chars, 256) : 256;
  if (userAgent.length > maxPlain) return 'embedded_text';
  return classify(userAgent, classFile);
}

// -------------------------------------------------- intel, context, untrusted

function intelSummaries(reports, intelFields) {
  if (!Array.isArray(reports)) return UNKNOWN;
  const fields = isObject(intelFields) ? intelFields : {};
  const analyzers = Array.isArray(fields.analyzers) ? fields.analyzers : [];
  const maxTaxonomies = positiveInt(fields.max_taxonomies_per_report, 5);
  const maxDetail = positiveInt(fields.max_detail_chars, 200);
  const summaries = [];
  for (const report of reports) {
    if (!isObject(report)) continue;
    const analyzerName = clean(report.analyzer, 80) || UNKNOWN;
    const selection = analyzers.find((entry) => {
      if (!isObject(entry) || typeof entry.match !== 'string') return false;
      try {
        return new RegExp(entry.match).test(analyzerName);
      } catch (error) {
        return false;
      }
    });
    const taxonomies = [];
    let worst = -1;
    const raw = get(report, 'summary.taxonomies');
    for (const taxonomy of Array.isArray(raw) ? raw.slice(0, maxTaxonomies) : []) {
      if (!isObject(taxonomy)) continue;
      const level = INTEL_LEVELS.indexOf(taxonomy.level);
      if (level === -1) continue;
      worst = Math.max(worst, level);
      taxonomies.push([
        taxonomy.level,
        `${cleanOrUnknown(taxonomy.namespace, 40)}:${cleanOrUnknown(taxonomy.predicate, 40)}`,
        cleanOrUnknown(taxonomy.value, 60),
      ].join(' '));
    }
    const details = [];
    for (const field of selection && Array.isArray(selection.fields) ? selection.fields : []) {
      const value = clean(get(report.full, field.path), maxDetail);
      if (value) details.push(`${field.label}: ${value}`);
    }
    summaries.push({
      source: selection && typeof selection.source === 'string' ? selection.source : analyzerName,
      level: worst === -1 ? UNKNOWN : INTEL_LEVELS[worst],
      taxonomies,
      detail: details.join('; ').slice(0, maxDetail),
    });
  }
  return summaries;
}

// The patterns that apply to this agent and rule, as [{ description, verify }],
// or null when there is no pattern file. Jev is shown the descriptions; the
// verify blocks are evaluated in code (verifyBenignPatterns).
function applicablePatterns(file, agentName, ruleId, policyState) {
  if (!isObject(file) || !Array.isArray(file.patterns)) return null;
  const selected = [];
  for (const pattern of file.patterns) {
    if (!isObject(pattern)) continue;
    const description = clean(pattern.description, 400);
    if (!description) continue;
    const scope = isObject(pattern.applies_to) ? pattern.applies_to : {};
    if (Array.isArray(scope.agents) && scope.agents.indexOf(agentName) === -1) continue;
    if (Array.isArray(scope.rule_ids) && scope.rule_ids.map(String).indexOf(ruleId) === -1) continue;
    selected.push({ description, verify: pattern.verify });
  }
  return selected.slice(0, positiveInt(policyState.max_benign_patterns, 20));
}

// yes | no | unknown for one verify block. `source_ip_in` is the only type:
// the address in the alert field the block names must be inside a CIDR list
// file of this folder. Only that field is read: no fallback to another one,
// so a pattern is verified against the address its author chose and reviewed.
function verifyPattern(verify, alert, ipLists) {
  if (!isObject(verify)) return 'no';
  if (verify.type !== 'source_ip_in') return UNKNOWN;
  if (typeof verify.field !== 'string' || verify.field === '') return UNKNOWN;
  const list = isObject(ipLists) && typeof verify.list === 'string' ? ipLists[verify.list] : undefined;
  if (!isObject(list) || !Array.isArray(list.cidrs)) return UNKNOWN;
  const source = parseIp(get(alert, verify.field));
  if (!source) return UNKNOWN;
  return inAnyRange(source, list.cidrs) ? 'yes' : 'no';
}

// Did code confirm a known benign pattern for this alert? `yes` when the
// verify block of at least one applicable pattern holds; `no` when none
// does, including when no applicable pattern has a verify block (prose
// alone verifies nothing); `unknown` when a check could not be made.
function verifyBenignPatterns(alert, config) {
  const a = isObject(alert) ? alert : {};
  const c = isObject(config) ? config : {};
  const policyState = isObject(c.policy) && isObject(c.policy.state) ? c.policy.state : {};
  const patterns = applicablePatterns(
    c.benignPatterns, cleanOrUnknown(get(a, 'agent.name'), 80), cleanOrUnknown(get(a, 'rule.id'), 20), policyState,
  );
  if (patterns === null) return UNKNOWN;
  const results = patterns.map((pattern) => verifyPattern(pattern.verify, a, c.ipLists));
  if (results.indexOf('yes') !== -1) return 'yes';
  return results.indexOf(UNKNOWN) !== -1 ? UNKNOWN : 'no';
}

function untrustedFields(alert, file, skipPaths) {
  const out = {};
  if (!isObject(file)) return out;
  const maxTotal = positiveInt(file.max_chars_total, 2000);
  const maxField = positiveInt(file.max_chars_per_field, 500);
  const decoderName = get(alert, 'decoder.name');
  const perDecoder = isObject(file.decoders) && typeof decoderName === 'string' ? file.decoders[decoderName] : undefined;
  const listed = (Array.isArray(file.default) ? file.default : []).concat(Array.isArray(perDecoder) ? perDecoder : []);
  let remaining = maxTotal;
  for (const field of listed) {
    if (remaining <= 0) break;
    if (!isObject(field) || typeof field.path !== 'string' || typeof field.key !== 'string') continue;
    if (skipPaths.indexOf(field.path) !== -1) continue;
    if (Object.prototype.hasOwnProperty.call(out, field.key)) continue;
    const value = clean(get(alert, field.path), Math.min(maxField, remaining));
    if (!value) continue;
    out[field.key] = value;
    remaining -= value.length;
  }
  return out;
}

// --------------------------------------------------------------- entry points

function buildState(alert, enrichment, config) {
  const a = isObject(alert) ? alert : {};
  const e = isObject(enrichment) ? enrichment : {};
  const c = isObject(config) ? config : {};
  const policyState = isObject(c.policy) && isObject(c.policy.state) ? c.policy.state : {};
  const networks = policyState.networks;
  const nowMs = toMillis(c.now);

  const ruleId = cleanOrUnknown(get(a, 'rule.id'), 20);
  const ruleLevel = Number(get(a, 'rule.level'));
  const agentName = cleanOrUnknown(get(a, 'agent.name'), 80);
  const tactics = get(a, 'rule.mitre.tactic');
  const asset = isObject(c.assets) && isObject(c.assets.assets) ? c.assets.assets[agentName] : undefined;
  const observable = primaryObservable(a, e);
  // A rule description can interpolate decoded fields, so it is untrusted
  // unless the rule is listed as having a static one.
  const staticRules = isObject(c.untrustedFields) && Array.isArray(c.untrustedFields.static_description_rules)
    ? c.untrustedFields.static_description_rules.map(String) : [];
  const staticDescription = ruleId !== UNKNOWN && staticRules.indexOf(ruleId) !== -1;
  const groups = get(a, 'rule.groups');
  const untrusted = untrustedFields(a, c.untrustedFields, staticDescription ? ['rule.description'] : []);

  const facts = { observable_type: observable.type };
  facts.ip_scope = observable.type === 'ip' ? ipScope(observable.value, networks) : UNKNOWN;
  facts.direction = direction(
    get(a, 'data.srcip') || get(a, 'data.src_ip'),
    get(a, 'data.dstip') || get(a, 'data.dest_ip'),
    networks,
  );
  Object.assign(facts, seenBeforeFacts(e.seen_before, policyState, nowMs));
  facts.misp_match = mispMatch(e.misp, policyState, nowMs);
  facts.warninglists = warninglistNames(e.warninglists, policyState);
  facts.asset_criticality = isObject(asset) && CRITICALITIES.indexOf(asset.criticality) !== -1
    ? asset.criticality : UNKNOWN;
  // Safe facts derived in code from untrusted fields (DERIVED_FACTS): a
  // closed set of class names. They stay in the ablated run, while the raw
  // values do not, and are removed from the strict ablation.
  facts.request_path_class = requestPathClass(get(a, 'data.url'), c.pathClasses);
  facts.user_agent_class = userAgentClass(get(a, 'data.http_user_agent'), c.userAgentClasses);
  facts.untrusted_text_class = untrustedTextClass(untrusted, c.textClasses);

  const alertSection = {
    rule_id: ruleId,
    rule_level: Number.isInteger(ruleLevel) ? ruleLevel : UNKNOWN,
    rule_groups: Array.isArray(groups) ? groups.map((group) => clean(group, 40)).filter(Boolean).slice(0, 10) : [],
    mitre_tactics: Array.isArray(tactics)
      ? tactics.map((tactic) => clean(tactic, 60)).filter(Boolean).slice(0, 10) : [],
    agent_name: agentName,
    decoder: cleanOrUnknown(get(a, 'decoder.name'), 80),
  };
  if (staticDescription) alertSection.rule_description = cleanOrUnknown(get(a, 'rule.description'), 200);
  const patterns = applicablePatterns(c.benignPatterns, agentName, ruleId, policyState);

  return {
    alert: alertSection,
    facts,
    intel: intelSummaries(e.cortex_reports, c.intelFields),
    context: {
      asset_role: isObject(asset) ? cleanOrUnknown(asset.role, 300) : UNKNOWN,
      known_benign_patterns: patterns === null ? UNKNOWN : patterns.map((pattern) => pattern.description),
    },
    untrusted,
    derived_facts: DERIVED_FACTS.slice(),
  };
}

// Values the decision needs and Jev must never see (doc 6.2 marks
// rule_eligible_for_auto "used by code only"). `config` is the one given to
// buildState; `extra` carries what only the playbook knows: thehive_severity
// (1-4) and response_action_proposed. The key names differ from every key of
// the state on purpose, so a test can prove none of them reaches a request
// body.
function buildCodeCtx(alert, config, extra) {
  const a = isObject(alert) ? alert : {};
  const p = isObject(config) && isObject(config.policy) ? config.policy : {};
  const x = isObject(extra) ? extra : {};
  const ruleId = cleanOrUnknown(get(a, 'rule.id'), 20);
  const ruleLevel = Number(get(a, 'rule.level'));
  const listed = Array.isArray(p.auto_close_rules) && p.auto_close_rules.map(String).indexOf(ruleId) !== -1;
  const never = Array.isArray(p.never_auto_rules) && p.never_auto_rules.map(String).indexOf(ruleId) !== -1;
  return {
    wazuh_rule_id: ruleId,
    wazuh_rule_level: Number.isInteger(ruleLevel) ? ruleLevel : UNKNOWN,
    rule_eligible_for_auto: ruleId !== UNKNOWN && listed && !never ? 'yes' : 'no',
    benign_pattern_verified: verifyBenignPatterns(a, config),
    thehive_severity: Number.isInteger(x.thehive_severity) ? x.thehive_severity : UNKNOWN,
    response_action_proposed: typeof x.response_action_proposed === 'boolean'
      ? x.response_action_proposed : UNKNOWN,
  };
}

const jevState = {
  buildState,
  buildCodeCtx,
  DERIVED_FACTS,
  // exported for the unit tests
  parseIp,
  ipInCidr,
  parseCidr,
  ipScope,
  direction,
  ageBucket,
  countBucket,
  classify,
  requestPathClass,
  userAgentClass,
  verifyBenignPatterns,
  UNKNOWN,
  SEEN_BEFORE,
  AGE,
};

if (typeof module !== 'undefined' && module.exports) module.exports = jevState;
