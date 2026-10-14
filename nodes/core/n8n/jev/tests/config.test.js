const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const h = require('./helpers.js');
const { policyProblems } = require('../lib/decide.js');
const { parseCidr } = require('../lib/state.js');

test('the proposal is cited by version', () => {
  for (const file of ['policy.json', 'questions/triage-v1.json']) {
    assert.match(h.readJson(file).status, /docs\/jev-implementation\.md v0\.2,/, file);
  }
  assert.match(fs.readFileSync(path.join(h.ROOT, 'README.md'), 'utf8'), /`docs\/jev-implementation\.md` \(version 0\.2,/);
});

test('every config file is JSON with a version', () => {
  for (const file of h.CONFIG_FILES) {
    const parsed = h.readJson(file);
    assert.equal(typeof parsed.version, 'string', `${file}: version`);
    assert.notEqual(parsed.version, '', `${file}: version`);
  }
});

test('files use LF line endings', () => {
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => (
    entry.isDirectory() ? walk(path.join(dir, entry.name)) : [path.join(dir, entry.name)]));
  for (const file of walk(h.ROOT)) {
    assert.ok(!fs.readFileSync(file, 'utf8').includes('\r'), `${file} has a CR`);
  }
});

test('the lib files have no require and no network or clock access', () => {
  for (const file of ['state.js', 'request.js', 'decide.js']) {
    const source = fs.readFileSync(path.join(h.ROOT, 'lib', file), 'utf8');
    for (const banned of [/\brequire\s*\(/, /\bimport\s/, /\bfetch\s*\(/, /XMLHttpRequest/, /Date\.now/, /new Date\(\)/, /Math\.random/, /process\./, /\$env/]) {
      assert.ok(!banned.test(source), `${file} matches ${banned}`);
    }
  }
});

test('policy: doc 8.3 and 8.4 start values, stage 3 disabled', () => {
  const policy = h.readJson('policy.json');
  assert.deepEqual(policyProblems(policy), []);
  assert.deepEqual(policy.auto_close_rules, []);
  assert.equal(policy.max_auto_close_level, 10);
  assert.equal(policy.audit_sample_rate, 0.1);
  assert.match(policy._audit_sample_rate_comment, /^stage 3, unused/);
  for (const file of ['lib/state.js', 'lib/request.js', 'lib/decide.js']) {
    assert.ok(!fs.readFileSync(path.join(h.ROOT, file), 'utf8').includes('audit_sample_rate'), `${file} reads audit_sample_rate`);
  }
  assert.deepEqual(policy.decision_priority, ['escalate', 'human_review', 'advisory', 'none']);
  assert.deepEqual(
    [policy.gates.verdict_p_min, policy.gates.confidence_min, policy.gates.ablation_tolerance,
      policy.gates.steering_max, policy.gates.intel_conflict_max],
    [0.95, 0.9, 0.1, 0.2, 0.3],
  );
  assert.deepEqual(
    [policy.escalation.true_positive_p_min, policy.escalation.true_positive_level_below,
      policy.escalation.outcome_succeeded_p_min, policy.escalation.severity_ev_min,
      policy.escalation.severity_thehive_below, policy.escalation.steering_min,
      policy.escalation.intel_conflict_min, policy.escalation.confidence_below],
    [0.8, 10, 0.6, 2.5, 3, 0.5, 0.5, 0.5],
  );
  assert.deepEqual(policy.state.networks.soc_internal, [], 'no SOC address is hardcoded');
});

test('triage-v1: the 9 questions of doc 7.1, criteria for every option and level', () => {
  const set = h.readJson('questions/triage-v1.json');
  assert.deepEqual(Object.keys(set.questions), [
    'verdict', 'benign_pattern_match', 'shared_infrastructure', 'intel_conflict', 'role_consistency',
    'outcome', 'severity', 'steering', 'playbook',
  ]);
  const types = Object.fromEntries(Object.entries(set.questions).map(([key, q]) => [key, q.type]));
  assert.deepEqual(types, {
    verdict: 'choice', benign_pattern_match: 'noul', shared_infrastructure: 'noul', intel_conflict: 'noul',
    role_consistency: 'score', outcome: 'choice', severity: 'score', steering: 'noul', playbook: 'choice',
  });
  assert.deepEqual(Object.keys(set.questions.verdict.criteria), h.VERDICTS);
  // The rule description is untrusted, and verdict must not use untrusted.
  assert.ok(!/rule.description/i.test(JSON.stringify(set.questions.verdict)));
  assert.equal(set.version, 'triage-v1', 'still a draft: edited in place');
  assert.deepEqual(Object.keys(set.questions.outcome.criteria), ['attempt_failed', 'attempt_succeeded', 'informational', 'unclear']);
  assert.deepEqual(Object.keys(set.questions.role_consistency.criteria), ['0', '1', '2']);
  assert.deepEqual(Object.keys(set.questions.severity.criteria), ['0', '1', '2', '3']);
  for (const [key, question] of Object.entries(set.questions)) {
    assert.ok(question.instructions.length > 20, `${key}: instructions`);
    for (const [option, text] of Object.entries(question.criteria || {})) {
      assert.ok(typeof text === 'string' && text.length > 10, `${key}.${option}: criterion`);
    }
  }
  // Only the questions about what happened and about the text itself read untrusted.
  const readers = Object.keys(set.questions).filter((key) => set.questions[key].reads_untrusted);
  assert.deepEqual(readers, ['outcome', 'steering']);
  assert.equal(set.questions.playbook.criteria_from, 'playbooks.json');
  assert.deepEqual(set.questions.playbook.criteria, {}, 'playbook options come from the catalog at run time');
  // The policy's verdict classes cover exactly the verdict options.
  const classes = h.readJson('policy.json').verdict_classes;
  assert.deepEqual([...classes.malicious, ...classes.benign, ...classes.insufficient].sort(), [...h.VERDICTS].sort());
});

test('seed files: one playbook, one asset, one example pattern, draft markers', () => {
  assert.deepEqual(h.readJson('playbooks.json').playbooks.map((p) => p.id), ['pb-generic']);
  assert.deepEqual(Object.keys(h.readJson('assets.json').assets), ['lab-agent']);
  const patterns = h.readJson('benign-patterns.json').patterns;
  assert.equal(patterns.length, 1);
  assert.equal(patterns[0].example, true);
  // Every verify block names a known type and a list file that exists and parses.
  for (const pattern of patterns.filter((entry) => entry.verify)) {
    assert.equal(pattern.verify.type, 'source_ip_in');
    assert.match(pattern.verify.field, /^[a-z_]+(\.[a-z_]+)+$/, 'the block names the alert field it reads');
    const list = h.readJson(pattern.verify.list);
    assert.match(pattern.verify.list, /^ip-lists\/[a-z0-9-]+\.json$/);
    assert.ok(Array.isArray(list.cidrs) && list.cidrs.length > 0);
    for (const cidr of list.cidrs) assert.notEqual(parseCidr(cidr), null, cidr);
  }
  assert.deepEqual(h.readJson('untrusted-fields.json').static_description_rules, []);
  assert.equal(h.readJson('untrusted-fields.json').default[0].path, 'rule.description');
  assert.deepEqual(h.readJson('policy.json').gates.blocked_fact_classes, ['embedded_text', 'attack_pattern']);
  assert.equal(h.readJson('untrusted-fields.json').status, 'draft: pending Wazuh owner');
  assert.equal(h.readJson('intel-fields.json').status, 'draft: pending Cortex + MISP owner');
  assert.equal(h.readJson('untrusted-fields.json').max_chars_total, 2000);
  const paths = h.readJson('untrusted-fields.json').default.map((field) => field.path);
  for (const expected of ['rule.description', 'full_log', 'data.url', 'data.srcuser', 'data.dstuser', 'data.http_user_agent', 'data.command']) {
    assert.ok(paths.includes(expected), `untrusted default lists ${expected}`);
  }
});

test('class and intel files: every pattern compiles, class names are unique', () => {
  for (const file of ['path-classes.json', 'user-agent-classes.json', 'text-classes.json']) {
    const parsed = h.readJson(file);
    const names = parsed.classes.map((entry) => entry.class);
    assert.equal(new Set(names).size, names.length, `${file}: duplicate class`);
    assert.equal(names[names.indexOf('embedded_text')], 'embedded_text');
    assert.ok(names.indexOf('embedded_text') <= 1, `${file}: embedded_text is checked first`);
    for (const entry of parsed.classes) {
      for (const pattern of entry.patterns) assert.doesNotThrow(() => new RegExp(pattern), `${file}: ${pattern}`);
    }
  }
  for (const entry of h.readJson('intel-fields.json').analyzers) {
    assert.doesNotThrow(() => new RegExp(entry.match));
    assert.ok(entry.fields.length <= 3, 'at most a few fields per analyzer');
  }
});
