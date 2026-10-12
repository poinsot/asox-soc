const test = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers.js');
const { decide, policyProblems } = require('../lib/decide.js');

const RULE = '100100';

// Mode gated, rule listed, every gate passing: the one situation in which
// decide returns auto_close_fp. Each test changes one thing from here.
function base() {
  return {
    runs: h.passingRuns(),
    facts: h.passingFacts(),
    policy: h.eligiblePolicy([RULE]),
    mode: 'gated',
    ctx: h.passingCtx(RULE),
  };
}

function run(change) {
  const b = base();
  if (change) change(b);
  return decide(b.runs, b.facts, b.policy, b.mode, b.ctx);
}

const tagNames = (result) => [...result.tags].sort();
const triggerIds = (result) => result.triggers.map((trigger) => trigger.id);

test('baseline: gated, listed rule, every gate passes -> auto_close_fp', () => {
  const result = run();
  assert.equal(result.decision, 'auto_close_fp');
  assert.deepEqual(result.gatesFailed, []);
  assert.deepEqual(result.triggers, []);
  assert.deepEqual(result.tags, []);
  assert.equal(result.wouldAutoClose, true);
  assert.deepEqual(result.closeGatesFailed, []);
  assert.equal(result.policy_version, 'policy-0.2.0');
});

test('policy.json in git: auto_close_fp is unreachable in every mode', () => {
  for (const mode of ['off', 'shadow', 'advisory', 'gated', 'GATED', undefined]) {
    const result = run((b) => { b.policy = h.readJson('policy.json'); b.mode = mode; });
    assert.notEqual(result.decision, 'auto_close_fp', `mode ${mode}`);
  }
  const gated = run((b) => { b.policy = h.readJson('policy.json'); });
  assert.equal(gated.decision, 'advisory');
  assert.deepEqual(gated.gatesFailed, ['G2']);
  assert.equal(gated.gateDetails.G2, 'rule 100100 is not in auto_close_rules');
  assert.equal(gated.wouldAutoClose, false, 'in gated mode this is the real result');
});

test('each gate failing on its own blocks the closure and gives advisory', () => {
  const cases = [
    ['G1', (b) => { b.mode = 'advisory'; }],
    ['G2', (b) => { b.ctx.wazuh_rule_level = 10; }],
    ['G2', (b) => { b.ctx.wazuh_rule_level = 'unknown'; }],
    ['G2', (b) => { b.policy.auto_close_rules = ['5716']; }],
    ['G2', (b) => { b.policy.never_auto_rules = [RULE]; }],
    ['G2', (b) => { b.ctx.rule_eligible_for_auto = 'no'; }],
    ['G2', (b) => { b.ctx.wazuh_rule_id = 'unknown'; }],
    ['G3', (b) => { b.facts.asset_criticality = 'high'; }],
    ['G3', (b) => { b.facts.asset_criticality = 'protected'; }],
    ['G3', (b) => { b.facts.asset_criticality = 'unknown'; }],
    ['G4', (b) => { b.runs.full.answers.verdict = h.verdict('benign_true_positive', 0.94, 0.95); }],
    ['G4', (b) => { b.ctx.benign_pattern_verified = 'no'; }],
    ['G4', (b) => { b.ctx.benign_pattern_verified = 'unknown'; }],
    ['G4', (b) => { delete b.ctx.benign_pattern_verified; }],
    ['G4', (b) => { b.ctx.benign_pattern_verified = 'no'; b.runs.full.answers.benign_pattern_match.noul = 0.5; }],
    ['G4', (b) => { delete b.runs.full.answers.benign_pattern_match; }],
    ['G5', (b) => { b.runs.full.answers.verdict = h.verdict('benign_true_positive', 0.97, 0.89); }],
    ['G5', (b) => { delete b.runs.full.answers.verdict.confidence; }],
    ['G6', (b) => { delete b.runs.ablated; }],
    ['G6', (b) => { delete b.runs.strictAblated; }],
    ['G6', (b) => { b.runs.strictAblated.answers.verdict = h.verdict('benign_true_positive', 0.8, 0.7); }],
    ['G6', (b) => { b.runs.strictAblated.answers.verdict = h.verdict('insufficient_evidence', 0.6, 0.5); }],
    ['G6', (b) => { b.runs.strictAblated.answers.verdict = h.verdict('true_positive', 0.8, 0.8); }],
    ['G12', (b) => { b.facts.request_path_class = 'embedded_text'; }],
    ['G12', (b) => { b.facts.user_agent_class = 'attack_pattern'; }],
    ['G12', (b) => { b.facts.untrusted_text_class = 'embedded_text'; }],
    ['G12', (b) => { b.facts.some_future_class = 'embedded_text'; }],
    ['G7', (b) => { delete b.runs.orderCheck; }],
    ['G7', (b) => { b.runs.orderCheck.answers.verdict = h.verdict('false_positive', 0.6, 0.7); }],
    ['G7', (b) => { b.runs.orderCheck.answers.verdict = h.verdict('true_positive', 0.6, 0.7); }],
    ['G8', (b) => { b.runs.full.answers.steering.noul = 0.2; }],
    ['G8', (b) => { delete b.runs.full.answers.steering; }],
    ['G9', (b) => { b.runs.full.answers.intel_conflict.noul = 0.35; }],
    ['G9', (b) => { delete b.runs.full.answers.intel_conflict; }],
    ['G10', (b) => { b.runs.full.answers.outcome = h.outcome('attempt_succeeded', 0.5); }],
    ['G10', (b) => { delete b.runs.full.answers.outcome; }],
    ['G11', (b) => { b.facts.related_high_alerts = 'some'; }],
    ['G11', (b) => { b.facts.related_high_alerts = 'unknown'; }],
    ['G11', (b) => { b.facts.misp_match = 'unknown'; }],
    ['G11', (b) => { b.facts.misp_match = { events: 'few', newest_event_age: '8–30 days ago', threat_level: 'high' }; }],
    ['G11', (b) => { b.facts.misp_match = { events: 'few', newest_event_age: 'unknown', threat_level: 'high' }; }],
    ['G11', (b) => { b.facts.misp_match = { events: 'few', newest_event_age: 'more than 30 days ago', threat_level: 'unknown' }; }],
    ['G11', (b) => { b.ctx.response_action_proposed = true; }],
    ['G11', (b) => { b.ctx.response_action_proposed = 'unknown'; }],
    ['G11', (b) => { delete b.facts.related_high_alerts; }],
  ];
  cases.forEach(([gate, change], index) => {
    const result = run(change);
    const label = `case ${index} (${gate}): ${result.gateDetails[gate]}`;
    assert.deepEqual(result.gatesFailed, [gate], label);
    assert.equal(result.decision, 'advisory', label);
    assert.deepEqual(result.triggers, [], label);
    assert.deepEqual(result.tags, [], label);
    assert.equal(typeof result.gateDetails[gate], 'string', label);
  });
});

test('gates that pass at their limits', () => {
  const passes = [
    (b) => { b.ctx.wazuh_rule_level = 9; },
    (b) => { b.facts.asset_criticality = 'medium'; },
    // No pattern claimed: nothing to verify.
    (b) => { b.ctx.benign_pattern_verified = 'no'; b.runs.full.answers.benign_pattern_match.noul = 0.49; },
    (b) => { for (const name of ['request_path_class', 'user_agent_class', 'untrusted_text_class']) b.facts[name] = 'unknown'; },
    (b) => { for (const name of Object.keys(b.runs)) b.runs[name].answers.verdict = h.verdict('false_positive', 0.95, 0.9); },
    (b) => { b.runs.full.answers.steering.noul = 0.19; },
    (b) => { b.runs.full.answers.intel_conflict.noul = 0.29; },
    (b) => { b.facts.misp_match = { events: 'many', newest_event_age: 'more than 30 days ago', threat_level: 'high' }; },
    (b) => { b.facts.misp_match = { events: 'few', newest_event_age: 'less than 24 hours ago', threat_level: 'medium' }; },
    (b) => {
      // An ablation delta of exactly the tolerance passes, without float noise.
      b.runs.full.answers.verdict = h.verdict('benign_true_positive', 0.98, 0.95);
      b.runs.ablated.answers.verdict = h.verdict('benign_true_positive', 0.88, 0.9);
      b.runs.strictAblated.answers.verdict = h.verdict('benign_true_positive', 0.88, 0.9);
    },
  ];
  passes.forEach((change, index) => assert.equal(run(change).decision, 'auto_close_fp', `case ${index}`));
});

test('G9 alone in gated mode: advisory, gatesFailed [G9], no triggers', () => {
  const result = run((b) => { b.runs.full.answers.intel_conflict.noul = 0.35; });
  assert.equal(result.decision, 'advisory');
  assert.deepEqual(result.gatesFailed, ['G9']);
  assert.deepEqual(result.triggers, []);
  assert.equal(result.gateDetails.G9, 'intel_conflict 0.35 >= 0.30');
});

test('ablation: a probability shift blocks de-escalation and is not manipulation', () => {
  // The full run is more benign than the ablated run by more than the tolerance.
  let result = run((b) => { b.runs.ablated.answers.verdict = h.verdict('benign_true_positive', 0.7, 0.6); });
  assert.equal(result.decision, 'advisory');
  assert.deepEqual(result.gatesFailed, ['G6']);
  assert.deepEqual(result.tags, ['jev:untrusted-dependent']);
  assert.deepEqual(result.triggers, []);
  assert.equal(result.wouldAutoClose, false);

  // The ablated run could not decide: still dependence, still not manipulation.
  result = run((b) => { b.runs.ablated.answers.verdict = h.verdict('insufficient_evidence', 0.6, 0.4); });
  assert.equal(result.decision, 'advisory');
  assert.deepEqual(result.gatesFailed, ['G6']);
  assert.deepEqual(result.tags, ['jev:untrusted-dependent']);

  // One benign option to the other is not a flip from the malicious class.
  result = run((b) => { b.runs.ablated.answers.verdict = h.verdict('false_positive', 0.9, 0.9); });
  assert.deepEqual(result.tags, ['jev:untrusted-dependent']);
  assert.deepEqual(result.triggers, []);

  // A missing ablated run fails the gate but says nothing about dependence.
  result = run((b) => { delete b.runs.ablated; });
  assert.deepEqual(result.tags, []);
  assert.deepEqual(result.notes, ['ablation-missing']);
});

test('strict ablation decides G6; the tags come from the plain ablation only', () => {
  // The verdict holds without the raw text but not without the class facts
  // an attacker can choose: closure is blocked, and nothing is tagged.
  let result = run((b) => { b.runs.strictAblated.answers.verdict = h.verdict('benign_true_positive', 0.6, 0.5); });
  assert.equal(result.decision, 'advisory');
  assert.deepEqual(result.gatesFailed, ['G6']);
  assert.equal(result.gateDetails.G6, 'delta 0.37 > 0.10 in the strict ablation');
  assert.deepEqual(result.tags, []);
  assert.deepEqual(result.triggers, []);

  // A malicious verdict in the strict ablation is not, alone, the flip trigger.
  result = run((b) => { b.runs.strictAblated.answers.verdict = h.verdict('true_positive', 0.8, 0.8); });
  assert.equal(result.decision, 'advisory');
  assert.deepEqual([result.gatesFailed, result.tags, result.triggers], [['G6'], [], []]);

  result = run((b) => { delete b.runs.strictAblated; });
  assert.deepEqual(result.notes, ['strict-ablation-missing']);
  assert.equal(result.gateDetails.G6, 'strict ablated run missing');

  // Both disagree: one G6 entry (the strict reason), and the tag.
  result = run((b) => {
    b.runs.ablated.answers.verdict = h.verdict('benign_true_positive', 0.7, 0.6);
    b.runs.strictAblated.answers.verdict = h.verdict('benign_true_positive', 0.6, 0.5);
  });
  assert.deepEqual(result.gatesFailed, ['G6']);
  assert.match(result.gateDetails.G6, /strict ablation$/);
  assert.deepEqual(result.tags, ['jev:untrusted-dependent']);

  // The strict ablation agrees and the plain one does not: still no closure.
  result = run((b) => { b.runs.ablated.answers.verdict = h.verdict('benign_true_positive', 0.7, 0.6); });
  assert.deepEqual(result.gatesFailed, ['G6']);
  assert.equal(result.gateDetails.G6, 'delta 0.27 > 0.10 without untrusted');
});

test('G4: a benign verdict resting on a pattern needs the pattern verified in code', () => {
  for (const verified of ['no', 'unknown', undefined, true, 'YES']) {
    const result = run((b) => { b.ctx.benign_pattern_verified = verified; });
    assert.deepEqual(result.gatesFailed, ['G4'], `verified ${verified}`);
    assert.equal(result.decision, 'advisory');
    assert.equal(result.wouldAutoClose, false);
  }
  assert.equal(run((b) => { b.ctx.benign_pattern_verified = 'no'; }).gateDetails.G4,
    'benign_pattern_match 0.96 >= 0.50, benign_pattern_verified no');
  // It is a closure gate only: in advisory mode nothing else changes.
  const advisory = run((b) => { b.mode = 'advisory'; b.ctx.benign_pattern_verified = 'no'; });
  assert.deepEqual([advisory.decision, advisory.gatesFailed, advisory.closeGatesFailed], ['advisory', ['G1', 'G4'], ['G4']]);
});

test('G12: a class fact reporting prose or attack syntax blocks closure, with the fact named', () => {
  const result = run((b) => { b.facts.user_agent_class = 'embedded_text'; b.facts.request_path_class = 'attack_pattern'; });
  assert.deepEqual(result.gatesFailed, ['G12']);
  assert.equal(result.gateDetails.G12, 'request_path_class attack_pattern, user_agent_class embedded_text');
  assert.equal(result.decision, 'advisory');
  const advisory = run((b) => { b.mode = 'shadow'; b.facts.untrusted_text_class = 'embedded_text'; });
  assert.deepEqual([advisory.wouldAutoClose, advisory.closeGatesFailed], [false, ['G12']]);
});

test('ablation: malicious without the untrusted text, benign with it -> possible manipulation', () => {
  const result = run((b) => { b.runs.ablated.answers.verdict = h.verdict('true_positive', 0.8, 0.8); });
  assert.equal(result.decision, 'human_review');
  assert.deepEqual(triggerIds(result), ['ablation_verdict_flip']);
  assert.deepEqual(tagNames(result), ['jev:possible-manipulation', 'jev:untrusted-dependent']);
  assert.deepEqual(result.gatesFailed, ['G6']);

  // The other direction is normal: the raw log can hold real evidence.
  const other = run((b) => {
    b.runs.full.answers.verdict = h.verdict('true_positive', 0.9, 0.9);
    b.runs.ablated.answers.verdict = h.verdict('benign_true_positive', 0.8, 0.8);
    b.runs.orderCheck.answers.verdict = h.verdict('true_positive', 0.9, 0.9);
  });
  assert.equal(other.decision, 'escalate');
  assert.ok(!other.tags.includes('jev:possible-manipulation'));
  assert.ok(other.tags.includes('jev:untrusted-dependent'));
});

test('8.4 triggers, one at a time', () => {
  const tp = (p, confidence) => (b) => {
    b.runs.full.answers.verdict = h.verdict('true_positive', p, confidence);
    b.runs.ablated.answers.verdict = h.verdict('true_positive', p, confidence);
    b.runs.orderCheck.answers.verdict = h.verdict('true_positive', p, confidence);
  };
  let result = run(tp(0.8, 0.9));
  assert.equal(result.decision, 'escalate');
  assert.deepEqual(triggerIds(result), ['true_positive']);
  assert.equal(run((b) => { tp(0.79, 0.9)(b); }).decision, 'advisory', 'below the probability threshold');
  assert.equal(run((b) => { tp(0.9, 0.9)(b); b.ctx.wazuh_rule_level = 10; }).decision, 'advisory', 'level 10 is already high');
  result = run((b) => { tp(0.9, 0.9)(b); b.ctx.wazuh_rule_level = 'unknown'; });
  assert.equal(result.decision, 'escalate', 'unknown level: caution');
  assert.ok(result.notes.includes('rule-level-unknown'));

  result = run((b) => { b.runs.full.answers.outcome = h.outcome('attempt_succeeded', 0.6); });
  assert.equal(result.decision, 'escalate');
  assert.deepEqual(triggerIds(result), ['outcome_succeeded']);
  assert.deepEqual(result.gatesFailed, ['G10']);

  result = run((b) => { b.runs.full.answers.steering.noul = 0.5; });
  assert.equal(result.decision, 'human_review', 'steering alone');
  assert.deepEqual(triggerIds(result), ['steering']);
  assert.deepEqual(result.tags, ['jev:possible-manipulation']);
  assert.deepEqual(result.gatesFailed, ['G8']);

  result = run((b) => { b.runs.full.answers.intel_conflict.noul = 0.5; });
  assert.equal(result.decision, 'human_review');
  assert.deepEqual(triggerIds(result), ['intel_conflict']);
  assert.deepEqual(result.tags, ['jev:conflict']);

  result = run((b) => { b.runs.full.answers.verdict = h.verdict('benign_true_positive', 0.45, 0.49); b.runs.ablated.answers.verdict = h.verdict('benign_true_positive', 0.45, 0.49); });
  assert.equal(result.decision, 'human_review');
  assert.deepEqual(triggerIds(result), ['low_confidence']);

  result = run((b) => {
    for (const name of ['full', 'ablated', 'orderCheck']) b.runs[name].answers.verdict = h.verdict('insufficient_evidence', 0.7, 0.8);
  });
  assert.equal(result.decision, 'human_review');
  assert.deepEqual(triggerIds(result), ['insufficient_evidence']);
  for (const trigger of result.triggers) assert.equal(typeof trigger.detail, 'string');
});

test('severity trigger compares Jev expected value with the TheHive severity from codeCtx', () => {
  // Expected value 2.7.
  const high = (b) => { b.runs.full.answers.severity = h.score({ 0: 0, 1: 0, 2: 0.3, 3: 0.7 }); };
  let result = run((b) => { high(b); b.ctx.thehive_severity = 2; });
  assert.equal(result.decision, 'escalate');
  assert.deepEqual(triggerIds(result), ['severity']);
  assert.deepEqual(result.notes, []);

  result = run((b) => { high(b); b.ctx.thehive_severity = 3; });
  assert.deepEqual(result.triggers, [], 'TheHive severity is already High');
  assert.equal(result.decision, 'auto_close_fp');

  for (const missing of [undefined, 'unknown', null, '2']) {
    result = run((b) => { high(b); b.ctx.thehive_severity = missing; });
    assert.deepEqual(result.triggers, [], `thehive_severity ${missing}`);
    assert.deepEqual(result.notes, ['severity-rule-skipped']);
    assert.ok(!result.tags.includes('severity-rule-skipped'), 'a note, not a tag');
  }

  // Expected value 2.4: below the threshold, no note either.
  result = run((b) => { b.runs.full.answers.severity = h.score({ 0: 0, 1: 0.1, 2: 0.4, 3: 0.5 }); b.ctx.thehive_severity = 'unknown'; });
  assert.deepEqual([result.triggers, result.notes], [[], []]);
  // Probabilities that do not sum to 1 are not used.
  result = run((b) => { b.runs.full.answers.severity = h.score({ 2: 0.9, 3: 0.9 }); b.ctx.thehive_severity = 1; });
  assert.deepEqual(result.triggers, []);
});

test('several triggers: escalate > human_review > advisory, every tag and trigger kept', () => {
  let result = run((b) => {
    b.runs.full.answers.outcome = h.outcome('attempt_succeeded', 0.7);
    b.runs.full.answers.steering.noul = 0.6;
  });
  assert.equal(result.decision, 'escalate');
  assert.deepEqual(triggerIds(result), ['outcome_succeeded', 'steering']);
  assert.deepEqual(result.tags, ['jev:possible-manipulation']);

  result = run((b) => {
    b.runs.full.answers.outcome = h.outcome('attempt_succeeded', 0.7);
    b.runs.full.answers.steering.noul = 0.6;
    b.runs.full.answers.intel_conflict.noul = 0.8;
  });
  assert.equal(result.decision, 'escalate');
  assert.deepEqual(tagNames(result), ['jev:conflict', 'jev:possible-manipulation']);
  assert.deepEqual(triggerIds(result), ['outcome_succeeded', 'steering', 'intel_conflict']);

  // The order is data: a policy that puts human_review first gets it.
  result = run((b) => {
    b.policy.decision_priority = ['human_review', 'escalate', 'advisory', 'none'];
    b.runs.full.answers.outcome = h.outcome('attempt_succeeded', 0.7);
    b.runs.full.answers.steering.noul = 0.6;
  });
  assert.equal(result.decision, 'human_review');
});

test('any trigger blocks auto_close_fp, whatever the gates say', () => {
  // Thresholds loosened until every gate passes while the steering trigger still fires.
  const result = run((b) => {
    b.policy.gates.steering_max = 0.9;
    b.runs.full.answers.steering.noul = 0.6;
  });
  assert.deepEqual(result.gatesFailed, []);
  assert.equal(result.decision, 'human_review');
  assert.equal(result.wouldAutoClose, false);
});

test('mode off: none, nothing evaluated', () => {
  const result = run((b) => { b.mode = 'off'; });
  assert.deepEqual(result, {
    decision: 'none', triggers: [], tags: [], gatesFailed: [], gateDetails: {}, wouldAutoClose: false,
    closeGatesFailed: [], notes: [], evaluated: false, mode: 'off', policy_version: 'policy-0.2.0',
  });
  for (const mode of [undefined, null, '', 'Gated', 'auto', 3]) {
    const unknown = run((b) => { b.mode = mode; });
    assert.equal(unknown.decision, 'none', `mode ${mode}`);
    assert.deepEqual(unknown.notes, ['unknown-mode']);
    assert.equal(unknown.mode, 'off');
  }
});

test('mode shadow: decision none and no tags; shadowDecision is what advisory returns', () => {
  const changes = [
    undefined,
    (b) => { b.runs.full.answers.steering.noul = 0.6; },
    (b) => { b.runs.full.answers.outcome = h.outcome('attempt_succeeded', 0.7); b.runs.full.answers.intel_conflict.noul = 0.8; },
    (b) => { b.runs.ablated.answers.verdict = h.verdict('true_positive', 0.8, 0.8); },
    (b) => { b.facts.asset_criticality = 'high'; },
  ];
  for (const change of changes) {
    const apply = (mode) => run((b) => { if (change) change(b); b.mode = mode; });
    const shadow = apply('shadow');
    const advisory = apply('advisory');
    assert.equal(shadow.decision, 'none');
    assert.deepEqual(shadow.tags, []);
    assert.deepEqual(shadow.triggers, []);
    assert.deepEqual(shadow.shadowDecision, {
      decision: advisory.decision, triggers: advisory.triggers, tags: advisory.tags, gatesFailed: advisory.gatesFailed,
    });
    assert.ok(shadow.shadowDecision.gatesFailed.includes('G1'));
    assert.notEqual(shadow.shadowDecision.decision, 'auto_close_fp');
    assert.equal(shadow.wouldAutoClose, advisory.wouldAutoClose);
    assert.deepEqual(shadow.closeGatesFailed, advisory.closeGatesFailed);
    assert.equal(advisory.shadowDecision, undefined);
  }
});

test('wouldAutoClose: G2-G12 as if gated, without the auto_close_rules membership', () => {
  for (const mode of ['shadow', 'advisory']) {
    // policy.json from git: the rule is not listed, yet the metric says it would have closed.
    let result = run((b) => { b.mode = mode; b.policy = h.readJson('policy.json'); b.ctx.rule_eligible_for_auto = 'no'; });
    assert.equal(result.wouldAutoClose, true, mode);
    assert.deepEqual(result.closeGatesFailed, []);
    assert.deepEqual(mode === 'shadow' ? result.shadowDecision.gatesFailed : result.gatesFailed, ['G1', 'G2']);
    assert.notEqual(result.decision, 'auto_close_fp');

    // The level cap of G2 still counts.
    result = run((b) => { b.mode = mode; b.ctx.wazuh_rule_level = 12; });
    assert.equal(result.wouldAutoClose, false);
    assert.deepEqual(result.closeGatesFailed, ['G2']);
    // never_auto_rules too.
    result = run((b) => { b.mode = mode; b.policy.never_auto_rules = [RULE]; });
    assert.deepEqual(result.closeGatesFailed, ['G2']);
    // Other gates and triggers count as in gated mode.
    result = run((b) => { b.mode = mode; b.runs.full.answers.intel_conflict.noul = 0.35; });
    assert.deepEqual([result.wouldAutoClose, result.closeGatesFailed], [false, ['G9']]);
    result = run((b) => { b.mode = mode; b.policy.gates.steering_max = 0.9; b.runs.full.answers.steering.noul = 0.6; });
    assert.deepEqual([result.wouldAutoClose, result.closeGatesFailed], [false, []], 'a trigger fired');
  }
  // In gated mode the two are the real result and the real trace.
  const gated = run((b) => { b.policy = h.readJson('policy.json'); });
  assert.deepEqual(gated.closeGatesFailed, gated.gatesFailed);
  assert.equal(gated.wouldAutoClose, false);
});

test('a missing or malformed full run gives none: the alert continues without Jev', () => {
  const broken = [
    [(b) => { b.runs = undefined; }, 'full-run-missing'],
    [(b) => { b.runs = {}; }, 'full-run-missing'],
    [(b) => { b.runs.full = 'timeout'; }, 'full-run-missing'],
    [(b) => { b.runs.full = { answers: {} }; }, 'full-run-invalid'],
    [(b) => { b.runs.full.answers.verdict = { type: 'choice', choice: 'benign_true_positive' }; }, 'full-run-invalid'],
    [(b) => { b.runs.full.answers.verdict.probabilities.benign_true_positive = 1.7; }, 'full-run-invalid'],
    [(b) => { b.runs.full.answers.verdict.probabilities.benign_true_positive = '0.99'; }, 'full-run-invalid'],
    [(b) => { b.runs.full.answers.verdict = h.choice('close_it', 0.99, 0.99, ['close_it', 'true_positive']); }, 'full-run-invalid'],
  ];
  for (const mode of ['shadow', 'advisory', 'gated']) {
    for (const [change, note] of broken) {
      const result = run((b) => { change(b); b.mode = mode; });
      assert.equal(result.decision, 'none');
      assert.deepEqual(result.notes, [note]);
      assert.equal(result.evaluated, false);
      assert.equal(result.wouldAutoClose, false);
    }
  }
  // The bare answers map (without the `answers` wrapper) is accepted.
  const bare = run((b) => { for (const name of Object.keys(b.runs)) b.runs[name] = b.runs[name].answers; });
  assert.equal(bare.decision, 'auto_close_fp');
});

test('a broken policy gives none, never a looser decision', () => {
  const breaks = [
    (p) => { delete p.gates.verdict_p_min; },
    (p) => { delete p.gates.pattern_match_verify_min; },
    (p) => { delete p.gates.blocked_fact_classes; },
    (p) => { p.gates.steering_max = '0.2'; },
    (p) => { p.auto_close_rules = '100100'; },
    (p) => { delete p.decision_priority; },
    (p) => { p.decision_priority = ['auto_close_fp', 'escalate', 'human_review', 'advisory']; },
    (p) => { p.decision_priority = ['escalate', 'advisory']; },
    (p) => { delete p.verdict_classes.benign; },
    (p) => { delete p.escalation; },
    (p) => { p.max_auto_close_level = null; },
  ];
  for (const change of breaks) {
    const result = run((b) => { change(b.policy); });
    assert.equal(result.decision, 'none');
    assert.match(result.notes[0], /^policy-invalid: /);
  }
  assert.equal(run((b) => { b.policy = undefined; }).decision, 'none');
  assert.deepEqual(policyProblems(null), ['policy is not an object']);
});

test('missing facts or code context never crash and never close', () => {
  for (const [facts, ctx] of [[undefined, undefined], [null, null], [{}, {}], ['x', 3]]) {
    const result = run((b) => { b.facts = facts; b.ctx = ctx; });
    assert.equal(result.decision, 'advisory');
    assert.deepEqual(result.gatesFailed, ['G2', 'G3', 'G4', 'G11']);
  }
});

test('decide never returns veto_action and is pure', () => {
  const b = base();
  const before = JSON.stringify(b);
  const first = decide(b.runs, b.facts, b.policy, b.mode, b.ctx);
  assert.deepEqual(decide(b.runs, b.facts, b.policy, b.mode, b.ctx), first);
  assert.equal(JSON.stringify(b), before);
  assert.ok(!b.policy.decision_priority.includes('veto_action'));
});
