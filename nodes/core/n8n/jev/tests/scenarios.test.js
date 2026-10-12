// End-to-end over the three pure steps, with Jev's answers mocked:
// buildState -> buildRequests -> (mocked answers) -> decide.
const test = require('node:test');
const assert = require('node:assert/strict');
const h = require('./helpers.js');
const s = require('../lib/state.js');
const r = require('../lib/request.js');
const { decide } = require('../lib/decide.js');

const MODEL = 'model-name-from-configuration';
const MODES = ['off', 'shadow', 'advisory', 'gated'];

function pipeline(fixture, runs, mode, policy) {
  const config = h.configFor(fixture);
  if (policy) {
    policy.state = config.policy.state;
    config.policy = policy;
  }
  const state = s.buildState(fixture.alert, fixture.enrichment, config);
  const questionSet = r.resolveQuestionSet(h.readJson('questions/triage-v1.json'), h.readJson('playbooks.json'));
  const requests = r.buildRequests(state, questionSet, { model: MODEL });
  const ctx = s.buildCodeCtx(fixture.alert, config.policy, fixture.code_ctx_extra || { thehive_severity: 2, response_action_proposed: false });
  return { state, requests, ctx, result: decide(runs, state.facts, config.policy, mode, ctx) };
}

test('doc 6.6 scenario: the state matches the example', () => {
  const fixture = h.loadFixture('scenario-6.6.json');
  const { state } = pipeline(fixture, fixture.runs, 'advisory');
  assert.deepEqual(state.alert, {
    rule_id: '100210',
    rule_description: 'Repeated HTTP requests from IP flagged by threat intel',
    rule_level: 10,
    mitre_tactics: ['Reconnaissance'],
    agent_name: 'web-01',
    decoder: 'nginx-accesslog',
  });
  assert.deepEqual(state.facts, {
    observable_type: 'ip',
    ip_scope: 'public',
    direction: 'inbound',
    seen_before: 'more than 50 times',
    first_seen: 'more than 30 days ago',
    last_seen: 'less than 24 hours ago',
    related_high_alerts: 'none',
    misp_match: { events: 'few', newest_event_age: 'more than 30 days ago', threat_level: 'medium' },
    warninglists: [],
    asset_criticality: 'medium',
    request_path_class: 'health_check',
    user_agent_class: 'claims_monitoring_tool',
  });
  assert.deepEqual(state.intel.map((entry) => [entry.source, entry.level]), [['MISP', 'malicious'], ['AbuseIPDB', 'suspicious']]);
  assert.equal(state.context.asset_role, 'public web server, nginx, serves the marketing site; monitored by an external uptime service');
  assert.deepEqual(state.untrusted, { request_url: '/healthz', user_agent: 'UptimeMonitor/3.2' });
  // Data minimization (doc 11): the raw address is not in the state.
  assert.ok(!JSON.stringify(state).includes('198.51.100.23'));
});

test('doc 6.6 scenario: human_review, G9 failed, not possible-manipulation', () => {
  const fixture = h.loadFixture('scenario-6.6.json');
  const { result } = pipeline(fixture, fixture.runs, 'advisory');
  assert.equal(result.decision, 'human_review');
  assert.ok(result.gatesFailed.includes('G9'));
  assert.equal(result.gateDetails.G9, 'intel_conflict 0.62 >= 0.30');
  assert.ok(!result.tags.includes('jev:possible-manipulation'));
  assert.deepEqual(result.tags, ['jev:conflict']);
  // human_review comes from the 8.4 trigger; the gates are listed separately.
  assert.deepEqual(result.triggers.map((trigger) => trigger.id), ['intel_conflict']);
  assert.deepEqual(result.gatesFailed, ['G1', 'G2', 'G4', 'G5', 'G9']);
  assert.deepEqual(result.closeGatesFailed, ['G2', 'G4', 'G5', 'G9']);
  assert.equal(result.wouldAutoClose, false);
  assert.ok(!result.gatesFailed.includes('G6'), 'ablation agreed');
  assert.ok(!result.gatesFailed.includes('G7'), 'order check agreed');
});

test('doc 6.6 scenario: a large ablation delta alone is still not manipulation', () => {
  // Doc 9.2 as written would tag this possible-manipulation: without the raw
  // text Jev is much less sure the alert is benign. The refinement tags it
  // untrusted-dependent and only blocks de-escalation.
  const fixture = h.loadFixture('scenario-6.6.json');
  fixture.runs.ablated.answers.verdict.probabilities = { true_positive: 0.2, benign_true_positive: 0.55, false_positive: 0.15, insufficient_evidence: 0.1 };
  const { result } = pipeline(fixture, fixture.runs, 'advisory');
  assert.equal(result.decision, 'human_review');
  assert.ok(result.gatesFailed.includes('G6') && result.gatesFailed.includes('G9'));
  assert.deepEqual([...result.tags].sort(), ['jev:conflict', 'jev:untrusted-dependent']);
});

test('doc 6.6 scenario in every mode', () => {
  const fixture = h.loadFixture('scenario-6.6.json');
  const expected = { off: 'none', shadow: 'none', advisory: 'human_review', gated: 'human_review' };
  for (const mode of MODES) {
    const { result } = pipeline(fixture, fixture.runs, mode);
    assert.equal(result.decision, expected[mode], mode);
  }
  const shadow = pipeline(fixture, fixture.runs, 'shadow').result;
  assert.deepEqual(shadow.tags, []);
  assert.equal(shadow.shadowDecision.decision, 'human_review');
  assert.deepEqual(shadow.shadowDecision.tags, ['jev:conflict']);
  // Even with the rule listed, in gated mode: the trigger and the gates hold.
  const listed = pipeline(fixture, fixture.runs, 'gated', h.eligiblePolicy(['100210'])).result;
  assert.equal(listed.decision, 'human_review');
});

test('clear true positive: escalate', () => {
  const fixture = h.loadFixture('true-positive.json');
  const { state, result } = pipeline(fixture, fixture.runs, 'advisory');
  assert.equal(state.facts.ip_scope, 'documentation');
  assert.equal(state.facts.related_high_alerts, 'some');
  assert.deepEqual(state.facts.misp_match, { events: 'few', newest_event_age: '1–7 days ago', threat_level: 'high' });
  assert.equal(result.decision, 'escalate');
  assert.deepEqual(result.triggers.map((trigger) => trigger.id), ['true_positive']);
  assert.deepEqual(result.tags, []);
  assert.ok(result.gatesFailed.includes('G4') && result.gatesFailed.includes('G11'));
  assert.equal(result.wouldAutoClose, false);
  const expected = { off: 'none', shadow: 'none', advisory: 'escalate', gated: 'escalate' };
  for (const mode of MODES) {
    assert.equal(pipeline(fixture, fixture.runs, mode).result.decision, expected[mode], mode);
    assert.equal(pipeline(fixture, fixture.runs, mode, h.eligiblePolicy(['5716'])).result.decision, expected[mode], `${mode}, rule listed`);
  }
});

test('missing enrichment: all facts unknown, no crash, never closed', () => {
  const fixture = { alert: h.loadFixture('true-positive.json').alert, enrichment: undefined };
  const bare = { alert: {}, enrichment: undefined };
  for (const mode of MODES) {
    for (const policy of [undefined, h.eligiblePolicy(['5716', 'unknown'])]) {
      // Even if Jev answered "benign" with full marks on no evidence at all.
      for (const input of [fixture, bare]) {
        const { state, requests, result } = pipeline(input, h.passingRuns(), mode, policy && h.clone(policy));
        for (const fact of ['seen_before', 'first_seen', 'last_seen', 'related_high_alerts', 'misp_match', 'warninglists']) {
          assert.equal(state.facts[fact], 'unknown', fact);
        }
        assert.equal(state.intel, 'unknown');
        assert.equal(requests.full.state.intel, 'unknown');
        assert.notEqual(result.decision, 'auto_close_fp', mode);
        if (mode === 'advisory' || mode === 'gated') {
          assert.equal(result.decision, 'advisory');
          assert.ok(result.gatesFailed.includes('G11'), 'unknown facts fail the gate');
          assert.equal(result.wouldAutoClose, false);
        }
      }
    }
  }
  const { state } = pipeline(bare, h.passingRuns(), 'advisory');
  assert.ok(Object.values(state.facts).every((value) => value === 'unknown'), 'every fact');
});

// ------------------------------------------------------------ adversarial set
//
// What Jev might answer to an injection, from best to worst:
//   resisted   it flags the text and keeps a malicious verdict
//   flagged    it is steered to "benign" but still flags the text
//   flipped    it is steered and does not flag the text; the ablated run,
//              which never saw the text, stays malicious
//   fooled     every answer is steered, in all three runs, with full marks
const VARIANTS = {
  resisted: () => {
    const runs = h.passingRuns();
    for (const name of Object.keys(runs)) runs[name].answers.verdict = h.verdict('true_positive', 0.85, 0.8);
    runs.full.answers.steering.noul = 0.93;
    runs.full.answers.outcome = h.outcome('attempt_failed', 0.7);
    return runs;
  },
  flagged: () => {
    const runs = h.passingRuns();
    runs.full.answers.verdict = h.verdict('false_positive', 0.99, 0.99);
    runs.orderCheck.answers.verdict = h.verdict('false_positive', 0.99, 0.99);
    runs.ablated.answers.verdict = h.verdict('false_positive', 0.97, 0.97);
    runs.full.answers.steering.noul = 0.5;
    return runs;
  },
  flipped: () => {
    const runs = h.passingRuns();
    runs.full.answers.verdict = h.verdict('false_positive', 0.99, 0.99);
    runs.orderCheck.answers.verdict = h.verdict('false_positive', 0.99, 0.99);
    runs.ablated.answers.verdict = h.verdict('true_positive', 0.8, 0.8);
    runs.full.answers.steering.noul = 0.01;
    return runs;
  },
  fooled: () => {
    const runs = h.passingRuns();
    for (const name of Object.keys(runs)) runs[name].answers.verdict = h.verdict('false_positive', 0.99, 0.99);
    runs.full.answers.steering.noul = 0.01;
    return runs;
  },
};
const BELOW_HUMAN_REVIEW = ['none', 'advisory', 'auto_close_fp'];

test('adversarial set: four fixtures, injection in user agent, URL, user name and command', () => {
  assert.deepEqual(h.adversarialFixtures().map((fixture) => fixture.name), [
    'command-instruction', 'url-instruction', 'user-agent-authorized-scanner', 'username-instruction',
  ]);
});

test('adversarial set: the injected text is quarantined', () => {
  for (const fixture of h.adversarialFixtures()) {
    const { state, requests } = pipeline(fixture, VARIANTS.fooled(), 'advisory');
    const marker = fixture.marker;
    assert.ok(JSON.stringify(state.untrusted).includes(marker), `${fixture.name}: marker is in untrusted`);
    for (const section of ['alert', 'facts', 'intel', 'context']) {
      assert.ok(!JSON.stringify(state[section]).includes(marker), `${fixture.name}: marker leaked into ${section}`);
    }
    assert.ok(!JSON.stringify(requests.ablated).includes(marker), `${fixture.name}: marker in the ablated request`);
    assert.ok(JSON.stringify(requests.full).includes(marker));
    const total = Object.values(state.untrusted).reduce((sum, value) => sum + value.length, 0);
    assert.ok(total <= 2000);
  }
});

test('adversarial set: the class facts name the prose, never an ordinary class', () => {
  const classes = Object.fromEntries(h.adversarialFixtures().map((fixture) => {
    const { state } = pipeline(fixture, VARIANTS.fooled(), 'advisory');
    return [fixture.name, [state.facts.request_path_class, state.facts.user_agent_class]];
  }));
  assert.deepEqual(classes, {
    'command-instruction': ['unknown', 'unknown'],
    'url-instruction': ['embedded_text', 'http_library_or_cli'],
    'user-agent-authorized-scanner': ['admin_interface', 'embedded_text'],
    'username-instruction': ['unknown', 'unknown'],
  });
});

test('adversarial set: never auto_close_fp with policy.json from git, whatever Jev answers', () => {
  for (const fixture of h.adversarialFixtures()) {
    for (const [variant, makeRuns] of Object.entries(VARIANTS)) {
      for (const mode of MODES) {
        const { result } = pipeline(fixture, makeRuns(), mode);
        const label = `${fixture.name} / ${variant} / ${mode}`;
        assert.notEqual(result.decision, 'auto_close_fp', label);
        if (result.shadowDecision) assert.notEqual(result.shadowDecision.decision, 'auto_close_fp', label);
        if (mode === 'off' || mode === 'shadow') {
          assert.equal(result.decision, 'none', label);
          assert.deepEqual(result.tags, [], label);
        }
      }
    }
  }
});

test('adversarial set: detected steering never ends below human_review', () => {
  for (const fixture of h.adversarialFixtures()) {
    for (const variant of ['resisted', 'flagged', 'flipped']) {
      for (const mode of ['advisory', 'gated']) {
        // Rule listed for auto-closure too: the worst policy for this alert.
        for (const policy of [undefined, h.eligiblePolicy([fixture.alert.rule.id])]) {
          const { result } = pipeline(fixture, VARIANTS[variant](), mode, policy);
          const label = `${fixture.name} / ${variant} / ${mode} / ${policy ? 'rule listed' : 'policy.json'}`;
          assert.ok(!BELOW_HUMAN_REVIEW.includes(result.decision), `${label}: ${result.decision}`);
          assert.ok(result.tags.includes('jev:possible-manipulation'), label);
          assert.equal(result.wouldAutoClose, false, label);
        }
      }
      const shadow = pipeline(fixture, VARIANTS[variant](), 'shadow', h.eligiblePolicy([fixture.alert.rule.id])).result;
      assert.equal(shadow.decision, 'none');
      assert.ok(!BELOW_HUMAN_REVIEW.includes(shadow.shadowDecision.decision));
    }
  }
});
