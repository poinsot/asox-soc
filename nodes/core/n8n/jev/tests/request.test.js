const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const h = require('./helpers.js');
const s = require('../lib/state.js');
const r = require('../lib/request.js');

const MODEL = 'model-name-from-configuration';

function scenario() {
  const fixture = h.loadFixture('scenario-6.6.json');
  const config = h.configFor(fixture);
  const state = s.buildState(fixture.alert, fixture.enrichment, config);
  const questionSet = r.resolveQuestionSet(h.readJson('questions/triage-v1.json'), h.readJson('playbooks.json'));
  return { fixture, config, state, questionSet };
}

test('sha256Hex matches node:crypto', () => {
  assert.equal(r.sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  for (const text of ['', 'a', 'x'.repeat(55), 'x'.repeat(56), 'x'.repeat(64), 'x'.repeat(1000), 'ñ – 日本 😀', JSON.stringify(h.readJson('playbooks.json'))]) {
    assert.equal(r.sha256Hex(text), crypto.createHash('sha256').update(text, 'utf8').digest('hex'), `length ${text.length}`);
  }
});

test('resolveQuestionSet: playbook options from the catalog, version carries its hash', () => {
  const file = h.readJson('questions/triage-v1.json');
  const catalog = h.readJson('playbooks.json');
  const set = r.resolveQuestionSet(file, catalog);
  assert.match(set.version, /^triage-v1\+pb\.[0-9a-f]{12}$/);
  assert.equal(set.base_version, 'triage-v1');
  assert.deepEqual(Object.keys(set.questions.playbook.criteria), ['pb-generic']);
  assert.equal(set.questions.playbook.criteria_from, undefined);
  assert.deepEqual(file.questions.playbook.criteria, {}, 'the file object is not modified');
  assert.equal(r.resolveQuestionSet(file, catalog).version, set.version, 'stable');

  const added = h.clone(catalog);
  added.playbooks.unshift({ id: 'pb-ssh-bruteforce', description: 'Repeated failed SSH logins from one source.' });
  const bigger = r.resolveQuestionSet(file, added);
  assert.notEqual(bigger.version, set.version, 'a new playbook changes the version');
  assert.deepEqual(Object.keys(bigger.questions.playbook.criteria), ['pb-ssh-bruteforce', 'pb-generic']);

  const reworded = h.clone(catalog);
  reworded.playbooks[0].description += ' Reworded.';
  assert.notEqual(r.resolveQuestionSet(file, reworded).version, set.version, 'a reworded description changes the version');
  const renumbered = h.clone(catalog);
  renumbered.version = 'playbooks-2';
  assert.equal(r.resolveQuestionSet(file, renumbered).version, set.version, 'the hash covers what Jev is shown');
});

test('resolveQuestionSet refuses a set that would produce a wrong request', () => {
  const file = h.readJson('questions/triage-v1.json');
  const catalog = h.readJson('playbooks.json');
  assert.throws(() => r.resolveQuestionSet(file, { playbooks: [] }), /catalog is empty/);
  assert.throws(() => r.resolveQuestionSet(file, undefined), /catalog is empty/);
  assert.throws(() => r.resolveQuestionSet({}, catalog), /version and questions/);
  assert.throws(() => r.resolveQuestionSet(file, { playbooks: [catalog.playbooks[0], catalog.playbooks[0]] }), /listed twice/);
  assert.throws(() => r.resolveQuestionSet(file, { playbooks: [{ id: '7', description: 'numeric id' }] }), /numeric option/);
  const broken = h.clone(file);
  broken.questions.verdict.type = 'essay';
  assert.throws(() => r.resolveQuestionSet(broken, catalog), /valid type/);
  const empty = h.clone(file);
  empty.questions.severity.criteria = {};
  assert.throws(() => r.resolveQuestionSet(empty, catalog), /no criteria/);
  const order = h.clone(file);
  order.order_check = ['steering'];
  assert.throws(() => r.resolveQuestionSet(order, catalog), /not a choice question/);
});

test('buildRequests: the model is a parameter', () => {
  const { state, questionSet } = scenario();
  assert.throws(() => r.buildRequests(state, questionSet), /model is required/);
  assert.throws(() => r.buildRequests(state, questionSet, { model: ' ' }), /model is required/);
  const requests = r.buildRequests(state, questionSet, { model: MODEL });
  for (const name of ['full', 'ablated', 'orderCheck']) {
    assert.deepEqual(Object.keys(requests[name]), ['model', 'state', 'questions']);
    assert.equal(requests[name].model, MODEL);
  }
});

test('full request: the state of doc 6.6 and all 9 questions in the 7.3 shape', () => {
  const { state, questionSet } = scenario();
  const { full } = r.buildRequests(state, questionSet, { model: MODEL });
  assert.deepEqual(full.state, state);
  assert.deepEqual(Object.keys(full.questions), Object.keys(questionSet.questions));
  assert.deepEqual(Object.keys(full.questions.verdict), ['type', 'instructions', 'criteria']);
  assert.deepEqual(Object.keys(full.questions.steering), ['type', 'instructions']);
  assert.deepEqual(Object.keys(full.questions.verdict.criteria), h.VERDICTS);
  assert.deepEqual(full.questions.playbook.criteria, { 'pb-generic': h.readJson('playbooks.json').playbooks[0].description });
  assert.ok(!JSON.stringify(full).includes('reads_untrusted'));
  // The request is a copy: changing it does not change the state.
  full.state.facts.ip_scope = 'changed';
  assert.equal(state.facts.ip_scope, 'public');
});

test('ablated request: no untrusted section, no question that reads it', () => {
  const { state, questionSet } = scenario();
  const { full, ablated } = r.buildRequests(state, questionSet, { model: MODEL });
  assert.deepEqual(Object.keys(ablated.state), ['alert', 'facts', 'intel', 'context']);
  assert.deepEqual(Object.keys(ablated.questions), [
    'verdict', 'benign_pattern_match', 'shared_infrastructure', 'intel_conflict', 'role_consistency', 'severity', 'playbook',
  ]);
  for (const key of Object.keys(ablated.questions)) assert.deepEqual(ablated.questions[key], full.questions[key]);
  for (const section of ['alert', 'facts', 'intel', 'context']) assert.deepEqual(ablated.state[section], full.state[section]);
  // The class facts derived in code stay; the raw values they came from do not.
  assert.equal(ablated.state.facts.request_path_class, 'health_check');
  assert.equal(ablated.state.facts.user_agent_class, 'claims_monitoring_tool');
  assert.ok(!JSON.stringify(ablated).includes('UptimeMonitor'));
});

test('order check: only the verdict question, options reversed, same texts', () => {
  const { state, questionSet } = scenario();
  const { full, orderCheck } = r.buildRequests(state, questionSet, { model: MODEL });
  assert.deepEqual(Object.keys(orderCheck.questions), ['verdict']);
  assert.deepEqual(Object.keys(orderCheck.questions.verdict.criteria), [...h.VERDICTS].reverse());
  assert.deepEqual(orderCheck.questions.verdict.criteria, full.questions.verdict.criteria, 'same options and texts');
  assert.equal(orderCheck.questions.verdict.instructions, full.questions.verdict.instructions);
  assert.deepEqual(orderCheck.state, full.state);
  // The reversed order survives serialization, which is what gets sent.
  assert.deepEqual(Object.keys(JSON.parse(JSON.stringify(orderCheck)).questions.verdict.criteria), [...h.VERDICTS].reverse());
});

test('no code-only value reaches a request body', () => {
  const { fixture, config, state, questionSet } = scenario();
  const ctx = s.buildCodeCtx(fixture.alert, h.eligiblePolicy(['100210']), { thehive_severity: 3, response_action_proposed: true });
  assert.deepEqual(Object.keys(ctx), ['wazuh_rule_id', 'wazuh_rule_level', 'rule_eligible_for_auto', 'thehive_severity', 'response_action_proposed']);
  // Even if a caller wrongly hangs the context (or anything else) on the state.
  const polluted = Object.assign({}, state, ctx, { codeCtx: ctx, policy: config.policy });
  for (const source of [state, polluted]) {
    const body = JSON.stringify(r.buildRequests(source, questionSet, { model: MODEL }));
    for (const key of Object.keys(ctx).concat(['codeCtx', 'auto_close_rules', 'policy'])) {
      assert.ok(!body.includes(`"${key}"`), `${key} is in a request body`);
    }
  }
});

test('buildRequests is pure: inputs untouched, same output twice', () => {
  const { state, questionSet } = scenario();
  const before = JSON.stringify([state, questionSet]);
  const first = r.buildRequests(state, questionSet, { model: MODEL });
  assert.deepEqual(r.buildRequests(state, questionSet, { model: MODEL }), first);
  assert.equal(JSON.stringify([state, questionSet]), before);
});
