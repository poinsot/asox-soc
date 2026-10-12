// Shared helpers for the unit tests: load the versioned config of this
// folder, load fixtures, and build mocked Jev answers.
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

function readJson(relativePath) {
  return JSON.parse(fs.readFileSync(path.join(ROOT, relativePath), 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

const CONFIG_FILES = [
  'policy.json', 'playbooks.json', 'assets.json', 'benign-patterns.json', 'untrusted-fields.json',
  'intel-fields.json', 'path-classes.json', 'user-agent-classes.json', 'questions/triage-v1.json',
];

// The config as buildState takes it, from the files in git. `now` is fixed
// so the date buckets are reproducible.
function loadConfig(now) {
  return {
    policy: readJson('policy.json'),
    assets: readJson('assets.json'),
    benignPatterns: readJson('benign-patterns.json'),
    untrustedFields: readJson('untrusted-fields.json'),
    intelFields: readJson('intel-fields.json'),
    pathClasses: readJson('path-classes.json'),
    userAgentClasses: readJson('user-agent-classes.json'),
    now: now || '2026-10-12T12:00:00Z',
  };
}

// A fixture's `config` block overrides parts of the versioned config (an
// asset that only exists in the scenario, for example).
function configFor(fixture) {
  const config = loadConfig(fixture.now);
  const overrides = fixture.config || {};
  if (overrides.assets) Object.assign(config.assets.assets, overrides.assets);
  if (overrides.benign_patterns) config.benignPatterns.patterns = overrides.benign_patterns;
  if (overrides.networks) Object.assign(config.policy.state.networks, overrides.networks);
  return config;
}

function loadFixture(name) {
  return readJson(path.join('tests', 'fixtures', name));
}

function adversarialFixtures() {
  const dir = path.join(ROOT, 'tests', 'fixtures', 'adversarial');
  return fs.readdirSync(dir).filter((file) => file.endsWith('.json')).sort()
    .map((file) => readJson(path.join('tests', 'fixtures', 'adversarial', file)));
}

// A policy in which stage 3 is open for the given rules. Only tests build
// one: policy.json in git keeps auto_close_rules empty.
function eligiblePolicy(ruleIds) {
  const policy = readJson('policy.json');
  policy.auto_close_rules = ruleIds.map(String);
  return policy;
}

function choice(chosen, p, confidence, options) {
  const others = options.filter((option) => option !== chosen);
  const probabilities = {};
  for (const option of options) {
    probabilities[option] = option === chosen ? p : Number(((1 - p) / others.length).toFixed(6));
  }
  return { type: 'choice', choice: chosen, confidence, probabilities };
}

const VERDICTS = ['true_positive', 'benign_true_positive', 'false_positive', 'insufficient_evidence'];
const OUTCOMES = ['attempt_failed', 'attempt_succeeded', 'informational', 'unclear'];

function verdict(chosen, p, confidence) {
  return choice(chosen, p, confidence === undefined ? 0.95 : confidence, VERDICTS);
}

function outcome(chosen, p) {
  return choice(chosen, p, 0.9, OUTCOMES);
}

function score(probabilities) {
  let best = '0';
  for (const level of Object.keys(probabilities)) if (probabilities[level] > probabilities[best]) best = level;
  return { type: 'score', score: Number(best), confidence: 0.8, probabilities };
}

// Three runs in which every Jev-side gate passes and no trigger fires: a
// confident benign verdict, stable without the untrusted text and with the
// options reversed. Tests change one thing at a time from here.
function passingRuns() {
  return {
    full: {
      answers: {
        verdict: verdict('benign_true_positive', 0.97, 0.95),
        benign_pattern_match: { type: 'noul', noul: 0.96 },
        shared_infrastructure: { type: 'noul', noul: 0.1 },
        intel_conflict: { type: 'noul', noul: 0.05 },
        role_consistency: score({ 0: 0.02, 1: 0.08, 2: 0.9 }),
        outcome: outcome('informational', 0.9),
        severity: score({ 0: 0.6, 1: 0.3, 2: 0.08, 3: 0.02 }),
        steering: { type: 'noul', noul: 0.02 },
        playbook: choice('pb-generic', 1, 1, ['pb-generic']),
      },
    },
    ablated: { answers: { verdict: verdict('benign_true_positive', 0.96, 0.94) } },
    orderCheck: { answers: { verdict: verdict('benign_true_positive', 0.96, 0.94) } },
  };
}

// Facts and code context with which every code-side gate passes.
function passingFacts() {
  return {
    observable_type: 'ip',
    ip_scope: 'public',
    direction: 'inbound',
    seen_before: 'more than 50 times',
    first_seen: 'more than 30 days ago',
    last_seen: 'less than 24 hours ago',
    related_high_alerts: 'none',
    misp_match: 'none',
    warninglists: [],
    asset_criticality: 'low',
    request_path_class: 'health_check',
    user_agent_class: 'claims_monitoring_tool',
  };
}

function passingCtx(ruleId) {
  return {
    wazuh_rule_id: String(ruleId),
    wazuh_rule_level: 7,
    rule_eligible_for_auto: 'yes',
    thehive_severity: 2,
    response_action_proposed: false,
  };
}

module.exports = {
  ROOT, CONFIG_FILES, readJson, clone, loadConfig, configFor, loadFixture, adversarialFixtures,
  eligiblePolicy, verdict, outcome, score, choice, passingRuns, passingFacts, passingCtx, VERDICTS,
};
