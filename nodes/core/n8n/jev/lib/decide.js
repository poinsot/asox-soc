// Jev decision step (docs/jev-implementation.md v0.2, 8.2-8.4, 9.2, 9.3).
// Stage 0, draft.
//
// decide(runs, facts, policy, mode, codeCtx) -> result
//   runs     { full, ablated, strictAblated, orderCheck }: Jev's answers for
//            the four requests of lib/request.js, each `{ answers: {...} }` or the
//            answers map itself (shape of doc 7.3)
//   facts    state.facts from lib/state.js
//   policy   parsed policy.json
//   mode     JEV_MODE: off | shadow | advisory | gated
//   codeCtx  values only code uses, never sent to Jev (lib/state.js
//            buildCodeCtx): wazuh_rule_id, wazuh_rule_level,
//            rule_eligible_for_auto, benign_pattern_verified,
//            thehive_severity, response_action_proposed
//
// result
//   decision          none | advisory | escalate | human_review | auto_close_fp
//   triggers          the 8.4 triggers that fired, [{ id, decision, detail }]
//   tags              jev:conflict, jev:possible-manipulation, jev:untrusted-dependent
//   gatesFailed       failed de-escalation gates of 8.3, ["G1", "G4", ...]
//   gateDetails       every failing reason of each failed gate:
//                     { G4: ["verdict p 0.90 < 0.95", "benign_pattern_verified no"], ... }
//   wouldAutoClose    metrics only outside gated mode: would the alert have
//   closeGatesFailed  been closed? G2-G12 as if the mode were gated, and G2
//   closeGateDetails  without the auto_close_rules membership. In gated mode
//                     they are the real result and the real gate trace.
//   consistency       what G6 and G7 compared, as values (doc 12.1), so the
//                     record step stores them and never recomputes them:
//                     { ablationDelta, strictAblationDelta, orderAgree }.
//                     A delta is |p in the full run - p in the ablated run|
//                     of the full run's verdict option, rounded to 6
//                     decimals; orderAgree is a boolean. null = the run or
//                     the probability is missing.
//   notes             things the record should say that are not tags
//   shadowDecision    shadow mode only: { decision, triggers, tags,
//                     gatesFailed } as advisory mode would have returned them
//
// Rules decided for stage 0 (README, "Decisions folded into v0.2"):
// - The decision is the first entry of policy.decision_priority among the
//   decisions of the fired triggers, or `advisory` when none fired.
// - Gates only gate auto_close_fp. A failed gate alone gives `advisory`.
// - Any fired trigger blocks auto_close_fp, whatever the gates say.
// - G6 compares the full run with the strict ablation (no untrusted section,
//   no fact derived from it). The plain ablation drives the tags
//   jev:untrusted-dependent and jev:possible-manipulation, and also fails
//   G6 when it disagrees: an alert is never closed carrying that tag.
// - G4: no benign verdict closes unless code verified a known benign pattern
//   for the alert (codeCtx.benign_pattern_verified), whatever Jev answers to
//   benign_pattern_match.
// - G12: no closure when a class fact reports prose or attack syntax.
// - In shadow mode the decision is always `none` and no tags are returned.
// - `veto_action` is never returned here: it belongs to guard-v1.
//
// Pure: no I/O, no require. Anything missing or malformed fails toward "an
// analyst sees the alert": a gate that cannot be checked has failed, and a
// broken policy or full run gives `none` (the alert continues without Jev).

const MODES = ['off', 'shadow', 'advisory', 'gated'];
const UNKNOWN = 'unknown';
const REQUIRED_NUMBERS = {
  gates: ['verdict_p_min', 'confidence_min', 'ablation_tolerance', 'steering_max', 'intel_conflict_max'],
  escalation: [
    'true_positive_p_min', 'true_positive_level_below', 'outcome_succeeded_p_min', 'severity_ev_min',
    'severity_thehive_below', 'steering_min', 'intel_conflict_min', 'confidence_below',
  ],
};
const REQUIRED_LISTS = {
  gates: ['asset_criticality_allowed', 'blocked_outcomes', 'misp_high_threat_old_age_buckets', 'blocked_fact_classes'],
  escalation: ['outcome_succeeded_options'],
  verdict_classes: ['malicious', 'benign', 'insufficient'],
};
const REQUIRED_PRIORITIES = ['escalate', 'human_review', 'advisory'];

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isProbability(value) {
  return typeof value === 'number' && value >= 0 && value <= 1;
}

function fmt(value) {
  if (value === undefined) return UNKNOWN;
  return typeof value === 'number' ? value.toFixed(2) : String(value);
}

// ------------------------------------------------------------------ policy

function policyProblems(policy) {
  const problems = [];
  if (!isObject(policy)) return ['policy is not an object'];
  if (typeof policy.version !== 'string') problems.push('version missing');
  if (!Array.isArray(policy.auto_close_rules)) problems.push('auto_close_rules is not a list');
  if (!Array.isArray(policy.never_auto_rules)) problems.push('never_auto_rules is not a list');
  if (!Number.isInteger(policy.max_auto_close_level)) problems.push('max_auto_close_level is not an integer');
  for (const [section, keys] of Object.entries(REQUIRED_NUMBERS)) {
    for (const key of keys) {
      if (!isObject(policy[section]) || typeof policy[section][key] !== 'number' || Number.isNaN(policy[section][key])) {
        problems.push(`${section}.${key} is not a number`);
      }
    }
  }
  for (const [section, keys] of Object.entries(REQUIRED_LISTS)) {
    for (const key of keys) {
      if (!isObject(policy[section]) || !Array.isArray(policy[section][key])) {
        problems.push(`${section}.${key} is not a list`);
      }
    }
  }
  const priority = Array.isArray(policy.decision_priority) ? policy.decision_priority : [];
  for (const decision of REQUIRED_PRIORITIES) {
    if (priority.indexOf(decision) === -1) problems.push(`decision_priority lacks ${decision}`);
  }
  if (priority.indexOf('auto_close_fp') !== -1) problems.push('decision_priority must not list auto_close_fp');
  return problems;
}

// ----------------------------------------------------------------- answers

function answersOf(run) {
  if (!isObject(run)) return null;
  return isObject(run.answers) ? run.answers : run;
}

function readNoul(answers, key) {
  const answer = answers ? answers[key] : undefined;
  return isObject(answer) && isProbability(answer.noul) ? answer.noul : null;
}

// { choice, p, confidence } or null. p is the probability of the chosen option.
function readChoice(answers, key) {
  const answer = answers ? answers[key] : undefined;
  if (!isObject(answer) || typeof answer.choice !== 'string' || !isObject(answer.probabilities)) return null;
  const p = answer.probabilities[answer.choice];
  if (!isProbability(p)) return null;
  return {
    choice: answer.choice,
    p,
    confidence: isProbability(answer.confidence) ? answer.confidence : null,
    probabilities: answer.probabilities,
  };
}

// Expected value of a Score answer, computed here because Jev does no
// arithmetic. null unless the probabilities are usable and sum to 1.
function readScoreEv(answers, key) {
  const answer = answers ? answers[key] : undefined;
  if (!isObject(answer) || !isObject(answer.probabilities)) return null;
  let total = 0;
  let expected = 0;
  for (const [level, p] of Object.entries(answer.probabilities)) {
    if (!/^\d+$/.test(level) || !isProbability(p)) return null;
    total += p;
    expected += Number(level) * p;
  }
  return Math.abs(total - 1) <= 0.01 ? expected : null;
}

// A run without attacker-controlled input against the full run. Computed
// once: G6 reads it and the result returns the deltas, so the gate and the
// record cannot disagree. Rounding removes float noise at the tolerance.
function compareRuns(verdict, other) {
  if (!other) return { choice: null, sameVerdict: null, delta: null };
  const otherP = other.probabilities[verdict.choice];
  return {
    choice: other.choice,
    sameVerdict: other.choice === verdict.choice,
    delta: isProbability(otherP) ? Math.round(Math.abs(verdict.p - otherP) * 1e6) / 1e6 : null,
  };
}

function verdictClass(policy, choice) {
  for (const name of ['malicious', 'benign', 'insufficient']) {
    if (policy.verdict_classes[name].indexOf(choice) !== -1) return name;
  }
  return null;
}

// ---------------------------------------------------------------- triggers

function evaluateTriggers(read, policy, ctx, out) {
  const rules = policy.escalation;
  const fire = (id, decision, detail, tag) => {
    out.triggers.push({ id, decision, detail });
    if (tag && out.tags.indexOf(tag) === -1) out.tags.push(tag);
  };
  const { verdict, ablatedVerdict, outcome, steering, conflict, severityEv } = read;
  const fullClass = verdictClass(policy, verdict.choice);

  if (fullClass === 'malicious' && verdict.p >= rules.true_positive_p_min) {
    const level = ctx.wazuh_rule_level;
    if (!Number.isInteger(level)) {
      out.notes.push('rule-level-unknown');
      fire('true_positive', 'escalate', `verdict ${verdict.choice} p ${fmt(verdict.p)} >= ${fmt(rules.true_positive_p_min)}, rule level unknown`);
    } else if (level < rules.true_positive_level_below) {
      fire('true_positive', 'escalate', `verdict ${verdict.choice} p ${fmt(verdict.p)} >= ${fmt(rules.true_positive_p_min)}, rule level ${level} < ${rules.true_positive_level_below}`);
    }
  }
  if (outcome && rules.outcome_succeeded_options.indexOf(outcome.choice) !== -1 && outcome.p >= rules.outcome_succeeded_p_min) {
    fire('outcome_succeeded', 'escalate', `outcome ${outcome.choice} p ${fmt(outcome.p)} >= ${fmt(rules.outcome_succeeded_p_min)}`);
  }
  if (severityEv !== null && severityEv >= rules.severity_ev_min) {
    const current = ctx.thehive_severity;
    if (!Number.isInteger(current)) {
      // Jev's severity alone is a judgment: without the alert's current
      // severity there is nothing to compare it with, so the rule is skipped.
      out.notes.push('severity-rule-skipped');
    } else if (current < rules.severity_thehive_below) {
      fire('severity', 'escalate', `severity expected value ${fmt(severityEv)} >= ${fmt(rules.severity_ev_min)}, TheHive severity ${current} < ${rules.severity_thehive_below}`);
    }
  }
  if (steering !== null && steering >= rules.steering_min) {
    fire('steering', 'human_review', `steering ${fmt(steering)} >= ${fmt(rules.steering_min)}`, 'jev:possible-manipulation');
  }
  // The untrusted text turned a malicious verdict into a benign one: the
  // signature of an injection. A probability shift alone is not (see G6).
  if (ablatedVerdict && verdictClass(policy, ablatedVerdict.choice) === 'malicious' && fullClass === 'benign') {
    fire('ablation_verdict_flip', 'human_review', `verdict ${ablatedVerdict.choice} without untrusted, ${verdict.choice} with it`, 'jev:possible-manipulation');
  }
  if (conflict !== null && conflict >= rules.intel_conflict_min) {
    fire('intel_conflict', 'human_review', `intel_conflict ${fmt(conflict)} >= ${fmt(rules.intel_conflict_min)}`, 'jev:conflict');
  }
  if (verdict.confidence !== null && verdict.confidence < rules.confidence_below) {
    fire('low_confidence', 'human_review', `confidence ${fmt(verdict.confidence)} < ${fmt(rules.confidence_below)}`);
  }
  if (fullClass === 'insufficient') {
    fire('insufficient_evidence', 'human_review', `verdict ${verdict.choice}`);
  }
}

// ------------------------------------------------------------------- gates

// Returns [{ id, reason }], one entry per failing reason, in gate order: a
// gate with two reasons to fail appears twice (gateTrace groups them).
// `hypothetical` answers "would it have closed?": G1 is not checked and G2
// ignores the auto_close_rules membership (the list is empty until stage 3).
function evaluateGates(read, facts, policy, mode, ctx, hypothetical, out) {
  const gates = policy.gates;
  const failed = [];
  const fail = (id, reason) => failed.push({ id, reason });
  const { verdict, ablatedVerdict, strictVerdict, outcome, steering, conflict } = read;

  if (!hypothetical && mode !== 'gated') fail('G1', `mode ${mode}`);

  const ruleId = ctx.wazuh_rule_id;
  const level = ctx.wazuh_rule_level;
  const known = typeof ruleId === 'string' && ruleId !== '' && ruleId !== UNKNOWN;
  if (!known) {
    fail('G2', 'rule id unknown');
  } else {
    if (policy.never_auto_rules.map(String).indexOf(ruleId) !== -1) fail('G2', `rule ${ruleId} is in never_auto_rules`);
    if (!hypothetical && policy.auto_close_rules.map(String).indexOf(ruleId) === -1) {
      fail('G2', `rule ${ruleId} is not in auto_close_rules`);
    }
  }
  if (!hypothetical && ctx.rule_eligible_for_auto !== 'yes') fail('G2', 'rule_eligible_for_auto is not yes');
  if (!Number.isInteger(level)) fail('G2', 'rule level unknown');
  else if (level >= policy.max_auto_close_level) fail('G2', `rule level ${level} >= ${policy.max_auto_close_level}`);

  if (gates.asset_criticality_allowed.indexOf(facts.asset_criticality) === -1) {
    fail('G3', `asset_criticality ${fmt(facts.asset_criticality)}`);
  }

  if (verdictClass(policy, verdict.choice) !== 'benign') {
    fail('G4', `verdict ${verdict.choice}`);
  } else if (verdict.p < gates.verdict_p_min) {
    fail('G4', `verdict p ${fmt(verdict.p)} < ${fmt(gates.verdict_p_min)}`);
  }
  if (ctx.benign_pattern_verified !== 'yes') {
    // Jev's word is never enough to close on: code must have confirmed a
    // known benign pattern for this alert, whatever Jev says it matched.
    fail('G4', `benign_pattern_verified ${fmt(ctx.benign_pattern_verified)}`);
  }

  if (verdict.confidence === null) {
    fail('G5', 'confidence missing');
  } else if (verdict.confidence < gates.confidence_min) {
    fail('G5', `confidence ${fmt(verdict.confidence)} < ${fmt(gates.confidence_min)}`);
  }

  // Why a run without attacker-controlled input disagrees with the full
  // run; empty when it agrees within the tolerance.
  const disagreements = (compared, label) => {
    const reasons = [];
    if (!compared.sameVerdict) reasons.push(`verdict ${compared.choice} ${label}, ${verdict.choice} in the full run`);
    if (compared.delta === null) reasons.push(`probability missing ${label}`);
    else if (compared.delta > gates.ablation_tolerance) reasons.push(`delta ${fmt(compared.delta)} > ${fmt(gates.ablation_tolerance)} ${label}`);
    return reasons;
  };
  const note = (text) => { if (out && out.notes.indexOf(text) === -1) out.notes.push(text); };
  const strictReasons = strictVerdict ? disagreements(read.strict, 'in the strict ablation') : ['strict ablated run missing'];
  const plainReasons = ablatedVerdict ? disagreements(read.plain, 'without untrusted') : ['ablated run missing'];
  // The judgment depends on attacker-writable text. That blocks
  // de-escalation and is worth showing; it is not, alone, manipulation.
  if (ablatedVerdict && plainReasons.length > 0 && out && out.tags.indexOf('jev:untrusted-dependent') === -1) {
    out.tags.push('jev:untrusted-dependent');
  }
  if (!strictVerdict) note('strict-ablation-missing');
  if (!ablatedVerdict) note('ablation-missing');
  for (const reason of strictReasons.concat(plainReasons)) fail('G6', reason);

  if (read.orderAgree === null) {
    fail('G7', 'order-check run missing');
    note('order-check-missing');
  } else if (!read.orderAgree) {
    fail('G7', `verdict ${read.orderVerdict.choice} with options reversed`);
  }

  if (steering === null) fail('G8', 'steering missing');
  else if (steering >= gates.steering_max) fail('G8', `steering ${fmt(steering)} >= ${fmt(gates.steering_max)}`);

  if (conflict === null) fail('G9', 'intel_conflict missing');
  else if (conflict >= gates.intel_conflict_max) fail('G9', `intel_conflict ${fmt(conflict)} >= ${fmt(gates.intel_conflict_max)}`);

  if (!outcome) fail('G10', 'outcome missing');
  else if (gates.blocked_outcomes.indexOf(outcome.choice) !== -1) fail('G10', `outcome ${outcome.choice}`);

  const misp = facts.misp_match;
  if (facts.related_high_alerts !== 'none') fail('G11', `related_high_alerts ${fmt(facts.related_high_alerts)}`);
  if (misp !== 'none' && !isObject(misp)) {
    fail('G11', `misp_match ${fmt(misp)}`);
  } else if (isObject(misp) && ['low', 'medium', 'high'].indexOf(misp.threat_level) === -1) {
    fail('G11', `misp threat_level ${fmt(misp.threat_level)}`);
  } else if (isObject(misp) && misp.threat_level === 'high'
      && gates.misp_high_threat_old_age_buckets.indexOf(misp.newest_event_age) === -1) {
    fail('G11', `misp threat_level high, newest event ${fmt(misp.newest_event_age)}`);
  }
  if (ctx.response_action_proposed !== false) {
    fail('G11', ctx.response_action_proposed === true
      ? 'a response action is proposed' : 'response_action_proposed unknown');
  }

  // G12: a class fact computed in code says the untrusted input carries
  // prose or attack syntax.
  for (const name of Object.keys(facts)) {
    if (typeof facts[name] === 'string' && gates.blocked_fact_classes.indexOf(facts[name]) !== -1) {
      fail('G12', `${name} ${facts[name]}`);
    }
  }

  return failed;
}

// { ids: ["G2", "G4"], details: { G2: [reason, ...], G4: [...] } }
function gateTrace(failed) {
  const ids = [];
  const details = {};
  for (const { id, reason } of failed) {
    if (!details[id]) {
      ids.push(id);
      details[id] = [];
    }
    details[id].push(reason);
  }
  return { ids, details };
}

// ------------------------------------------------------------- entry point

function emptyResult(mode, policy, note) {
  return {
    decision: 'none',
    triggers: [],
    tags: [],
    gatesFailed: [],
    gateDetails: {},
    wouldAutoClose: false,
    closeGatesFailed: [],
    closeGateDetails: {},
    consistency: { ablationDelta: null, strictAblationDelta: null, orderAgree: null },
    notes: note ? [note] : [],
    evaluated: false,
    mode,
    policy_version: isObject(policy) && typeof policy.version === 'string' ? policy.version : UNKNOWN,
  };
}

function decide(runs, facts, policy, mode, codeCtx) {
  if (MODES.indexOf(mode) === -1) return emptyResult('off', policy, 'unknown-mode');
  if (mode === 'off') return emptyResult(mode, policy);
  const problems = policyProblems(policy);
  if (problems.length > 0) return emptyResult(mode, policy, `policy-invalid: ${problems.join('; ')}`);

  const full = answersOf(isObject(runs) ? runs.full : null);
  if (!full) return emptyResult(mode, policy, 'full-run-missing');
  const verdict = readChoice(full, 'verdict');
  if (!verdict || verdictClass(policy, verdict.choice) === null) return emptyResult(mode, policy, 'full-run-invalid');

  const f = isObject(facts) ? facts : {};
  const ctx = isObject(codeCtx) ? codeCtx : {};
  const read = {
    verdict,
    ablatedVerdict: readChoice(answersOf(runs.ablated), 'verdict'),
    strictVerdict: readChoice(answersOf(runs.strictAblated), 'verdict'),
    orderVerdict: readChoice(answersOf(runs.orderCheck), 'verdict'),
    outcome: readChoice(full, 'outcome'),
    steering: readNoul(full, 'steering'),
    conflict: readNoul(full, 'intel_conflict'),
    severityEv: readScoreEv(full, 'severity'),
  };
  read.plain = compareRuns(verdict, read.ablatedVerdict);
  read.strict = compareRuns(verdict, read.strictVerdict);
  read.orderAgree = read.orderVerdict ? read.orderVerdict.choice === verdict.choice : null;

  const out = { triggers: [], tags: [], notes: [] };
  evaluateTriggers(read, policy, ctx, out);
  const realGates = gateTrace(evaluateGates(read, f, policy, mode, ctx, false, out));
  const closeGates = mode === 'gated' ? realGates : gateTrace(evaluateGates(read, f, policy, mode, ctx, true, null));

  // What stage 2 does with the triggers; `advisory` when none fired.
  const fired = out.triggers.map((trigger) => trigger.decision);
  const advisoryDecision = policy.decision_priority
    .find((candidate) => candidate === 'advisory' || fired.indexOf(candidate) !== -1);

  const noTriggers = out.triggers.length === 0;
  const gatesFailed = realGates.ids;
  const result = {
    decision: advisoryDecision,
    triggers: out.triggers,
    tags: out.tags,
    gatesFailed,
    gateDetails: realGates.details,
    wouldAutoClose: noTriggers && closeGates.ids.length === 0,
    closeGatesFailed: closeGates.ids,
    closeGateDetails: closeGates.details,
    consistency: {
      ablationDelta: read.plain.delta,
      strictAblationDelta: read.strict.delta,
      orderAgree: read.orderAgree,
    },
    notes: out.notes,
    evaluated: true,
    mode,
    policy_version: policy.version,
  };

  // The only path to auto_close_fp: mode gated, every gate passed (G2
  // includes "rule listed in auto_close_rules") and no trigger fired.
  if (mode === 'gated' && noTriggers && gatesFailed.length === 0) result.decision = 'auto_close_fp';

  if (mode === 'shadow') {
    result.shadowDecision = {
      decision: advisoryDecision,
      triggers: out.triggers,
      tags: out.tags,
      gatesFailed,
    };
    result.decision = 'none';
    result.triggers = [];
    result.tags = [];
  }
  return result;
}

const jevDecide = { decide, policyProblems, MODES };

if (typeof module !== 'undefined' && module.exports) module.exports = jevDecide;
