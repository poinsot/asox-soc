// Jev request builder (docs/jev-implementation.md 7.3, 9.2, 9.3). Stage 0, draft.
//
// resolveQuestionSet(questionSetFile, playbooksFile) -> questionSet
//   Fills the `playbook` options from the catalog and returns the effective
//   question set. Its version is "<file version>+pb.<12 hex of SHA-256 of the
//   catalog>", so a judgment records which catalog it was asked with.
//
// buildRequests(state, questionSet, options) -> { full, ablated, orderCheck }
//   options.model is required: the model name is configuration (JEV_MODEL),
//   never written here. Each result is a request body { model, state,
//   questions }. Nothing is sent: there is no network code in this file.
//
// Pure: no I/O, no require. Both functions throw on input that would produce
// a wrong request (a missing model, an empty catalog, an unknown question
// type); the caller treats that as jev_status "error" (doc 10.4).

const STATE_SECTIONS = ['alert', 'facts', 'intel', 'context', 'untrusted'];
const QUESTION_TYPES = ['noul', 'choice', 'score'];

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

// ----------------------------------------------------------------- SHA-256
// n8n Code nodes cannot require node:crypto by default, so the catalog hash is computed
// here. The unit tests compare it with node:crypto.

const K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

function utf8Bytes(text) {
  const bytes = [];
  for (const char of String(text)) {
    const code = char.codePointAt(0);
    if (code < 0x80) {
      bytes.push(code);
    } else if (code < 0x800) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code < 0x10000) {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    }
  }
  return bytes;
}

function sha256Hex(text) {
  const bytes = utf8Bytes(text);
  const bitLength = bytes.length * 8;
  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0);
  const high = Math.floor(bitLength / 0x100000000);
  const low = bitLength >>> 0;
  bytes.push((high >>> 24) & 0xff, (high >>> 16) & 0xff, (high >>> 8) & 0xff, high & 0xff);
  bytes.push((low >>> 24) & 0xff, (low >>> 16) & 0xff, (low >>> 8) & 0xff, low & 0xff);

  const h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const w = new Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let offset = 0; offset < bytes.length; offset += 64) {
    for (let i = 0; i < 16; i += 1) {
      const j = offset + i * 4;
      w[i] = ((bytes[j] << 24) | (bytes[j + 1] << 16) | (bytes[j + 2] << 8) | bytes[j + 3]) >>> 0;
    }
    for (let i = 16; i < 64; i += 1) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i += 1) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + s1 + ch + K[i] + w[i]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (s0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  return h.map((word) => word.toString(16).padStart(8, '0')).join('');
}

// ------------------------------------------------------------ question set

// The hash covers what Jev is shown, in the order it is shown: ids and
// descriptions. Reordering the catalog changes the version too.
function catalogHash(playbooksFile) {
  const playbooks = isObject(playbooksFile) && Array.isArray(playbooksFile.playbooks) ? playbooksFile.playbooks : [];
  return sha256Hex(JSON.stringify(playbooks.map((playbook) => [playbook.id, playbook.description]))).slice(0, 12);
}

function resolveQuestionSet(questionSetFile, playbooksFile) {
  if (!isObject(questionSetFile) || typeof questionSetFile.version !== 'string' || !isObject(questionSetFile.questions)) {
    throw new Error('jev: question set needs a version and questions');
  }
  if (!isObject(playbooksFile) || !Array.isArray(playbooksFile.playbooks) || playbooksFile.playbooks.length === 0) {
    throw new Error('jev: playbook catalog is empty');
  }
  const questions = clone(questionSetFile.questions);
  for (const [key, question] of Object.entries(questions)) {
    if (!isObject(question) || QUESTION_TYPES.indexOf(question.type) === -1) {
      throw new Error(`jev: question ${key} has no valid type`);
    }
    if (typeof question.instructions !== 'string' || question.instructions === '') {
      throw new Error(`jev: question ${key} has no instructions`);
    }
    if (question.criteria_from === 'playbooks.json') {
      question.criteria = {};
      for (const playbook of playbooksFile.playbooks) {
        if (!isObject(playbook) || typeof playbook.id !== 'string' || typeof playbook.description !== 'string') {
          throw new Error('jev: every playbook needs an id and a description');
        }
        if (Object.prototype.hasOwnProperty.call(question.criteria, playbook.id)) {
          throw new Error(`jev: playbook ${playbook.id} is listed twice`);
        }
        question.criteria[playbook.id] = playbook.description;
      }
      delete question.criteria_from;
    }
    if (question.type !== 'noul') {
      const options = isObject(question.criteria) ? Object.keys(question.criteria) : [];
      if (options.length === 0) throw new Error(`jev: question ${key} has no criteria`);
      // JavaScript lists integer-like keys first and in numeric order, which
      // would silently undo the reversed order of the order check.
      if (question.type === 'choice' && options.some((option) => /^\d+$/.test(option))) {
        throw new Error(`jev: choice question ${key} has a numeric option name`);
      }
    }
  }
  const orderCheck = Array.isArray(questionSetFile.order_check) ? questionSetFile.order_check.slice() : [];
  for (const key of orderCheck) {
    if (!questions[key] || questions[key].type !== 'choice') {
      throw new Error(`jev: order_check names ${key}, which is not a choice question`);
    }
  }
  return {
    version: `${questionSetFile.version}+pb.${catalogHash(playbooksFile)}`,
    base_version: questionSetFile.version,
    playbooks_version: typeof playbooksFile.version === 'string' ? playbooksFile.version : 'unknown',
    order_check: orderCheck,
    questions,
  };
}

// ---------------------------------------------------------------- requests

function wireQuestion(question, reverse) {
  const wire = { type: question.type, instructions: question.instructions };
  if (isObject(question.criteria)) {
    const entries = Object.entries(question.criteria);
    if (reverse) entries.reverse();
    wire.criteria = {};
    for (const [option, text] of entries) wire.criteria[option] = text;
  }
  return wire;
}

function wireQuestions(questionSet, keep, reverse) {
  const questions = {};
  for (const [key, question] of Object.entries(questionSet.questions)) {
    if (keep(key, question)) questions[key] = wireQuestion(question, reverse);
  }
  return questions;
}

// Only the five sections of the state are copied: anything else on the
// object passed in (code-only values, playbook data) cannot reach a request.
function wireState(state, withUntrusted) {
  const wire = {};
  for (const section of STATE_SECTIONS) {
    if (section === 'untrusted' && !withUntrusted) continue;
    if (state[section] !== undefined) wire[section] = clone(state[section]);
  }
  return wire;
}

function buildRequests(state, questionSet, options) {
  const model = isObject(options) ? options.model : undefined;
  if (typeof model !== 'string' || model.trim() === '') throw new Error('jev: options.model is required');
  if (!isObject(state)) throw new Error('jev: state is required');
  if (!isObject(questionSet) || !isObject(questionSet.questions)) {
    throw new Error('jev: a resolved question set is required');
  }
  const orderCheck = Array.isArray(questionSet.order_check) ? questionSet.order_check : [];
  return {
    // The judgment the alert gets.
    full: {
      model,
      state: wireState(state, true),
      questions: wireQuestions(questionSet, () => true, false),
    },
    // Same questions without the untrusted section; questions that read it
    // are dropped (doc 9.2).
    ablated: {
      model,
      state: wireState(state, false),
      questions: wireQuestions(questionSet, (key, question) => question.reads_untrusted !== true, false),
    },
    // The order-check questions again, options reversed (doc 9.3).
    orderCheck: {
      model,
      state: wireState(state, true),
      questions: wireQuestions(questionSet, (key) => orderCheck.indexOf(key) !== -1, true),
    },
  };
}

const jevRequest = { resolveQuestionSet, buildRequests, catalogHash, sha256Hex };

if (typeof module !== 'undefined' && module.exports) module.exports = jevRequest;
