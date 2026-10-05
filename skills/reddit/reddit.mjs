// Pure Reddit domain admission. Storage, digest, approval and host tools stay native.
const ensure = (ok, message) => { if (!ok) throw new Error(message); };
const norm = value => value.replace(/\r\n?/gu, '\n');
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const username = value => typeof value === 'string' && /^[a-z0-9_-]{3,20}$/u.test(value);

function tail(packet, resource, aggregate) {
  ensure(packet?.status === 'read', 'State read did not complete.');
  ensure(packet.resource === resource && packet.aggregate_id === aggregate, 'State belongs to another resource or account.');
  ensure(Number.isInteger(packet.after_version) && packet.after_version >= 0, 'Missing state version.');
  ensure(Array.isArray(packet.events), 'Missing event tail.');
  if (packet.after_version === 0) {
    ensure(packet.events.length === 0, 'Empty state has unexpected events.');
    return { version: 0, event: null };
  }
  ensure(packet.events.length === 1 && packet.events[0].version === packet.after_version, 'State tail does not match its head.');
  return { version: packet.after_version, event: packet.events[0].event };
}
function accountState(packet, accountId) {
  ensure(username(accountId), 'Select an explicit lowercase Reddit username.');
  const state = tail(packet, 'reddit_accounts', accountId);
  ensure(state.event?.type === 'reddit.account', 'Account is not configured.');
  ensure(state.event.account_id === accountId, 'Account configuration identity mismatch.');
  validateConfig(accountId, state.event.config);
  return { account_id: accountId, version: state.version, config: state.event.config };
}
function writerState(packet) {
  const state = tail(packet, 'reddit_browser', 'writer');
  if (state.event) {
    ensure(state.event.type === 'reddit.writer', 'Unexpected browser writer event.');
    ensure(['reserved', 'held', 'published_host_observed', 'voted_host_observed', 'released_unsubmitted', 'closed_by_operator'].includes(state.event.status), 'Unknown browser writer state.');
  }
  return state;
}
function isHeld(state) {
  return state.event && ['reserved', 'held'].includes(state.event.status);
}
function validateConfig(accountId, config) {
  ensure(config?.expected_username?.toLowerCase() === accountId, 'Expected username must match the selected account.');
  for (const name of ['profile_ref', 'binding_ref', 'credential_profile_ref', 'login_credential_profile_ref']) {
    ensure(typeof config[name] === 'string' && /^[a-zA-Z0-9_.:-]{0,100}$/u.test(config[name]), `${name} must be a non-secret local name, not a URL or credential.`);
  }
  ensure(config.profile_ref && config.binding_ref, 'A named persistent profile and attachment binding are required.');
  ensure(config.background_only === true, 'This package requires background-only browser operation.');
}
function redditUrl(value) {
  const url = Runx.parseUrl(value);
  ensure(url.protocol === 'https:' && ['www.reddit.com', 'reddit.com', 'old.reddit.com'].includes(url.hostname), 'Target must be an HTTPS Reddit page.');
  const match = /^https:\/\/(?:www\.|old\.)?reddit\.com(\/[^?#]*)$/u.exec(value);
  ensure(match && url.href === value, 'Use a canonical Reddit URL without credentials, port, query or fragment.');
  const pathname = match[1];
  const parts = pathname.split('/').filter(Boolean);
  ensure(parts[0] === 'r' && /^[A-Za-z0-9_]{2,21}$/u.test(parts[1] || ''), 'Target must name a subreddit.');
  ensure(!/%|\\/u.test(pathname), 'Encoded or ambiguous Reddit paths are not allowed.');
  return { parts, community: parts[1].toLowerCase(), path: pathname.replace(/\/+$/u, '') };
}
function validateAction(action) {
  const target = redditUrl(action.target_url);
  ensure(target.community === action.subreddit.toLowerCase(), 'Target community differs from the approved subreddit.');
  ensure(action.body.trim().length > 0, 'Empty Reddit contribution.');
  ensure(action.kind === 'upvote' || !/\[[^\]\n]+\]\([^)]+\)/u.test(action.body), 'Reddit editor text must not contain Markdown links.');
  ensure(action.kind === 'upvote' || action.allow_bare_urls || !/https?:\/\/|www\./iu.test(action.body), 'Bare URLs require explicit inclusion in the action.');
  if (action.kind === 'post') {
    ensure(target.parts.length === 3 && target.parts[2] === 'submit', 'A post must target the exact subreddit submit page.');
    ensure(action.title.trim().length > 0, 'A post needs a title.');
  } else {
    ensure(action.kind === 'upvote' || action.title === '', 'A comment must not carry a post title.');
    ensure(target.parts[2] === 'comments' && /^[a-z0-9]+$/u.test(target.parts[3] || ''), 'A comment needs a specific thread or comment permalink.');
    ensure(target.parts.length >= 4 && target.parts.length <= 7, 'Unexpected comment target path.');
    if (target.parts.length === 7) ensure(target.parts[5] === 'comment' && /^[a-z0-9]+$/u.test(target.parts[6]), 'Invalid comment permalink.');
    if (target.parts.length === 6) ensure(/^[a-z0-9]+$/u.test(target.parts[5]), 'Invalid comment permalink.');
  }
  return action;
}
function targetIdentity(value) {
  const {parts, community} = redditUrl(value);
  return { community, thread: parts[3] || '', comment: parts[5] === 'comment' ? (parts[6] || '') : (parts[5] || '') };
}
function exactReadback(action, account, observation) {
  ensure(observation.evidence_refs.length > 0 && observation.observed_at.length > 0, 'Readback needs evidence and observation time.');
  ensure(observation.username.toLowerCase() === account.account_id, 'Readback author differs from the selected account.');
  ensure(observation.profile_ref === account.config.profile_ref, 'Readback uses another browser profile.');
  ensure(observation.subreddit.toLowerCase() === action.subreddit.toLowerCase(), 'Readback community mismatch.');
  ensure(norm(observation.body) === norm(action.body) && (action.kind === 'upvote' || observation.title === action.title), 'Readback content differs from the approved action.');
  ensure(observation.visibility === 'visible', 'A pending, removed or unknown contribution is not a visible publication.');
  const published = targetIdentity(observation.permalink);
  ensure(published.community === action.subreddit.toLowerCase() && /^[a-z0-9]+$/u.test(published.thread), 'Invalid publication permalink.');
  if (action.kind === 'upvote') {
    ensure(observation.target_author.toLowerCase() === action.target_author && observation.vote_state === 'up', 'Vote author or selected state mismatch.');
    ensure(same(targetIdentity(observation.permalink), targetIdentity(action.target_url)), 'Vote readback points to another target.');
    return;
  }
  if (action.kind === 'comment') {
    ensure(/^[a-z0-9]+$/u.test(published.comment), 'Comment readback needs its own comment permalink.');
    const parent = targetIdentity(action.target_url);
    ensure(published.thread === parent.thread && same(targetIdentity(observation.parent_url), parent), 'Readback parent differs from the approved target.');
    ensure(published.comment !== parent.comment, 'Readback points to the parent rather than the new comment.');
  } else ensure(!published.comment, 'Post readback must point to the post itself.');
}
export function configure(inputs) {
  validateConfig(inputs.account_id, inputs.config);
  ensure(username(inputs.account_id), 'Use the lowercase Reddit username as account_id.');
  return { configuration: { account_id: inputs.account_id, config: inputs.config, expected_version: inputs.expected_version }, event: { type: 'reddit.account', account_id: inputs.account_id, config: inputs.config } };
}
export function loadAccount(inputs) {
  return { account: accountState(inputs.account_state, inputs.account_id), writer_status: isHeld(writerState(inputs.writer_state)) ? 'held' : 'idle' };
}
export function validateResearch(inputs) {
  const research = inputs.research;
  let reason = '';
  let provisional = false;
  try {
    ensure(research.account_id === inputs.account.account_id, 'Research account differs from the loaded account.');
    const selected = research.target_candidates.filter(candidate => candidate.decision === 'selected');
    for (const candidate of selected) {
      const target = redditUrl(candidate.target_url);
      ensure(target.community === candidate.subreddit.toLowerCase(), 'Selected target community mismatch.');
      ensure(candidate.rule_status === 'allowed', 'Selected target needs confirmed community rules.');
      ensure(candidate.account_eligibility !== 'ineligible', 'Selected target account is ineligible.');
      if (candidate.account_eligibility === 'unknown') provisional = true;
      if (candidate.intent === 'post') ensure(target.parts.length === 3 && target.parts[2] === 'submit', 'Selected post target must be its subreddit submit page.');
      else ensure(target.parts[2] === 'comments' && /^[a-z0-9]+$/u.test(target.parts[3] || ''), 'Selected comment target must be a specific thread.');
    }
    for (const draft of research.drafts) {
      const action = validateAction(draft.action);
      ensure(action.kind === 'post' || action.kind === 'comment', 'Target discovery drafts must be posts or comments.');
      const intent = action.kind;
      ensure(selected.some(candidate => candidate.intent === intent && candidate.target_url === action.target_url), 'Draft has no selected, eligible target candidate.');
    }
  } catch (error) { reason = error.message; }
  const needsEligibility = !reason && provisional && research.drafts.length > 0;
  return {
    research: reason
      ? { ...research, account_id: inputs.account.account_id, status: 'held', drafts: [], unknowns: [...research.unknowns.slice(0, 11), reason], next_step: 'Re-evaluate the target evidence before drafting or publishing.' }
      : needsEligibility
        ? { ...research, status: 'provisional', unknowns: [...research.unknowns.slice(0, 11), 'Account eligibility is unverified.'], next_step: 'Review the draft; verify the logged-in account, community eligibility, thread, and editor immediately before any approved submission.' }
        : research,
    target_review: { admitted: reason === '', reason: needsEligibility ? 'Draft admitted provisionally; account eligibility requires an authenticated recheck.' : reason, candidate_count: research.target_candidates.length, draft_count: reason ? 0 : research.drafts.length }
  };
}
export function identify(inputs) {
  const a = inputs.action;
  let target = a.target_url;
  try { target = JSON.stringify(targetIdentity(a.target_url)); } catch { /* Admission reports invalid targets. */ }
  return { identity: { account_id: inputs.account_id, kind: a.kind, target, title: a.kind === 'upvote' ? '' : a.title, body: a.kind === 'upvote' ? '' : norm(a.body) } };
}
function prepareAction(inputs) {
  const account = accountState(inputs.account_state, inputs.account_id);
  const state = writerState(inputs.writer_state);
  ensure(!isHeld(state), 'Browser writer is held. Run reconcile; do not retry or switch accounts.');
  const action = validateAction(inputs.action);
  if (action.kind === 'upvote') {
    ensure(username(action.target_author) && action.target_author !== account.account_id, 'Do not vote on your own content.');
    const target = tail(inputs.target_account_state, 'reddit_accounts', action.target_author);
    ensure(target.version === 0, 'Do not vote on content by another managed account.');
  }
  const attempt = tail(inputs.attempt_state, 'reddit_attempts', inputs.attempt_id);
  if (attempt.event) {
    ensure(attempt.event.type === 'reddit.writer' && attempt.event.account.account_id === account.account_id, 'Attempt ledger identity mismatch.');
    ensure(attempt.event.status === 'released_unsubmitted', 'This action was already attempted, completed or closed. Do not repeat it.');
  }
  return { prepared: { account, action, writer_version: state.version, attempt_id: inputs.attempt_id, attempt_version: attempt.version } };
}
export function prepare(inputs) {
  try { return { admission: { ...prepareAction(inputs), admitted: true, reason: '' } }; }
  catch (error) { return { admission: { prepared: null, admitted: false, reason: error.message } }; }
}
export function refuse(inputs) {
  return { result: { status: 'refused', account_id: inputs.account_id, action: inputs.action, observation: null, evidence_level: 'none', state_version: 0, event_ref: '', reason: inputs.reason } };
}
export function reserve(inputs) {
  const p = inputs.prepared;
  return { reservation: { type: 'reddit.writer', status: 'reserved', account: p.account, action: p.action, plan_digest: inputs.digest, attempt_id: p.attempt_id, attempt_version: p.attempt_version, observation: null, original_observation: null, effect_possible: true, assessment: '' }, expected_version: p.writer_version, idempotency_key: `reddit:${inputs.digest}:reserve` };
}
export function finish(inputs) {
  const held = inputs.reservation;
  const observation = inputs.observation;
  let status = 'held';
  let reason = observation.reason;
  if (['published', 'voted'].includes(observation.status)) {
    try {
      exactReadback(held.action, held.account, observation);
      status = held.action.kind === 'upvote' ? 'voted_host_observed' : 'published_host_observed';
    } catch (error) { reason = `${reason}; ${error.message}`; }
  }
  const effect_possible = !(observation.evidence_refs.length > 0 && observation.reason.trim().length > 0 && observation.status === 'not_submitted' && observation.effect_attempted === false && observation.affirmative_no_submit === true && observation.username.toLowerCase() === held.account.account_id && observation.profile_ref === held.account.config.profile_ref);
  return { transition: { ...held, status, observation, original_observation: observation, effect_possible, assessment: reason }, idempotency_key: `reddit:${held.plan_digest}:observation` };
}
export function pending(inputs) {
  const state = writerState(inputs.writer_state);
  ensure(isHeld(state), 'No pending browser attempt requires reconciliation.');
  ensure(state.event.account.account_id === inputs.account_id, 'The held attempt belongs to another account.');
  return { pending: { reservation: state.event, version: state.version } };
}
export function resolve(inputs) {
  const { reservation, version } = inputs.pending;
  const o = inputs.observation;
  const original = reservation.original_observation;
  const effect_possible = reservation.effect_possible || o.effect_attempted === true || ['uncertain', 'challenge'].includes(o.status);
  let status = 'held';
  let assessment = o.reason;
  try {
  ensure(o.evidence_refs.length > 0 && o.reason.trim().length > 0, 'Reconciliation requires concrete evidence and a reason.');
  if (['published', 'voted'].includes(o.status)) { exactReadback(reservation.action, reservation.account, o); status = reservation.action.kind === 'upvote' ? 'voted_host_observed' : 'published_host_observed'; }
  if (o.status === 'not_submitted') {
    ensure(o.username.toLowerCase() === reservation.account.account_id && o.profile_ref === reservation.account.config.profile_ref, 'Reconciliation identity mismatch.');
    ensure(o.affirmative_no_submit === true, 'Absence from search does not establish that submission never happened.');
    ensure(o.effect_attempted === false, 'An attempted submit effect cannot be released as unsubmitted.');
    ensure(original?.status === 'not_submitted' && original.evidence_refs.length > 0 && original.reason.trim().length > 0 && original.effect_attempted === false && original.affirmative_no_submit === true && original.username.toLowerCase() === reservation.account.account_id && original.profile_ref === reservation.account.config.profile_ref && !effect_possible, 'Original or intervening evidence does not prove a pre-submit stop; do not release this attempt for retry.');
    status = 'released_unsubmitted';
  }
  } catch (error) { assessment = `${o.reason}; ${error.message}`; status = 'held'; }
  try {
  if (inputs.disposition === 'close_attempt') {
    ensure(o.evidence_refs.length > 0, 'Closure requires concrete evidence.');
    ensure(inputs.closure_reason.trim().length > 0, 'Closing an attempt requires a reason.');
    ensure(o.username.toLowerCase() === reservation.account.account_id && o.profile_ref === reservation.account.config.profile_ref, 'Closure observation identity mismatch.');
    status = 'closed_by_operator';
    assessment = `Closure proposed without a success claim: ${inputs.closure_reason}; observed assessment: ${assessment}`;
  }
  } catch (error) { assessment = `${assessment}; ${error.message}`; }
  return { resolution: { ...reservation, status, observation: o, effect_possible, assessment }, expected_version: version, idempotency_key: `reddit:${reservation.plan_digest}:resolve:v${version + 1}` };
}
export function recordOutcome(inputs) {
  ensure(inputs.record.status === 'committed', 'Outcome was not committed; keep the original attempt under reconciliation.');
  return { result: { status: inputs.transition.status, account_id: inputs.transition.account.account_id, action: inputs.transition.action, observation: inputs.transition.observation, evidence_level: 'host_observed', state_version: inputs.record.after_version, event_ref: inputs.record.event_ref, reason: inputs.transition.assessment } };
}
