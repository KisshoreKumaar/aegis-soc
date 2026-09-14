'use strict';
let token = '', state = null, current = null, session = 0, selection = 0, busy = false, activeJob = null, timelineLimit = 25, lastAnswer = null, draftRevision = null;
const paging = {incidents: {offset: 0}, events: {offset: 0}, audit: {offset: 0}};
const $ = id => document.getElementById(id);
const can = permission => state?.permissions.includes(permission);
const node = (tag, text = '', cls = '') => { const el = document.createElement(tag); el.textContent = text; if (cls) el.className = cls; return el; };
const notice = (message, error = false) => { $('notice').textContent = message; $('notice').classList.toggle('error', error); };
const badge = text => node('span', text, 'badge ' + text.toLowerCase());
function button(label, work, permission, cls = 'secondary') { const b = node('button', label, cls); b.disabled = permission ? !can(permission) : false; b.onclick = () => run(work, b); return b; }
function list(parent, title, items) { parent.append(node('h3', title)); const ul = node('ul'); for (const text of items) ul.append(node('li', text)); parent.append(ul); }
function rawDetails(value, title = 'View preserved event') { const d = node('details'); d.append(node('summary', title), node('pre', JSON.stringify(value, null, 2))); return d; }
function download(name, data, mime = 'application/json') { const blob = new Blob([typeof data === 'string' ? data : JSON.stringify(data, null, 2)], {type: mime}); const url = URL.createObjectURL(blob); const link = node('a'); link.href = url; link.download = name; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
async function api(path, body, text = false) {
  const response = await fetch('/api/' + path, {method: body === undefined ? 'GET' : 'POST', headers: {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}, ...(body === undefined ? {} : {body: JSON.stringify(body)})});
  if (!response.ok) { const result = await response.json(); throw new Error(result.error || `Request failed (${response.status})`); }
  return text ? response.text() : response.json();
}
async function run(work, control) {
  if (!token && control?.id !== 'connect') { notice('Connect with an operator token first.', true); return; }
  const wasDisabled = control?.disabled;
  if (control) control.disabled = true;
  busy = true;
  try { await work(); } catch (error) { notice(error.message, true); }
  finally { busy = false; if (control?.isConnected) control.disabled = wasDisabled; }
}
const titles = {overview: 'Operations overview', investigation: 'Incident investigation', events: 'Event explorer', responses: 'Response center', rules: 'Detection catalog', audit: 'Audit trail'};
function route() {
  const name = Object.hasOwn(titles, location.hash.slice(1)) ? location.hash.slice(1) : 'overview';
  for (const page of document.querySelectorAll('.page')) page.hidden = page.id !== name;
  for (const link of document.querySelectorAll('nav a')) link.classList.toggle('active', link.hash === '#' + name);
  $('page-title').textContent = titles[name];
  if (token) run(async () => { if (name === 'events' || name === 'audit') await loadPage(name); });
}
window.addEventListener('hashchange', route);
route();

$('connect').onclick = async () => {
  const supplied = $('token').value.trim();
  if (!supplied) { notice('Enter your local operator token.', true); return; }
  token = supplied; $('token').value = ''; session++;
  await run(async () => { await refresh(); $('disconnect').hidden = false; $('connect').hidden = true; $('token').hidden = true; $('refresh').disabled = false; notice('Connected. Offline investigation and virtual responses are ready.'); }, $('connect'));
};
$('token').addEventListener('keydown', e => { if (e.key === 'Enter') $('connect').click(); });
$('disconnect').onclick = () => { token = ''; session++; location.reload(); };
$('refresh').onclick = () => run(async () => { await refresh(); notice('Telemetry refreshed.'); }, $('refresh'));

async function refresh() {
  const generation = session;
  const next = await api('state');
  if (generation !== session) return;
  state = next;
  $('identity').textContent = `${state.identity.name} · ${state.identity.role}`;
  $('events-count').textContent = state.metrics.events;
  $('incidents-count').textContent = state.metrics.open_incidents;
  $('incident-total').textContent = `${state.metrics.incidents} total cases`;
  $('risk').textContent = state.metrics.highest_risk;
  $('demo').disabled = !can('ingest'); $('import-events').disabled = !can('ingest');
  $('approval-policy').textContent = state.two_person_approval ? 'TWO-PERSON APPROVAL' : 'SINGLE-OPERATOR DEMO';
  renderResponses();
  await loadPage('incidents');
  const visible = location.hash.slice(1);
  if (visible === 'events' || visible === 'audit') await loadPage(visible);
  if (!$('rule-rows').children.length) { const result = await api('rules'); renderRules(result.rules); }
  if (current) {
    const incident = await api('incidents/' + current.id);
    if (current && incident.id === current.id && incident.revision !== current.revision) showIncident(incident, true);
  }
  if (activeJob) {
    const result = await api('jobs/' + activeJob);
    if (result.status === 'COMPLETED' || result.status === 'FAILED') { renderAnswer(result); activeJob = null; }
  }
}
setInterval(() => { if (token && state && $('auto-refresh').checked && !busy && !document.hidden) run(refresh); }, 5000);

function table(headers, rows) { const wrap = node('div', '', 'table-wrap'), t = node('table'), head = node('thead'), tr = node('tr'), body = node('tbody'); for (const text of headers) tr.append(node('th', text)); head.append(tr); for (const cells of rows) { const row = node('tr'); for (const content of cells) { const td = node('td'); td.append(typeof content === 'string' ? node('span', content) : content); row.append(td); } body.append(row); } t.append(head, body); wrap.append(t); return wrap; }
async function loadPage(resource) {
  const config = {incidents: ['incident-search', 'queue', 'inc'], events: ['event-search', 'event-rows', 'event'], audit: ['audit-search', 'audit-rows', 'audit']}[resource];
  const p = paging[resource];
  const params = new URLSearchParams({q: $(config[0]).value, offset: p.offset, limit: 25});
  if (resource === 'incidents' && $('status-filter').value) params.set('status', $('status-filter').value);
  const result = await api(resource + '?' + params);
  p.result = result;
  const container = $(config[1]); container.replaceChildren(); container.classList.remove('empty');
  if (!result.items.length) container.append(node('p', 'No matching records. Load a scenario or change the search.', 'empty'));
  else if (resource === 'incidents') {
    const rows = result.items.map(i => {
      const label = button(i.asset, () => openIncident(i.id), null, 'link-button'); label.append(node('small', i.user));
      return [label, badge(i.analysis.severity), String(i.analysis.risk_score), badge(i.status || 'OPEN'), String(i.event_ids.length), i.owner || 'Unassigned', new Date(i.updated).toLocaleString()];
    });
    container.append(table(['Asset / user', 'Severity', 'Risk', 'Status', 'Events', 'Owner', 'Updated'], rows));
    $('queue-count').textContent = `${result.total} matching cases`;
  } else if (resource === 'events') {
    container.append(table(['Time', 'Source / asset', 'Event kind', 'Evidence'], result.items.map(e => {
      const source = node('strong', e.source); source.append(node('small', `${e.asset} / ${e.user}`));
      return [new Date(e.timestamp).toLocaleString(), source, e.kind, rawDetails(e)];
    })));
  } else {
    for (const a of result.items) { const row = node('div', '', 'row'); row.append(node('strong', `#${a.seq} · ${a.action}`), node('p', `${new Date(a.timestamp).toLocaleString()} · ${a.data.actor || 'system'}`, 'muted'), rawDetails(a.data, 'View audit details')); container.append(row); }
  }
  $(config[2] + '-page').textContent = `${result.total ? p.offset + 1 : 0}–${Math.min(p.offset + 25, result.total)} of ${result.total}`;
  $(config[2] + '-prev').disabled = p.offset === 0;
  $(config[2] + '-next').disabled = p.offset + 25 >= result.total;
}
for (const [resource, prefix] of [['incidents', 'inc'], ['events', 'event'], ['audit', 'audit']]) {
  $(prefix + '-prev').onclick = () => run(async () => { paging[resource].offset = Math.max(0, paging[resource].offset - 25); await loadPage(resource); });
  $(prefix + '-next').onclick = () => run(async () => { paging[resource].offset += 25; await loadPage(resource); });
  $('search-' + resource).onclick = () => run(async () => { paging[resource].offset = 0; await loadPage(resource); });
}
for (const [input, search] of [['incident-search','search-incidents'], ['event-search','search-events'], ['audit-search','search-audit']]) $(input).addEventListener('keydown', e => { if (e.key === 'Enter') $(search).click(); });
$('status-filter').onchange = () => $('search-incidents').click();
$('demo').onclick = () => run(async () => { const result = await api('demo', {scenario: $('scenario').value}); await refresh(); notice(`Loaded ${result.ingested} synthetic events · ${result.incident_ids.length} incident(s).`); if (result.incident_ids.length) await openIncident(result.incident_ids[0]); }, $('demo'));

async function openIncident(id) {
  const request = ++selection;
  const incident = await api('incidents/' + id);
  if (request !== selection) return;
  current = null; timelineLimit = 25; activeJob = null; lastAnswer = null;
  $('question').value = ''; $('note').value = ''; $('assistant-result').textContent = 'Choose a question to inspect the current evidence.';
  showIncident(incident);
  location.hash = 'investigation';
}
function showIncident(incident, preserveDraft = false) {
  const dirtyDraft = current && ($('note').value.trim() || $('owner').value !== (current.owner || '') || $('case-status').value !== current.status);
  current = incident;
  $('no-selection').hidden = true; $('case-workspace').hidden = false;
  $('case-id').textContent = `${incident.id} · Revision ${incident.revision}`;
  $('case-title').textContent = `${incident.asset} / ${incident.user}`;
  $('case-meta').textContent = `${incident.analysis.verdict} · ${incident.status} · ${incident.event_ids.length} correlated events · ${incident.owner || 'Unassigned'}`;
  $('chain').replaceChildren();
  incident.analysis.attack_chain.forEach((stage, index) => { const n = node('div', '', 'stage'); n.append(node('small', 'STAGE ' + (index + 1)), node('span', stage)); $('chain').append(n); });
  $('findings').replaceChildren();
  for (const d of incident.analysis.detections) { const finding = node('div', '', 'finding'); finding.append(badge(d.rule_id), node('p', `${d.evidence_ids.length} supporting event(s)`), rawDetails(d, 'Evidence references')); $('findings').append(finding); }
  list($('findings'), 'Inferences & uncertainty', [...incident.analysis.inferences, ...incident.analysis.hypotheses, ...incident.analysis.unknowns].map(i => `${i.label}: ${i.statement}`));
  $('techniques').replaceChildren();
  for (const t of incident.analysis.mitre_attack) { const row = node('div', '', 'row'); row.append(node('strong', `${t.id} · ${t.name}`), node('p', `${t.tactic} · ${t.status}`, 'muted'), rawDetails(t.evidence, 'Supporting event IDs')); $('techniques').append(row); }
  if (!incident.analysis.mitre_attack.length) $('techniques').append(node('p', 'No supported technique mapping.', 'muted'));
  const risk = $('risk-detail'); risk.replaceChildren(); const score = node('div', String(incident.analysis.risk_score), 'score-display'); score.append(node('small', ' / 100')); risk.append(score, badge(incident.analysis.severity), node('p', `${incident.analysis.confidence}% heuristic confidence; not a calibrated probability.`, 'muted'));
  for (const [key, value] of Object.entries(incident.analysis.risk_factors)) { const factor = node('div', '', 'factor'), progress = document.createElement('progress'); progress.max = 30; progress.value = value; progress.setAttribute('aria-label', key.replaceAll('_', ' ')); factor.append(node('span', key.replaceAll('_', ' ')), node('span', String(value)), progress); risk.append(factor); }
  risk.append(node('small', 'Factors add together; final score is capped at 100.'));
  if (!preserveDraft || !dirtyDraft) { draftRevision = incident.revision; $('owner').value = incident.owner || ''; $('case-status').value = incident.status === 'MERGED' ? 'RESOLVED' : incident.status; }
  if (draftRevision !== incident.revision) notice('Case evidence changed while you were editing. Reopen the case before saving your review.', true);
  if (lastAnswer) renderAnswer(lastAnswer);
  $('notes').replaceChildren(); for (const note of incident.notes || []) { const n = node('div', '', 'row'); n.append(node('small', `${note.actor} · ${new Date(note.timestamp).toLocaleString()}`), node('p', note.text)); $('notes').append(n); }
  $('save-case').disabled = !can('investigate') || incident.status === 'MERGED';
  $('investigate').disabled = !can('investigate'); $('recommend').disabled = !can('recommend') || !['OPEN', 'INVESTIGATING'].includes(incident.status);
  for (const b of document.querySelectorAll('.prompt')) b.disabled = !can('investigate');
  renderTimeline();
}
function renderTimeline() {
  $('timeline').replaceChildren();
  for (const e of current.events.slice(0, timelineLimit)) { const n = node('div', '', 'timeline-event'); n.append(node('time', new Date(e.timestamp).toLocaleString()), node('strong', e.kind), node('small', `${e.source} · ${e.id}`), rawDetails(e)); $('timeline').append(n); }
  $('timeline-more').hidden = timelineLimit >= current.events.length;
}
$('timeline-more').onclick = () => { timelineLimit += 25; renderTimeline(); };
$('save-case').onclick = () => run(async () => {
  const payload = {incident_id: current.id, revision: draftRevision, status: $('case-status').value};
  if ($('owner').value.trim()) payload.owner = $('owner').value.trim();
  if ($('note').value.trim()) payload.note = $('note').value.trim();
  await api('incidents/update', payload); const updated = await api('incidents/' + current.id); $('note').value = ''; showIncident(updated); await refresh(); notice('Case review saved and audited.');
}, $('save-case'));
$('export-json').onclick = () => run(async () => download(`aegis-${current.id}.json`, await api('incidents/' + current.id + '/report')));
$('export-md').onclick = () => run(async () => download(`aegis-${current.id}.md`, await api('incidents/' + current.id + '/report?format=markdown', undefined, true), 'text/markdown'));
$('recommend').onclick = () => run(async () => { await api('responses/recommend', {incident_id: current.id, action: $('playbook').value}); await refresh(); location.hash = 'responses'; notice('Response recommendation recorded. Approval is required before simulation.'); }, $('recommend'));

async function ask(question) {
  if (!current) return;
  const job = await api('investigate', {incident_id: current.id, question}); activeJob = job.id;
  $('assistant-result').textContent = 'Investigation queued. Analyzing preserved evidence…';
  // Poll this bounded local job even when automatic dashboard refresh is disabled.
  const jobId = job.id, incidentId = current.id, generation = session;
  for (let attempt = 0; attempt < 30; attempt++) {
    await new Promise(resolve => setTimeout(resolve, 500));
    if (session !== generation || current?.id !== incidentId) return;
    const result = await api('jobs/' + jobId);
    if (['COMPLETED', 'FAILED'].includes(result.status)) { renderAnswer(result); activeJob = null; return; }
  }
  notice('Investigation is still queued. Refresh to retrieve the result.');
}
$('investigate').onclick = () => run(() => ask($('question').value.trim() || 'Summarize the evidence'), $('investigate'));
for (const b of document.querySelectorAll('.prompt')) b.onclick = () => run(async () => { $('question').value = b.dataset.question; await ask(b.dataset.question); }, b);
function renderAnswer(job) {
  if (job.incident_id !== current?.id) return;
  lastAnswer = job;
  const d = $('assistant-result'); d.replaceChildren();
  if (job.status === 'FAILED') { d.append(node('p', job.result.error)); return; }
  const result = job.result;
  d.append(badge('DETERMINISTIC'), node('p', result.answer));
  if (result.analyzed_revision !== current.revision) d.append(node('p', `This report used revision ${result.analyzed_revision}. Re-run investigation for current evidence.`, 'callout'));
  if (result.focus === 'risk') list(d, 'Risk factors', Object.entries(result.risk_factors).map(([k,v]) => `${k.replaceAll('_',' ')}: ${v}`));
  else if (result.focus === 'techniques') list(d, 'Candidate techniques', result.techniques.length ? result.techniques.map(t => `${t.id} · ${t.name} · ${t.evidence.length} supporting events`) : ['No supported mapping']);
  else if (result.focus === 'actions') list(d, 'Prioritized actions', result.next_actions);
  else if (result.focus !== 'unsupported') for (const inference of result.inferences) { d.append(node('p', `INFERENCE: ${inference.statement}`), rawDetails(inference.evidence_ids, 'Supporting evidence IDs')); }
  list(d, 'Missing evidence', result.missing_evidence);
  list(d, 'Unknowns', result.unknowns.map(i => i.statement));
  d.append(rawDetails(result, 'Full structured investigation'));
}

async function decision(title, description, needsReason = false) {
  const d = $('decision-dialog'); $('decision-title').textContent = title; $('decision-description').textContent = description;
  $('decision-note').value = ''; $('decision-note').hidden = !needsReason; $('decision-label').hidden = !needsReason;
  d.returnValue = ''; d.showModal();
  return new Promise(resolve => d.addEventListener('close', () => resolve(d.returnValue === 'confirm' ? {reason: $('decision-note').value.trim()} : null), {once: true}));
}
function renderResponses() {
  const container = $('response-rows'); container.replaceChildren(); container.classList.remove('empty');
  if (!state.responses.length) container.append(node('p', 'No response requests. Open an incident to recommend a virtual playbook.', 'empty'));
  for (const r of state.responses) {
    const row = node('div', '', 'row'); row.append(badge(r.status), node('h3', r.action.replaceAll('_', ' ')), node('p', `${r.asset || 'Virtual endpoint'} · requested by ${r.requested_by || 'legacy operator'}`, 'muted'));
    row.append(button('Open incident', () => openIncident(r.incident_id), 'read', 'link-button'));
    if (r.verification) row.append(node('p', r.verification));
    if (r.reason) row.append(node('p', r.reason, 'muted'));
    if (r.expires_at) row.append(node('small', `Approval expires: ${new Date(r.expires_at).toLocaleString()}`));
    const toolbar = node('div', '', 'toolbar');
    if (r.status === 'PENDING') toolbar.append(button('Approve simulation', async () => {
      if (!await decision('Approve virtual response', `Approve ${r.action.replaceAll('_',' ')} on ${r.asset}? Approval is bound to incident revision ${r.incident_revision} and expires in 15 minutes. No real endpoint will be changed.`)) return;
      await api('responses/approve', {response_id: r.id, confirmation: 'APPROVE SIMULATION'}); await refresh(); notice('Simulation approved.');
    }, 'approve', ''));
    if (r.status === 'APPROVED') toolbar.append(button('Execute simulation', async () => {
      if (!await decision('Execute approved simulation', `Apply ${r.action.replaceAll('_',' ')} to the virtual endpoint ${r.asset}? The result will be verified in the local registry and recorded.`)) return;
      await api('responses/execute', {response_id: r.id}); await refresh(); notice('Virtual response executed and verified. No real endpoint was changed.');
    }, 'execute', ''));
    if (['PENDING', 'APPROVED'].includes(r.status)) toolbar.append(button('Reject', async () => { const answer = await decision('Reject response request', 'Document why this response should not proceed.', true); if (!answer) return; await api('responses/reject', {response_id: r.id, reason: answer.reason}); await refresh(); }, 'approve'));
    row.append(toolbar, rawDetails(r, 'Decision and verification record')); container.append(row);
  }
  $('virtual-endpoints').replaceChildren();
  if (!state.virtual_endpoints.length) $('virtual-endpoints').append(node('p', 'No virtual endpoint actions have run.'));
  for (const endpoint of state.virtual_endpoints) { const row = node('div', '', 'row'); row.append(node('strong', endpoint.asset + ' '), badge(endpoint.state)); $('virtual-endpoints').append(row); }
}
function renderRules(rules) { $('rule-rows').replaceChildren(); for (const r of rules) { const row = node('div', '', 'row'); row.append(badge(r.id), node('h3', r.name), node('p', r.threshold, 'muted'), node('small', r.technique ? `Candidate ATT&CK: ${r.technique}` : 'No automatic ATT&CK mapping')); $('rule-rows').append(row); } }
$('event-file').onchange = () => run(async () => { const file = $('event-file').files[0]; if (!file) return; if (file.size > 1048576) throw new Error('File exceeds 1 MiB'); $('event-json').value = await file.text(); notice('File loaded locally. Review it, then validate and ingest.'); });
$('import-events').onclick = () => run(async () => {
  const text = $('event-json').value.trim(); if (!text) throw new Error('Paste JSON or select a telemetry file.');
  let parsed; try { parsed = JSON.parse(text); } catch { parsed = text.split(/\r?\n/).filter(line => line.trim()).map(line => JSON.parse(line)); }
  const events = Array.isArray(parsed) ? parsed : parsed.events || [parsed];
  const result = await api('events/batch', {events}); await refresh(); await loadPage('events'); notice(`Processed ${result.results.length} events; ${result.results.filter(r => r.duplicate).length} duplicates skipped.`);
}, $('import-events'));
$('verify-audit').onclick = () => run(async () => { const result = await api('audit/verify'); $('audit-integrity').textContent = result.valid ? `Verified ${result.records} records · ${result.mode} · Retain exported checkpoints externally.` : `Integrity failure at sequence ${result.failed_sequence}. Preserve this database for investigation.`; }, $('verify-audit'));
$('export-events').onclick = () => run(async () => download('aegis-events-page.json', paging.events.result || await api('events')));
$('export-audit').onclick = () => run(async () => download('aegis-audit-checkpoint.json', {page: paging.audit.result || await api('audit'), checkpoint: await api('audit/verify')}));
