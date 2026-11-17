import { createHash, randomUUID } from "node:crypto";
import { env } from "../config/env.js";
import { pool } from "../db/pool.js";
import { analyzeDependencyGraph, ImpactEdge, ImpactNode } from "./dependency-impact.js";
import { getApplicationRiskContext } from "./okf.js";

const PRIORITIES = ["P0", "P1", "P2", "P3", "P4"] as const;
const POLICY_VERSION = "dependencyshield-risk-v1";
const CHOICE_OPTIONS = {
  priority_recommendation: { P0: "Emergency response is justified by immediate, severe, verified impact.", P1: "Critical response is warranted and the finding should be handled urgently.", P2: "High priority with a near-term security remediation target.", P3: "Normal priority for the standard security remediation queue.", P4: "Low priority; track and address through routine maintenance." },
  remediation_category: { upgrade: "A package upgrade is the appropriate likely remediation path; no version is being selected here.", mitigate: "A temporary compensating mitigation is appropriate while a fix is evaluated.", investigate: "More technical investigation is needed before choosing a remediation.", monitor: "Monitor the finding and reassess as evidence changes.", insufficient_information: "The available evidence is insufficient to choose a category." },
  operational_response: { emergency_escalation: "Immediate security incident or emergency escalation.", expedited_security_review: "Expedited review by the security response team.", normal_remediation_queue: "Standard security remediation workflow.", planned_maintenance: "Plan the work into a routine maintenance window.", collect_missing_context: "Collect missing application or vulnerability context before prioritizing." },
} as const;

const QUESTIONS = {
  priority_recommendation: { type: "choice", instructions: "Given only the supplied vulnerability evidence and application risk context, which remediation priority should the security team consider? Do not infer missing facts.", criteria: CHOICE_OPTIONS.priority_recommendation },
  risk_score: { type: "score", instructions: "How urgent is the security response warranted by the supplied evidence and context? Rate only urgency, not whether the vulnerability is real; the package match is already established.", criteria: ["Routine tracking; low apparent impact from the supplied context.", "Normal remediation queue; limited urgency is evident.", "High priority; meaningful application risk is indicated.", "Critical urgency; strong evidence supports expedited response.", "Emergency urgency; immediate severe impact is indicated."] },
  immediate_escalation: { type: "noul", instructions: "Should the security team immediately escalate this finding based on the supplied evidence? Unknown or missing facts are not evidence of an emergency.", criteria: { true: "The supplied evidence supports immediate escalation.", false: "The supplied evidence does not support immediate escalation." } },
  human_review: { type: "noul", instructions: "Does this decision need human review before anyone acts on it? Consider missing or conflicting application context and uncertainty in the supplied evidence.", criteria: { true: "A human should review the evidence or fill context before action.", false: "The supplied evidence is sufficient for a normal policy-controlled workflow." } },
  remediation_category: { type: "choice", instructions: "Which remediation category best fits the supplied evidence? Do not select a package version or perform an action.", criteria: CHOICE_OPTIONS.remediation_category },
  operational_response: { type: "choice", instructions: "Which operational response should the team consider for this finding?", criteria: CHOICE_OPTIONS.operational_response },
} as const;

type ChoiceAnswer = { type: "choice"; choice: string; probabilities: Record<string, number>; confidence: number };
type ScoreAnswer = { type: "score"; score: number; legend: Record<string, string>; probabilities: Record<string, number>; confidence: number };
type NoulAnswer = { type: "noul"; noul: number };
type JevAnswer = ChoiceAnswer | ScoreAnswer | NoulAnswer;
type JevResponse = { model: string; answers: Record<string, JevAnswer>; usage: { input_tokens: number; output_tokens: number }; requestId: string | null };

function object(value: unknown): value is Record<string, unknown> { return value !== null && typeof value === "object" && !Array.isArray(value); }
function finiteUnit(value: unknown): value is number { return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1; }
function distributionsMatch(probabilities: Record<string, number>, expected: string[]) {
  const keys = Object.keys(probabilities);
  return keys.length === expected.length && expected.every((key) => keys.includes(key)) && keys.every((key) => finiteUnit(probabilities[key])) && Math.abs(Object.values(probabilities).reduce((sum, value) => sum + value, 0) - 1) <= 0.03;
}

function parseAnswer(value: unknown, type: "choice" | "score" | "noul", expected: string[]): JevAnswer | null {
  if (!object(value) || value.type !== type) return null;
  if (type === "noul") return finiteUnit(value.noul) ? { type, noul: value.noul } : null;
  if (type === "choice") {
    const probabilities = value.probabilities;
    if (typeof value.choice !== "string" || !expected.includes(value.choice) || !object(probabilities) || !finiteUnit(value.confidence)) return null;
    const distribution = probabilities as Record<string, number>;
    if (!distributionsMatch(distribution, expected)) return null;
    return { type, choice: value.choice, probabilities: distribution, confidence: value.confidence };
  }
  const probabilities = value.probabilities;
  const legend = value.legend;
  if (typeof value.score !== "number" || !Number.isFinite(value.score) || value.score < 0 || value.score > 4 || !object(probabilities) || !object(legend) || !finiteUnit(value.confidence)) return null;
  const distribution = probabilities as Record<string, number>;
  const levelKeys = ["0", "1", "2", "3", "4"];
  if (!distributionsMatch(distribution, levelKeys) || levelKeys.some((key) => typeof legend[key] !== "string")) return null;
  return { type, score: value.score, legend: legend as Record<string, string>, probabilities: distribution, confidence: value.confidence };
}

function validateResponse(value: unknown): JevResponse | null {
  if (!object(value) || typeof value.model !== "string" || !value.model || !object(value.answers) || !object(value.usage)) return null;
  const answerInput = value.answers as Record<string, unknown>;
  const expectedIds = Object.keys(QUESTIONS);
  if (expectedIds.some((id) => !(id in answerInput)) || Object.keys(answerInput).length !== expectedIds.length) return null;
  const answers: Record<string, JevAnswer> = {};
  for (const id of expectedIds) {
    const question = QUESTIONS[id as keyof typeof QUESTIONS];
    const expected = question.type === "choice" ? Object.keys(question.criteria) : question.type === "score" ? ["0", "1", "2", "3", "4"] : [];
    const parsed = parseAnswer(answerInput[id], question.type, expected);
    if (!parsed) return null;
    answers[id] = parsed;
  }
  const usage = value.usage as Record<string, unknown>;
  if (!Number.isInteger(usage.input_tokens) || (usage.input_tokens as number) < 0 || !Number.isInteger(usage.output_tokens) || (usage.output_tokens as number) < 0) return null;
  return { model: value.model, answers, usage: { input_tokens: usage.input_tokens as number, output_tokens: usage.output_tokens as number }, requestId: typeof value.request_id === "string" ? value.request_id : null };
}

function getRetryDelay(response: Response, attempt: number) {
  const header = response.headers.get("retry-after");
  if (header) {
    const seconds = Number(header);
    if (Number.isFinite(seconds)) return Math.min(10_000, Math.max(0, seconds * 1000));
    const date = Date.parse(header);
    if (Number.isFinite(date)) return Math.min(10_000, Math.max(0, date - Date.now()));
  }
  return Math.min(4_000, 300 * 2 ** attempt);
}

async function requestJev(state: Record<string, unknown>): Promise<{ response: JevResponse | null; failure: string | null }> {
  if (!env.TYPESAFE_API_KEY) return { response: null, failure: "missing_api_key" };
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const requestId = randomUUID();
    let response: Response;
    try {
      response = await fetch("https://api.typesafe.ai/v1/systemone", {
        method: "POST",
        headers: { authorization: `Bearer ${env.TYPESAFE_API_KEY}`, "content-type": "application/json", "x-request-id": requestId },
        body: JSON.stringify({ model: env.JEV_MODEL_VERSION, state, questions: QUESTIONS }),
        signal: AbortSignal.timeout(12_000),
      });
    } catch (error) {
      const category = error instanceof Error && error.name === "TimeoutError" ? "provider_timeout" : "provider_network_error";
      if (attempt < 2) { await new Promise((resolve) => setTimeout(resolve, 300 * 2 ** attempt)); continue; }
      return { response: null, failure: category };
    }
    if (response.status === 429 || response.status === 529) {
      if (attempt < 2) { const delay = getRetryDelay(response, attempt); await response.body?.cancel(); await new Promise((resolve) => setTimeout(resolve, delay)); continue; }
      await response.body?.cancel();
      return { response: null, failure: `provider_http_${response.status}` };
    }
    if (!response.ok) { await response.body?.cancel(); return { response: null, failure: `provider_http_${response.status}` }; }
    let payload: unknown;
    try { payload = await response.json(); }
    catch { return { response: null, failure: "invalid_response_json" }; }
    const parsed = validateResponse(payload);
    if (!parsed) return { response: null, failure: "invalid_response_schema" };
    const responseHeaderId = response.headers.get("x-request-id") ?? parsed.requestId ?? requestId;
    return { response: { ...parsed, requestId: responseHeaderId }, failure: null };
  }
  return { response: null, failure: "provider_retry_exhausted" };
}

function advisoryFacts(payload: unknown) {
  const record = object(payload) ? payload : {};
  const databaseSpecific = object(record.database_specific) ? record.database_specific : {};
  const rawSeverity = typeof databaseSpecific.severity === "string" ? databaseSpecific.severity
    : typeof record.severity === "string" ? record.severity : "unknown";
  let cvssScore: number | null = null;
  if (Array.isArray(record.severity)) {
    const entry = record.severity.find((item) => object(item) && typeof item.score === "string");
    if (entry && object(entry)) {
      const parsed = Number(entry.score);
      if (Number.isFinite(parsed) && parsed >= 0 && parsed <= 10) cvssScore = parsed;
    }
  }
  if (cvssScore === null && typeof databaseSpecific.cvss_score === "number" && Number.isFinite(databaseSpecific.cvss_score) && databaseSpecific.cvss_score >= 0 && databaseSpecific.cvss_score <= 10) cvssScore = databaseSpecific.cvss_score;
  const severity = rawSeverity.toLowerCase();
  return { severity: severity === "critical" || severity === "high" || severity === "medium" || severity === "moderate" || severity === "low" ? (severity === "moderate" ? "medium" : severity) : "unknown", cvssScore };
}

function nvdFacts(payload: unknown) {
  const cve = object(payload) ? payload : {};
  const metrics = object(cve.metrics) ? cve.metrics : {};
  const metric = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    .flatMap((key) => Array.isArray(metrics[key]) ? metrics[key] as unknown[] : [])
    .find((item) => object(item) && object(item.cvssData) && typeof item.cvssData.baseScore === "number");
  const cvssData = metric && object(metric) && object(metric.cvssData) ? metric.cvssData : {};
  const cvssScore = typeof cvssData.baseScore === "number" && Number.isFinite(cvssData.baseScore) ? cvssData.baseScore : null;
  const nvdSeverity = typeof cvssData.baseSeverity === "string" ? cvssData.baseSeverity.toLowerCase() : "unknown";
  const cweIds = Array.isArray(cve.weaknesses) ? cve.weaknesses.flatMap((entry) => object(entry) && Array.isArray(entry.description) ? entry.description.flatMap((description) => object(description) && typeof description.value === "string" && /^CWE-\d+$/.test(description.value) ? [description.value] : []) : []) : [];
  return { cvssScore, severity: ["critical", "high", "medium", "low"].includes(nvdSeverity) ? nvdSeverity : "unknown", cweIds: [...new Set(cweIds)] };
}

function floorPriority(severity: string, cvssScore: number | null, knownExploited: unknown) {
  if (knownExploited === true || (cvssScore !== null && cvssScore >= 9)) return "P1";
  if (severity === "critical") return "P1";
  if ((cvssScore !== null && cvssScore >= 7) || severity === "high") return "P2";
  if ((cvssScore !== null && cvssScore >= 4) || severity === "medium") return "P3";
  if (severity === "low") return "P4";
  return "P3";
}

function urgentPriority(a: string, b: string) { return PRIORITIES[Math.min(PRIORITIES.indexOf(a as typeof PRIORITIES[number]), PRIORITIES.indexOf(b as typeof PRIORITIES[number]))]!; }
function scorePriority(score: number) { return PRIORITIES[4 - Math.min(4, Math.max(0, Math.round(score)))]!; }

type FindingRow = { id: string; scan_id: string; sbom_id: string; bom_ref: string; vulnerability_id: string; payload: unknown; nvd_payload: unknown; known_exploited: boolean; package_name: string; package_version: string | null; ecosystem: string | null; application_id: string; repository_id: string; owner: string; repository_name: string; root_bom_ref: string | null; dependency_graph_status: "complete" | "incomplete" | "unknown" | null; reachability_status: string | null; reachability_evidence: unknown };

export async function createFindingDecision(userId: string, findingId: string) {
  const selected = await pool.query<FindingRow>(
    `SELECT f.id, f.scan_id, f.sbom_id, f.bom_ref, f.vulnerability_id, v.payload,
            (SELECT payload FROM vulnerability_source_records WHERE source='NVD' AND canonical_vulnerability_id=f.vulnerability_id ORDER BY modified_at DESC NULLS LAST LIMIT 1) AS nvd_payload,
            EXISTS (SELECT 1 FROM vulnerability_aliases va JOIN kev_entries k ON k.cve_id=upper(va.alias) WHERE va.vulnerability_id=f.vulnerability_id) AS known_exploited,
            p.name AS package_name, p.version AS package_version, p.ecosystem,
            a.id AS application_id, r.id AS repository_id, r.owner, r.name AS repository_name,
            sa.root_bom_ref, sa.dependency_graph_status, fr.status AS reachability_status, fr.evidence AS reachability_evidence
     FROM findings f JOIN scans s ON s.id = f.scan_id JOIN repositories r ON r.id = s.repository_id
     JOIN applications a ON a.repository_id = r.id JOIN packages p ON p.id = f.package_id JOIN vulnerabilities v ON v.id = f.vulnerability_id
     LEFT JOIN scan_applications sa ON sa.scan_id = s.id AND sa.application_id = a.id
     LEFT JOIN finding_reachability fr ON fr.finding_id = f.id
     WHERE f.id = $1 AND r.user_id = $2`, [findingId, userId],
  );
  const finding = selected.rows[0];
  if (!finding) return null;
  const [componentRows, edgeRows, context] = await Promise.all([
    pool.query<ImpactNode>(`SELECT c.bom_ref AS "bomRef", c.package_id AS "packageId", c.component_type AS "componentType", p.name, p.version, p.purl FROM sbom_components c LEFT JOIN packages p ON p.id = c.package_id WHERE c.sbom_id = $1`, [finding.sbom_id]),
    pool.query<ImpactEdge>("SELECT source_ref AS \"sourceRef\", target_ref AS \"targetRef\" FROM dependency_edges WHERE sbom_id = $1", [finding.sbom_id]),
    getApplicationRiskContext(userId, finding.application_id),
  ]);
  const dependency = analyzeDependencyGraph({ rootRef: finding.root_bom_ref, graphStatus: finding.dependency_graph_status ?? "unknown", nodes: componentRows.rows, edges: edgeRows.rows, findings: [] }).dependencies.find((item) => item.bomRef === finding.bom_ref);
  const osvFacts = advisoryFacts(finding.payload);
  const nvd = nvdFacts(finding.nvd_payload);
  const facts = { severity: osvFacts.severity === "unknown" ? nvd.severity : osvFacts.severity, cvssScore: osvFacts.cvssScore ?? nvd.cvssScore };
  const riskContext = context?.values ?? { environment: "unknown", criticality: "unknown", internet_exposed: "unknown", data_classification: "unknown", sla: "unknown", service_dependencies: "unknown" };
  const state = {
    vulnerability: { id: finding.vulnerability_id, severity: facts.severity, cvss_score: facts.cvssScore, cwe_ids: nvd.cweIds, cvss_source: osvFacts.cvssScore === null && nvd.cvssScore !== null ? "NVD" : "OSV" },
    application: riskContext,
    dependency: { name: finding.package_name, version: finding.package_version ?? "unknown", ecosystem: finding.ecosystem ?? "unknown", relationship: dependency?.relationship ?? "unknown" },
    evidence_status: { known_exploited: finding.known_exploited ? "yes" : "unknown", reachability: finding.reachability_status ?? "unknown", fixed_version: "unknown", dependency_path: dependency?.path?.slice(1) ?? "unknown" },
  };
  const stateHash = createHash("sha256").update(JSON.stringify({ state, model: env.JEV_MODEL_VERSION, policy: POLICY_VERSION })).digest("hex");
  const { response, failure } = await requestJev(state);
  let source: "jev" | "deterministic_fallback" = "jev";
  let answers: Record<string, JevAnswer> = {};
  let suggestedPriority: string | null = null;
  let riskScore: number | null = null;
  let remediationCategory = "manual_triage";
  let operationalResponse = "security_review";
  let requestedEscalation = false;
  let modelHumanReview = false;
  let modelConfidence = 0;
  let usage: { input_tokens: number; output_tokens: number } | null = null;
  let resolvedModel: string | null = null;
  let providerRequestId: string | null = null;
  if (!response) source = "deterministic_fallback";
  else {
    answers = response.answers;
    resolvedModel = response.model;
    usage = response.usage;
    providerRequestId = response.requestId;
    const priority = answers.priority_recommendation as ChoiceAnswer;
    const score = answers.risk_score as ScoreAnswer;
    const escalation = answers.immediate_escalation as NoulAnswer;
    const review = answers.human_review as NoulAnswer;
    const remediation = answers.remediation_category as ChoiceAnswer;
    const operation = answers.operational_response as ChoiceAnswer;
    suggestedPriority = priority.choice;
    riskScore = score.score;
    remediationCategory = remediation.choice;
    operationalResponse = operation.choice;
    requestedEscalation = escalation.noul >= 0.8;
    modelHumanReview = review.noul >= 0.5;
    modelConfidence = Math.min(priority.confidence, score.confidence, remediation.confidence, operation.confidence, Math.abs(review.noul - 0.5) * 2);
  }
  const deterministicFloor = floorPriority(facts.severity, facts.cvssScore, finding.known_exploited);
  const evidencePriority = response && suggestedPriority ? urgentPriority(suggestedPriority, scorePriority(riskScore!)) : deterministicFloor;
  const finalPriority = urgentPriority(deterministicFloor, evidencePriority);
  const mandatoryEscalation = finalPriority === "P0" || finalPriority === "P1";
  const contextValues = Object.values(riskContext);
  const contextIncomplete = contextValues.some((value) => value === "unknown" || value === "conflicting") || Boolean(context?.conflicts.length || context?.invalidConcepts.length);
  const humanReviewRequired = source !== "jev" || finalPriority === "P0" || finalPriority === "P1" || modelHumanReview || contextIncomplete || (source === "jev" && modelConfidence < 0.65);
  const immediateEscalation = mandatoryEscalation || requestedEscalation;
  const policyAction = humanReviewRequired ? "human_review" : "prepare_remediation_plan";
  const deterministicReasons = [
    `Deterministic evidence floor: ${deterministicFloor} from advisory severity ${facts.severity}${facts.cvssScore === null ? "" : ` and CVSS ${facts.cvssScore}`}.`,
    source === "jev" ? `Jev recommended ${suggestedPriority}; its score maps to ${scorePriority(riskScore!)}; policy selected ${finalPriority}.` : `Jev was unavailable (${failure ?? "unknown failure"}); deterministic fallback selected ${finalPriority}.`,
    contextIncomplete ? "Human review is required because organizational context is missing, conflicting, or malformed." : "Available organizational context has no detected conflicts.",
    humanReviewRequired ? "No remediation is executed; a human review is required before action." : "No remediation is executed; this decision only prepares a reviewable remediation plan.",
  ];
  const policyEvidence = { deterministicFloor, dependencyPath: dependency?.path?.slice(1) ?? null, relationship: dependency?.relationship ?? "unknown", contextSources: context?.sources ?? {}, contextConflicts: context?.conflicts ?? [], invalidContextConcepts: context?.invalidConcepts ?? [], knownExploited: finding.known_exploited, nvdCweIds: nvd.cweIds, reachability: finding.reachability_status ?? "unknown", reachabilityEvidence: finding.reachability_evidence ?? [], fixedVersion: "unknown", humanReviewConfidenceThreshold: 0.65 };
  const inserted = await pool.query<{ id: string }>(
    `INSERT INTO jev_decisions (user_id, finding_id, application_id, scan_id, source, requested_model, resolved_model, provider_request_id, policy_version, input_hash, input_state, questions, answers, usage, fallback_reason, suggested_priority, final_priority, risk_score, immediate_escalation, human_review_required, remediation_category, operational_response, policy_action, decision_reason, policy_evidence)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25) RETURNING id`,
    [userId, finding.id, finding.application_id, finding.scan_id, source, env.JEV_MODEL_VERSION, resolvedModel, providerRequestId, POLICY_VERSION, stateHash, JSON.stringify(state), JSON.stringify(QUESTIONS), JSON.stringify(answers), usage ? JSON.stringify(usage) : null, failure, suggestedPriority, finalPriority, riskScore, immediateEscalation, humanReviewRequired, remediationCategory, operationalResponse, policyAction, deterministicReasons.join(" "), JSON.stringify(policyEvidence)],
  );
  const result = await getDecision(userId, inserted.rows[0]!.id);
  return result;
}

export async function getDecision(userId: string, decisionId: string) {
  const result = await pool.query(
    `SELECT d.*, f.vulnerability_id, p.name AS package_name, p.version AS package_version, r.owner, r.name AS repository_name, a.name AS application_name
     FROM jev_decisions d JOIN findings f ON f.id = d.finding_id JOIN packages p ON p.id = f.package_id
     JOIN applications a ON a.id = d.application_id JOIN repositories r ON r.id = a.repository_id
     WHERE d.id = $1 AND d.user_id = $2 AND r.user_id = $2`, [decisionId, userId],
  );
  return result.rows[0] ?? null;
}

export async function listDecisions(userId: string, filters: { applicationId?: string; findingId?: string; limit: number }) {
  const result = await pool.query(
    `SELECT d.id, d.finding_id, d.application_id, d.scan_id, d.source, d.requested_model, d.resolved_model, d.policy_version,
            d.suggested_priority, d.final_priority, d.risk_score, d.immediate_escalation, d.human_review_required,
            d.remediation_category, d.operational_response, d.policy_action, d.decision_reason, d.fallback_reason, d.created_at,
            f.vulnerability_id, p.name AS package_name, p.version AS package_version, a.name AS application_name, r.owner, r.name AS repository_name
     FROM jev_decisions d JOIN findings f ON f.id = d.finding_id JOIN packages p ON p.id = f.package_id
     JOIN applications a ON a.id = d.application_id JOIN repositories r ON r.id = a.repository_id
     WHERE d.user_id = $1 AND r.user_id = $1 AND ($2::uuid IS NULL OR d.application_id = $2) AND ($3::uuid IS NULL OR d.finding_id = $3)
     ORDER BY d.created_at DESC LIMIT $4`, [userId, filters.applicationId ?? null, filters.findingId ?? null, filters.limit],
  );
  return result.rows;
}
