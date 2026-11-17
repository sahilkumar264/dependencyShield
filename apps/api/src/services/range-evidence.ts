import semver from "semver";
import * as pep440 from "@renovatebot/pep440";
import type { OsvPackage, OsvVulnerability } from "./osv.js";

export type RangeEvaluation = { status: "affected" | "not_affected" | "unknown"; source: string | null; evidence: Record<string, unknown> };
type OsvAffected = NonNullable<OsvVulnerability["affected"]>[number];

function samePackage(entry: OsvAffected, pkg: OsvPackage) {
  const affectedPackage = entry.package;
  if (!affectedPackage?.name || !affectedPackage.ecosystem) return false;
  const ecosystemMatches = affectedPackage.ecosystem.toLocaleLowerCase() === pkg.ecosystem.toLocaleLowerCase();
  const nameMatches = pkg.ecosystem === "npm"
    ? affectedPackage.name.toLocaleLowerCase() === pkg.name.toLocaleLowerCase()
    : affectedPackage.name === pkg.name;
  return ecosystemMatches && nameMatches;
}

function osvSemverMatch(version: string, events: Array<Record<string, unknown>>) {
  let introduced: string | null = null;
  let sawBoundary = false;
  for (const event of events) {
    if (typeof event.introduced === "string") { introduced = event.introduced; sawBoundary = true; continue; }
    const upper = typeof event.fixed === "string" ? event.fixed
      : typeof event.last_affected === "string" ? event.last_affected
      : typeof event.limit === "string" ? event.limit : null;
    if (upper !== null) {
      sawBoundary = true;
      if (!introduced || (introduced !== "0" && !semver.valid(introduced)) || !semver.valid(upper)) return { known: false, affected: false };
      const lowerMatch = introduced === "0" || semver.gte(version, introduced);
      const inclusiveUpper = typeof event.last_affected === "string";
      const upperMatch = inclusiveUpper ? semver.lte(version, upper) : semver.lt(version, upper);
      if (lowerMatch && upperMatch) return { known: true, affected: true };
      introduced = null;
    }
  }
  if (introduced !== null) {
    if (introduced !== "0" && !semver.valid(introduced)) return { known: false, affected: false };
    if (introduced === "0" || semver.gte(version, introduced)) return { known: true, affected: true };
    sawBoundary = true;
  }
  return { known: sawBoundary, affected: false };
}

function osvPep440Match(version: string, events: Array<Record<string, unknown>>) {
  let introduced: string | null = null;
  let sawBoundary = false;
  for (const event of events) {
    if (typeof event.introduced === "string") { introduced = event.introduced; sawBoundary = true; continue; }
    const upper = typeof event.fixed === "string" ? event.fixed
      : typeof event.last_affected === "string" ? event.last_affected
      : typeof event.limit === "string" ? event.limit : null;
    if (upper !== null) {
      sawBoundary = true;
      if (!introduced || (introduced !== "0" && !pep440.valid(introduced)) || !pep440.valid(upper)) return { known: false, affected: false };
      const lowerMatch = introduced === "0" || pep440.ge(version, introduced);
      const upperMatch = typeof event.last_affected === "string" ? pep440.le(version, upper) : pep440.lt(version, upper);
      if (lowerMatch && upperMatch) return { known: true, affected: true };
      introduced = null;
    }
  }
  if (introduced !== null) {
    if (introduced !== "0" && !pep440.valid(introduced)) return { known: false, affected: false };
    if (introduced === "0" || pep440.ge(version, introduced)) return { known: true, affected: true };
    sawBoundary = true;
  }
  return { known: sawBoundary, affected: false };
}

export function evaluateOsvLocalRange(pkg: OsvPackage, advisory: OsvVulnerability): RangeEvaluation {
  const entries = (advisory.affected ?? []).filter((entry) => samePackage(entry, pkg));
  if (!entries.length) return { status: "unknown", source: null, evidence: { reason: "advisory_has_no_matching_package" } };
  const semverEcosystem = pkg.ecosystem === "npm" || pkg.ecosystem === "Go" || pkg.ecosystem === "crates.io";
  const pep440Ecosystem = pkg.ecosystem === "PyPI";
  if ((!semverEcosystem && !pep440Ecosystem) || (semverEcosystem && !semver.valid(pkg.version)) || (pep440Ecosystem && !pep440.valid(pkg.version))) {
    return { status: "unknown", source: null, evidence: { reason: "unsupported_local_version_scheme", ecosystem: pkg.ecosystem } };
  }
  const rangeEvidence: Array<Record<string, unknown>> = [];
  let hadVersionList = false;
  let hadUnknownRange = false;
  for (const entry of entries) {
    if (entry.versions) {
      hadVersionList = true;
      if (entry.versions.some((version) => pep440Ecosystem ? pep440.eq(version, pkg.version) : version === pkg.version)) return { status: "affected", source: "OSV versions", evidence: { version: pkg.version, affected_versions: entry.versions.filter((version) => pep440Ecosystem ? pep440.eq(version, pkg.version) : version === pkg.version) } };
    }
    for (const range of entry.ranges ?? []) {
      const expectedRangeType = pep440Ecosystem ? "ECOSYSTEM" : "SEMVER";
      if (range.type !== expectedRangeType) { hadUnknownRange = true; continue; }
      const events = (range.events ?? []) as Array<Record<string, unknown>>;
      const result = pep440Ecosystem ? osvPep440Match(pkg.version, events) : osvSemverMatch(pkg.version, events);
      if (!result.known) { hadUnknownRange = true; continue; }
      if (result.affected) return { status: "affected", source: `OSV ${expectedRangeType} range`, evidence: { version: pkg.version, events } };
      rangeEvidence.push({ type: expectedRangeType, events, matched: false });
    }
  }
  if (hadUnknownRange) return { status: "unknown", source: null, evidence: { reason: "advisory_contains_unhandled_range_types", checked_ranges: rangeEvidence } };
  if (rangeEvidence.length || hadVersionList) return { status: "not_affected", source: rangeEvidence.length ? `OSV ${pep440Ecosystem ? "ECOSYSTEM" : "SEMVER"} range` : "OSV versions", evidence: { version: pkg.version, checked_ranges: rangeEvidence } };
  return { status: "unknown", source: null, evidence: { reason: "advisory_contains_no_evaluable_ranges" } };
}

export function evaluateGithubSemverRange(pkg: OsvPackage, vulnerableRange: string | undefined): RangeEvaluation {
  if (!vulnerableRange || pkg.ecosystem !== "npm" || !semver.valid(pkg.version) || !semver.validRange(vulnerableRange)) {
    return { status: "unknown", source: null, evidence: { reason: "range_or_version_scheme_unsupported", vulnerable_range: vulnerableRange ?? null } };
  }
  const affected = semver.satisfies(pkg.version, vulnerableRange);
  return { status: affected ? "affected" : "not_affected", source: "GitHub Advisory Database SemVer range", evidence: { version: pkg.version, vulnerable_range: vulnerableRange } };
}
