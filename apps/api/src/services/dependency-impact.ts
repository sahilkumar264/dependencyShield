export type ImpactNode = {
  bomRef: string;
  packageId: string | null;
  componentType: string;
  name: string | null;
  version: string | null;
  purl: string | null;
};

export type ImpactEdge = { sourceRef: string; targetRef: string };

export type ImpactFinding = {
  id: string;
  bomRef: string;
  vulnerabilityId: string;
  summary: string | null;
  severity: string | null;
  package: string;
  version: string | null;
};

export function analyzeDependencyGraph(input: {
  rootRef: string | null;
  graphStatus: "complete" | "incomplete" | "unknown";
  nodes: ImpactNode[];
  edges: ImpactEdge[];
  findings: ImpactFinding[];
}) {
  const byRef = new Map(input.nodes.map((node) => [node.bomRef, node]));
  const adjacency = new Map<string, string[]>();
  for (const edge of input.edges) {
    const children = adjacency.get(edge.sourceRef) ?? [];
    children.push(edge.targetRef);
    adjacency.set(edge.sourceRef, children);
  }
  for (const children of adjacency.values()) children.sort((a, b) => a.localeCompare(b));

  const paths = new Map<string, string[]>();
  if (input.rootRef && byRef.has(input.rootRef)) {
    paths.set(input.rootRef, [input.rootRef]);
    const queue = [input.rootRef];
    for (let cursor = 0; cursor < queue.length; cursor += 1) {
      const source = queue[cursor]!;
      const sourcePath = paths.get(source)!;
      for (const target of adjacency.get(source) ?? []) {
        if (paths.has(target)) continue;
        paths.set(target, [...sourcePath, target]);
        queue.push(target);
      }
    }
  }

  const packageNodes = input.nodes.filter((node) => node.packageId !== null);
  const dependencies = packageNodes.map((node) => {
    const path = paths.get(node.bomRef) ?? null;
    const depth = path ? path.length - 1 : null;
    const relation = depth === 1 ? "direct" : depth !== null && depth > 1 ? "transitive" : input.graphStatus === "complete" ? "not_in_graph" : "unknown";
    return {
      bomRef: node.bomRef,
      packageId: node.packageId,
      name: node.name,
      version: node.version,
      purl: node.purl,
      depth,
      relationship: relation,
      path: path?.map((ref) => label(byRef.get(ref)!)) ?? null,
      pathRefs: path,
    };
  });
  const dependencyByRef = new Map(dependencies.map((dependency) => [dependency.bomRef, dependency]));
  const findingsByRef = new Set(input.findings.map((finding) => finding.bomRef));
  const findings = input.findings.map((finding) => {
    const dependency = dependencyByRef.get(finding.bomRef);
    return {
      ...finding,
      relationship: dependency?.relationship ?? "unknown",
      dependencyPath: dependency?.path ?? null,
      dependencyPathRefs: dependency?.pathRefs ?? null,
    };
  });

  return {
    graphStatus: input.graphStatus,
    rootRef: input.rootRef,
    counts: {
      packages: packageNodes.length,
      direct: dependencies.filter((dependency) => dependency.relationship === "direct").length,
      transitive: dependencies.filter((dependency) => dependency.relationship === "transitive").length,
      notInGraph: dependencies.filter((dependency) => dependency.relationship === "not_in_graph").length,
      unknownPath: dependencies.filter((dependency) => dependency.relationship === "unknown").length,
      findings: findings.length,
    },
    nodes: input.nodes.map((node) => {
      const dependency = dependencyByRef.get(node.bomRef);
      return {
        id: node.bomRef,
        label: label(node),
        componentType: node.componentType,
        packageId: node.packageId,
        purl: node.purl,
        relationship: dependency?.relationship ?? "application",
        depth: dependency?.depth ?? 0,
        hasFinding: findingsByRef.has(node.bomRef),
      };
    }),
    edges: input.edges.map((edge) => ({ id: `${edge.sourceRef}->${edge.targetRef}`, source: edge.sourceRef, target: edge.targetRef })),
    dependencies,
    findings,
  };
}

function label(node: ImpactNode) {
  if (node.packageId === null) return node.name ?? "Application root";
  return `${node.name ?? "Unknown package"}@${node.version ?? "unknown"}`;
}
