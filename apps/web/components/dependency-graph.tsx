"use client";

import { useMemo } from "react";
import { Background, Controls, MiniMap, ReactFlow, type Edge, type Node } from "@xyflow/react";

type GraphNode = { id: string; label: string; componentType: string; packageId: string | null; purl: string | null; relationship: string; depth: number; hasFinding: boolean };
type GraphData = { nodes: GraphNode[]; edges: Array<{ id: string; source: string; target: string }> };

export function DependencyGraph({ graph }: { graph: GraphData }) {
  const nodes = useMemo<Node[]>(() => {
    const columnCounts = new Map<number, number>();
    return graph.nodes.map((node) => {
      const column = node.packageId === null ? 0 : Math.max(1, node.depth || 1);
      const row = columnCounts.get(column) ?? 0;
      columnCounts.set(column, row + 1);
      const color = node.packageId === null ? "#14534c" : node.hasFinding ? "#5b2833" : node.relationship === "direct" ? "#213a5d" : "#17263a";
      return { id: node.id, position: { x: column * 310, y: row * 115 }, data: { label: `${node.label}\n${node.packageId === null ? "application root" : node.relationship}${node.hasFinding ? " · vulnerable" : ""}` }, style: { width: 240, minHeight: 58, whiteSpace: "pre-line", background: color, color: "#edf4ff", border: `1px solid ${node.hasFinding ? "#d66b78" : "#36516b"}`, borderRadius: 10, padding: 12, fontSize: 12 } };
    });
  }, [graph.nodes]);
  const edges = useMemo<Edge[]>(() => graph.edges.map((edge) => ({ ...edge, animated: false, style: { stroke: "#59718d" } })), [graph.edges]);
  return <div className="dependency-flow"><ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.15} maxZoom={1.5} nodesConnectable={false} proOptions={{ hideAttribution: true }}><Background color="#26364a" gap={24} /><MiniMap nodeColor={(node) => String((node.style as Record<string, unknown> | undefined)?.background ?? "#213a5d")} maskColor="#080d18cc" /><Controls /></ReactFlow></div>;
}
