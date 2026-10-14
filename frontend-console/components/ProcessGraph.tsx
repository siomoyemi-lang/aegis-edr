'use client';

import { useEffect, useMemo, useState } from 'react';
import { Background, Controls, ReactFlow, type Edge, type Node } from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { fetchLineage, type Lineage } from '@/lib/api';
import { useAegisStore } from '@/store/useAegisStore';

const X_GAP = 280;
const Y_GAP = 84;

/** Lay the tree out left→right by depth from the root ancestor. */
function layout(l: Lineage): { nodes: Node[]; edges: Edge[] } {
  const children = new Map<number, number[]>();
  const hasParent = new Set<number>();
  for (const e of l.edges) {
    children.set(e.source, [...(children.get(e.source) ?? []), e.target]);
    hasParent.add(e.target);
  }
  const roots = l.nodes.filter((n) => !hasParent.has(n.pid)).map((n) => n.pid);
  const depth = new Map<number, number>();
  const queue: [number, number][] = roots.map((r) => [r, 0]);
  while (queue.length) {
    const [pid, d] = queue.shift()!;
    if (depth.has(pid)) continue;
    depth.set(pid, d);
    for (const c of children.get(pid) ?? []) queue.push([c, d + 1]);
  }
  const rows = new Map<number, number>();
  const nodes: Node[] = l.nodes.map((n) => {
    const d = depth.get(n.pid) ?? 0;
    const row = rows.get(d) ?? 0;
    rows.set(d, row + 1);
    const focus = n.pid === l.focus;
    return {
      id: String(n.pid),
      position: { x: d * X_GAP, y: row * Y_GAP },
      data: { label: `${n.image_name || 'unknown'}\nPID ${n.pid}  ←  PPID ${n.ppid}` },
      style: {
        whiteSpace: 'pre-line', fontSize: 12, width: 230, color: '#e2e8f0',
        background: focus ? '#7f1d1d' : '#0f172a',
        border: `1px solid ${focus ? '#ef4444' : '#334155'}`,
      },
    };
  });
  const edges: Edge[] = l.edges.map((e) => ({
    id: `${e.source}-${e.target}`, source: String(e.source), target: String(e.target), animated: e.target === l.focus,
  }));
  return { nodes, edges };
}

export default function ProcessGraph() {
  const alert = useAegisStore((s) => s.alerts.find((a) => a.alert_id === s.selectedAlertId));
  const [state, setState] = useState<{ key: string; lineage: Lineage | null; error?: string } | null>(null);
  const key = alert ? `${alert.agent_id}:${alert.pid}` : null;

  useEffect(() => {
    if (!alert || !key) return;
    let cancelled = false;
    fetchLineage(alert.agent_id, alert.pid)
      .then((lineage) => !cancelled && setState({ key, lineage }))
      .catch(() => !cancelled && setState({ key, lineage: null, error: 'Could not load lineage' }));
    return () => { cancelled = true; };
  }, [alert, key]);

  const current = state && state.key === key ? state : null;
  const graph = useMemo(() => (current?.lineage ? layout(current.lineage) : null), [current]);

  return (
    <section>
      <h2 className="mb-3 text-xl font-semibold text-slate-200">Process Lineage</h2>
      <div className="h-80 overflow-hidden rounded-lg border border-slate-800 bg-slate-900">
        {!alert ? (
          <p className="p-4 text-slate-500">Select an alert to see its parent → child process tree.</p>
        ) : !current ? (
          <p className="p-4 text-slate-500">Loading lineage…</p>
        ) : !graph ? (
          <p className="p-4 text-slate-500">{current.error ?? 'No lineage cached for this process (older than 24h or started before the agent).'}</p>
        ) : (
          <ReactFlow nodes={graph.nodes} edges={graph.edges} fitView colorMode="dark" nodesConnectable={false} proOptions={{ hideAttribution: true }}>
            <Background />
            <Controls showInteractive={false} />
          </ReactFlow>
        )}
      </div>
    </section>
  );
}
