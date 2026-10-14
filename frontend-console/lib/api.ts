import { API_URL, authHeaders } from './config';
import type { Agent, Alert } from '@/store/useAegisStore';

export async function fetchAlerts(): Promise<Alert[]> {
  const res = await fetch(`${API_URL}/api/alerts?limit=200`);
  if (!res.ok) throw new Error(`alerts: HTTP ${res.status}`);
  return res.json();
}

export async function fetchAgents(): Promise<Agent[]> {
  const res = await fetch(`${API_URL}/api/agents`);
  if (!res.ok) throw new Error(`agents: HTTP ${res.status}`);
  return res.json();
}

export interface LineageNode {
  agent_id: string;
  pid: number;
  ppid: number;
  image_path: string;
  image_name: string;
  time: string;
}
export interface Lineage {
  focus: number;
  nodes: LineageNode[];
  edges: { source: number; target: number }[];
}

export async function fetchLineage(agentId: string, pid: number): Promise<Lineage | null> {
  const res = await fetch(`${API_URL}/api/agents/${encodeURIComponent(agentId)}/lineage/${pid}`);
  if (res.status === 404) return null; // aged out of the 24h process cache
  if (!res.ok) throw new Error(`lineage: HTTP ${res.status}`);
  return res.json();
}

/** Dispatches KILL_PID. Success here only means "sent"; the agent's KILL_RESULT arrives over the WebSocket. */
export async function dispatchKill(
  agentId: string,
  pid: number,
  alertId: string,
): Promise<{ ok: true } | { ok: false; message: string }> {
  try {
    const res = await fetch(`${API_URL}/api/agents/${encodeURIComponent(agentId)}/kill`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...authHeaders() },
      body: JSON.stringify({ pid, alert_id: alertId }),
    });
    if (res.ok) return { ok: true };
    const body = await res.json().catch(() => ({}));
    return { ok: false, message: body.detail ?? `Gateway returned HTTP ${res.status}` };
  } catch {
    return { ok: false, message: 'Gateway unreachable' };
  }
}
