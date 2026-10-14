import { create } from 'zustand';

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Alert {
  alert_id: string;
  time: string;
  agent_id: string;
  rule_id?: string;
  rule_name: string;
  severity: Severity;
  pid: number;
  ppid?: number;
  image_path: string;
  status: 'open' | 'resolved';
}

export interface Agent {
  agent_id: string;
  status: 'online' | 'offline';
  /** Unix seconds, as reported by the gateway. */
  last_seen: number;
  first_seen?: number;
}

export type KillState = { phase: 'pending' | 'failed'; message?: string };
export type Connection = 'connecting' | 'open' | 'closed';

const MAX_ALERTS = 500;

interface AegisState {
  alerts: Alert[];
  agents: Agent[];
  connection: Connection;
  killStates: Record<string, KillState>;
  selectedAlertId: string | null;

  setConnection: (c: Connection) => void;
  addAlert: (alert: Alert) => void;
  mergeAlerts: (incoming: Alert[]) => void;
  resolveAlert: (alert_id: string) => void;
  setAgents: (agents: Agent[]) => void;
  upsertAgent: (agent: Agent) => void;
  setKillState: (alert_id: string, state: KillState | null) => void;
  selectAlert: (alert_id: string | null) => void;
}

const byTimeDesc = (a: Alert, b: Alert) => (a.time < b.time ? 1 : a.time > b.time ? -1 : 0);

export const useAegisStore = create<AegisState>((set) => ({
  alerts: [],
  agents: [],
  connection: 'connecting',
  killStates: {},
  selectedAlertId: null,

  setConnection: (connection) => set({ connection }),

  addAlert: (alert) =>
    set((s) =>
      s.alerts.some((a) => a.alert_id === alert.alert_id)
        ? s // already have it (live push raced the snapshot fetch)
        : { alerts: [alert, ...s.alerts].slice(0, MAX_ALERTS) },
    ),

  // Used for the snapshot loaded on (re)connect: keep what we already know, add what we missed.
  mergeAlerts: (incoming) =>
    set((s) => {
      const known = new Map(s.alerts.map((a) => [a.alert_id, a]));
      for (const a of incoming) {
        const existing = known.get(a.alert_id);
        // never let a stale snapshot re-open an alert we already resolved
        known.set(a.alert_id, existing?.status === 'resolved' ? existing : a);
      }
      return { alerts: [...known.values()].sort(byTimeDesc).slice(0, MAX_ALERTS) };
    }),

  resolveAlert: (alert_id) =>
    set((s) => {
      const killStates = { ...s.killStates };
      delete killStates[alert_id];
      return {
        alerts: s.alerts.map((a) => (a.alert_id === alert_id ? { ...a, status: 'resolved' } : a)),
        killStates,
      };
    }),

  setAgents: (agents) => set({ agents }),

  upsertAgent: (agent) =>
    set((s) => ({
      agents: s.agents.some((a) => a.agent_id === agent.agent_id)
        ? s.agents.map((a) => (a.agent_id === agent.agent_id ? { ...a, ...agent } : a))
        : [...s.agents, agent],
    })),

  setKillState: (alert_id, state) =>
    set((s) => {
      const next = { ...s.killStates };
      if (state) next[alert_id] = state;
      else delete next[alert_id];
      return { killStates: next };
    }),

  selectAlert: (selectedAlertId) => set({ selectedAlertId }),
}));
