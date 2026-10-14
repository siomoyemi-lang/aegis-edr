import { create } from 'zustand';

export interface Alert {
  alert_id: string;
  time: string;
  agent_id: string;
  rule_name: string;
  severity: 'LOW' | 'HIGH' | 'CRITICAL';
  pid: number;
  image_path: string;
  status: 'open' | 'resolved';
}

interface AegisState {
  alerts: Alert[];
  agents: any[]; 
  addAlert: (alert: Alert) => void;
  resolveAlert: (alert_id: string) => void;
}

export const useAegisStore = create<AegisState>((set) => ({
  alerts: [],
  agents: [],
  addAlert: (alert) => set((state) => ({ alerts: [alert, ...state.alerts] })),
  resolveAlert: (alert_id) =>
    set((state) => ({
      alerts: state.alerts.map((a) =>
        a.alert_id === alert_id ? { ...a, status: 'resolved' } : a
      ),
    })),
}));