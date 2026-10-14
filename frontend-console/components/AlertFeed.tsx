'use client';

import { dispatchKill } from '@/lib/api';
import { useAegisStore, type Alert, type Severity } from '@/store/useAegisStore';

const SEVERITY_STYLE: Record<Severity, string> = {
  LOW: 'bg-slate-700 text-slate-200',
  MEDIUM: 'bg-yellow-900/70 text-yellow-200',
  HIGH: 'bg-orange-900/70 text-orange-200',
  CRITICAL: 'bg-red-800 text-red-100',
};

const KILL_TIMEOUT_MS = 10_000;

function AlertCard({ alert }: { alert: Alert }) {
  const kill = useAegisStore((s) => s.killStates[alert.alert_id]);
  const selected = useAegisStore((s) => s.selectedAlertId === alert.alert_id);
  const resolved = alert.status === 'resolved';

  const onKill = async () => {
    if (!window.confirm(`Terminate PID ${alert.pid} on ${alert.agent_id}?\n\n${alert.image_path}`)) return;
    const { setKillState } = useAegisStore.getState();
    setKillState(alert.alert_id, { phase: 'pending' });

    const res = await dispatchKill(alert.agent_id, alert.pid, alert.alert_id);
    if (!res.ok) {
      setKillState(alert.alert_id, { phase: 'failed', message: res.message });
      return;
    }
    // Dispatched. Stay "pending" until the agent reports back over the WebSocket; give up after a while.
    setTimeout(() => {
      const st = useAegisStore.getState();
      if (st.killStates[alert.alert_id]?.phase === 'pending') {
        st.setKillState(alert.alert_id, { phase: 'failed', message: 'No confirmation from the agent' });
      }
    }, KILL_TIMEOUT_MS);
  };

  return (
    <div
      onClick={() => useAegisStore.getState().selectAlert(alert.alert_id)}
      className={`flex cursor-pointer flex-col justify-between gap-4 rounded-lg border p-5 transition-all sm:flex-row sm:items-center ${
        resolved ? 'border-emerald-900/50 bg-emerald-950/20 opacity-60' : 'border-red-900/50 bg-red-950/30'
      } ${selected ? 'ring-2 ring-sky-500' : ''}`}
    >
      <div className="min-w-0">
        <h3 className={`font-bold ${resolved ? 'text-emerald-500' : 'text-red-400'}`}>
          {alert.rule_name}
          <span className={`ml-3 rounded px-2 py-1 text-xs uppercase tracking-wider ${SEVERITY_STYLE[alert.severity]}`}>
            {alert.severity}
          </span>
        </h3>
        <p className="mt-2 font-mono text-sm text-slate-300">
          <span className="text-slate-500">Agent:</span> {alert.agent_id} |{' '}
          <span className="text-slate-500">PID:</span> {alert.pid} |{' '}
          <span className="text-slate-500">At:</span> {new Date(alert.time).toLocaleTimeString()}
        </p>
        <p className="mt-1 truncate font-mono text-sm text-slate-400" title={alert.image_path}>
          <span className="text-slate-500">Target:</span> {alert.image_path}
        </p>
        {kill?.phase === 'failed' && <p className="mt-2 text-sm text-amber-400">⚠ {kill.message}</p>}
      </div>

      {resolved ? (
        <span className="flex items-center gap-2 px-4 py-2 text-sm font-semibold text-emerald-500">✓ Terminated</span>
      ) : (
        <button
          disabled={kill?.phase === 'pending'}
          onClick={(e) => { e.stopPropagation(); void onKill(); }}
          className="whitespace-nowrap rounded-md bg-red-600 px-6 py-2.5 text-sm font-semibold text-white shadow-lg shadow-red-900/20 transition-colors hover:bg-red-500 disabled:cursor-wait disabled:opacity-60"
        >
          {kill?.phase === 'pending' ? 'Terminating…' : kill?.phase === 'failed' ? 'Retry kill' : 'Kill Process'}
        </button>
      )}
    </div>
  );
}

export default function AlertFeed() {
  const alerts = useAegisStore((s) => s.alerts);
  return (
    <section>
      <h2 className="mb-3 text-xl font-semibold text-slate-200">Live Alert Feed</h2>
      <div className="space-y-4">
        {alerts.length === 0 ? (
          <div className="rounded-lg border border-slate-800 bg-slate-900 p-4 text-slate-500">
            No active threats detected. Listening for telemetry...
          </div>
        ) : (
          alerts.map((a) => <AlertCard key={a.alert_id} alert={a} />)
        )}
      </div>
    </section>
  );
}
