'use client';

import { useAegisStore } from '@/store/useAegisStore';
import { useAegisWebSocket } from '@/hooks/useAegisWebSocket';

export default function Dashboard() {
  // Connect to the frontend WebSocket endpoint specified in the blueprint
  useAegisWebSocket('ws://localhost:8000/ws/frontend');
  
  const alerts = useAegisStore((state) => state.alerts);
  const resolveAlert = useAegisStore((state) => state.resolveAlert);

  const executeKillCommand = async (agent_id: string, pid: number, alert_id: string) => {
    try {
      const response = await fetch(`http://localhost:8000/api/agents/${agent_id}/kill`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ pid: pid })
      });

      const data = await response.json();
      
      if (data.status === "Kill signal dispatched") {
         resolveAlert(alert_id);
      } else {
         console.error("Failed to dispatch:", data.error);
      }
    } catch (error) {
      console.error("Remediation execution failed:", error);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-white p-8 font-sans">
      <header className="mb-8 border-b border-slate-800 pb-4">
        <h1 className="text-3xl font-bold tracking-tight">Aegis EDR Console</h1>
        <p className="text-slate-400 mt-2">Active Responses & Telemetry Streams</p>
      </header>

      <main>
        <h2 className="text-xl font-semibold mb-4 text-slate-200">Live Alert Feed</h2>
        <div className="space-y-4">
          {alerts.length === 0 ? (
            <div className="p-4 bg-slate-900 rounded-lg border border-slate-800 text-slate-500">
              No active threats detected. Listening for telemetry...
            </div>
          ) : (
            alerts.map((alert) => (
              <div 
                key={alert.alert_id} 
                className={`p-5 rounded-lg border flex flex-col sm:flex-row justify-between sm:items-center gap-4 transition-all ${
                  alert.status === 'resolved' 
                    ? 'bg-emerald-950/20 border-emerald-900/50 opacity-60' 
                    : 'bg-red-950/30 border-red-900/50'
                }`}
              >
                <div>
                  <h3 className={`font-bold ${alert.status === 'resolved' ? 'text-emerald-500' : 'text-red-400'}`}>
                    {alert.rule_name} 
                    <span className="text-xs uppercase tracking-wider text-slate-400 ml-3 bg-slate-800 px-2 py-1 rounded">
                      {alert.severity}
                    </span>
                  </h3>
                  <p className="text-sm font-mono text-slate-300 mt-2">
                    <span className="text-slate-500">Agent:</span> {alert.agent_id} | <span className="text-slate-500">PID:</span> {alert.pid}
                  </p>
                  <p className="text-sm font-mono text-slate-400 mt-1 truncate max-w-2xl">
                    <span className="text-slate-500">Target:</span> {alert.image_path}
                  </p>
                </div>
                
                {alert.status === 'open' && (
                  <button
                    onClick={() => executeKillCommand(alert.agent_id, alert.pid, alert.alert_id)}
                    className="px-6 py-2.5 bg-red-600 hover:bg-red-500 text-white text-sm font-semibold rounded-md transition-colors shadow-lg shadow-red-900/20 whitespace-nowrap"
                  >
                    Kill Process
                  </button>
                )}
                {alert.status === 'resolved' && (
                  <span className="px-4 py-2 text-emerald-500 text-sm font-semibold flex items-center gap-2">
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    Terminated
                  </span>
                )}
              </div>
            ))
          )}
        </div>
      </main>
    </div>
  );
}