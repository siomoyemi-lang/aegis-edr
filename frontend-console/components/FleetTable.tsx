'use client';

import { useState } from 'react';
import { useAegisStore, type Agent } from '@/store/useAegisStore';

type SortKey = 'agent_id' | 'status' | 'last_seen';

export default function FleetTable() {
  const agents = useAegisStore((s) => s.agents);
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: 'agent_id', dir: 1 });

  const sorted = [...agents].sort((a: Agent, b: Agent) => {
    const x = a[sort.key], y = b[sort.key];
    return (x < y ? -1 : x > y ? 1 : 0) * sort.dir;
  });

  const head = (key: SortKey, label: string) => (
    <th className="px-4 py-2 text-left font-medium">
      <button
        className="hover:text-white"
        onClick={() => setSort((s) => ({ key, dir: s.key === key ? (s.dir === 1 ? -1 : 1) : 1 }))}
      >
        {label} {sort.key === key ? (sort.dir === 1 ? '▲' : '▼') : ''}
      </button>
    </th>
  );

  return (
    <section>
      <h2 className="mb-3 text-xl font-semibold text-slate-200">Fleet</h2>
      <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900">
        <table className="w-full text-sm">
          <thead className="border-b border-slate-800 text-slate-400">
            <tr>{head('agent_id', 'Agent')}{head('status', 'Status')}{head('last_seen', 'Last seen')}</tr>
          </thead>
          <tbody>
            {sorted.length === 0 && (
              <tr><td colSpan={3} className="px-4 py-3 text-slate-500">No agents have connected yet.</td></tr>
            )}
            {sorted.map((a) => (
              <tr key={a.agent_id} className="border-b border-slate-800/60 last:border-0">
                <td className="px-4 py-2 font-mono text-slate-200">{a.agent_id}</td>
                <td className="px-4 py-2">
                  <span className={a.status === 'online' ? 'text-emerald-400' : 'text-slate-500'}>
                    ● {a.status}
                  </span>
                </td>
                <td className="px-4 py-2 text-slate-400">{new Date(a.last_seen * 1000).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
