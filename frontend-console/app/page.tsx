'use client';

import AlertFeed from '@/components/AlertFeed';
import FleetTable from '@/components/FleetTable';
import Header from '@/components/Header';
import ProcessGraph from '@/components/ProcessGraph';
import { useAegisWebSocket } from '@/hooks/useAegisWebSocket';

export default function Dashboard() {
  useAegisWebSocket();

  return (
    <div className="min-h-screen bg-slate-950 p-8 font-sans text-white">
      <Header />
      <main className="grid gap-8 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <AlertFeed />
        <div className="space-y-8">
          <ProcessGraph />
          <FleetTable />
        </div>
      </main>
    </div>
  );
}
