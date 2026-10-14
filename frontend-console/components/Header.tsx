'use client';

import Image from 'next/image';
import { useAegisStore, type Connection } from '@/store/useAegisStore';

const LABEL: Record<Connection, { text: string; dot: string }> = {
  open: { text: 'Live', dot: 'bg-emerald-400' },
  connecting: { text: 'Connecting…', dot: 'bg-amber-400 animate-pulse' },
  closed: { text: 'Disconnected - retrying', dot: 'bg-red-500 animate-pulse' },
};

export default function Header() {
  const connection = useAegisStore((s) => s.connection);
  const openAlerts = useAegisStore((s) => s.alerts.filter((a) => a.status === 'open').length);
  const online = useAegisStore((s) => s.agents.filter((a) => a.status === 'online').length);
  const { text, dot } = LABEL[connection];

  return (
    <header className="mb-8 flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
      <Image src="/logo-dark-bg.png" alt="Aegis EDR - Endpoint Detection & Response" width={1526} height={231} priority className="h-10 w-auto" />
      <div className="flex items-center gap-5 text-sm text-slate-300">
        <span>{online} agent{online === 1 ? '' : 's'} online</span>
        <span>{openAlerts} open alert{openAlerts === 1 ? '' : 's'}</span>
        <span className="flex items-center gap-2 rounded-full border border-slate-700 px-3 py-1">
          <span className={`h-2 w-2 rounded-full ${dot}`} />
          {text}
        </span>
      </div>
    </header>
  );
}
