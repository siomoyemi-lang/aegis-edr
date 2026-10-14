import { useEffect } from 'react';
import { WS_URL } from '@/lib/config';
import { fetchAgents, fetchAlerts } from '@/lib/api';
import { useAegisStore } from '@/store/useAegisStore';

const WIN32_ERRORS: Record<number, string> = {
  5: 'access denied',
  87: 'process no longer exists',
};

/**
 * Keeps the Zustand store in sync with the gateway: loads a snapshot on every (re)connect, then applies
 * live NEW_ALERT / KILL_RESULT / AGENT_STATUS events. Reconnects with capped exponential backoff.
 */
export function useAegisWebSocket() {
  useEffect(() => {
    const store = useAegisStore.getState;
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let attempt = 0;
    let disposed = false;

    const loadSnapshot = async () => {
      try {
        const [alerts, agents] = await Promise.all([fetchAlerts(), fetchAgents()]);
        if (disposed) return;
        store().mergeAlerts(alerts);
        store().setAgents(agents);
      } catch (err) {
        console.warn('Aegis snapshot failed', err);
      }
    };

    const connect = () => {
      store().setConnection('connecting');
      ws = new WebSocket(WS_URL);

      ws.onopen = () => {
        attempt = 0;
        store().setConnection('open');
        void loadSnapshot();
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          switch (msg.type) {
            case 'NEW_ALERT':
              store().addAlert(msg.payload);
              break;
            case 'AGENT_STATUS':
              store().upsertAgent(msg.payload);
              break;
            case 'KILL_RESULT': {
              const { alert_id, status, error } = msg.payload;
              if (!alert_id) break;
              if (status === 'SUCCESS') {
                store().resolveAlert(alert_id);
              } else {
                const why = WIN32_ERRORS[error] ?? `Win32 error ${error}`;
                store().setKillState(alert_id, { phase: 'failed', message: `Agent could not terminate: ${why}` });
              }
              break;
            }
          }
        } catch (err) {
          console.error('Failed to parse Aegis message', err);
        }
      };

      ws.onclose = () => {
        if (disposed) return;
        store().setConnection('closed');
        timer = setTimeout(connect, Math.min(1000 * 2 ** attempt++, 15000));
      };
      ws.onerror = () => ws?.close();
    };

    connect();
    return () => {
      disposed = true;
      clearTimeout(timer);
      ws?.close();
    };
  }, []);
}
