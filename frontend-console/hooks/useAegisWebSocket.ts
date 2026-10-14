import { useEffect, useRef } from 'react';
import { useAegisStore } from '../store/useAegisStore';

export const useAegisWebSocket = (wsUrl: string) => {
  const ws = useRef<WebSocket | null>(null);
  const addAlert = useAegisStore((state) => state.addAlert);

  useEffect(() => {
    ws.current = new WebSocket(wsUrl);

    ws.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'NEW_ALERT') {
          addAlert(data.payload);
        }
      } catch (err) {
        console.error("Failed to parse WebSocket message", err);
      }
    };

    ws.current.onclose = () => {
      console.warn("Aegis Gateway WebSocket disconnected.");
    };

    return () => {
      ws.current?.close();
    };
  }, [wsUrl, addAlert]);
};