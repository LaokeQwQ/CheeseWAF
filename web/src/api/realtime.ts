export type RealtimeMessage = { type: string; payload: unknown };

type RealtimeOptions = {
  onEvent: (message: RealtimeMessage) => void;
  onConnectionChange: (connected: boolean) => void;
  EventSource?: typeof EventSource | null;
  WebSocket?: typeof WebSocket | null;
  setTimeout?: typeof window.setTimeout;
  clearTimeout?: typeof window.clearTimeout;
};

const eventTypes = ['stats', 'alert', 'ai_stream', 'approval', 'log'];

export function subscribeRealtimeEvents(options: RealtimeOptions) {
  const EventSourceConstructor = options.EventSource === undefined ? globalThis.EventSource : options.EventSource;
  const WebSocketConstructor = options.WebSocket === undefined ? globalThis.WebSocket : options.WebSocket;
  const schedule = options.setTimeout ?? window.setTimeout.bind(window);
  const cancel = options.clearTimeout ?? window.clearTimeout.bind(window);

  let closed = false;
  let source: EventSource | null = null;
  let socket: WebSocket | null = null;
  let reconnectTimer: number | null = null;
  let attempts = 0;
  let sseConnected = false;
  let socketConnected = false;
  let websocketStarted = false;
  let reportedConnected = false;

  const reportConnection = (force = false) => {
    const connected = sseConnected || socketConnected;
    if (force || connected !== reportedConnected) {
      reportedConnected = connected;
      options.onConnectionChange(connected);
    }
  };

  const closeSocket = () => {
    const activeSocket = socket;
    socket = null;
    socketConnected = false;
    activeSocket?.close();
    reportConnection();
  };
  const scheduleSocketReconnect = () => {
    if (closed || !websocketStarted || !WebSocketConstructor || reconnectTimer != null) {
      return;
    }
    const delay = Math.min(30_000, 1_000 * 2 ** Math.min(attempts, 5));
    attempts += 1;
    reconnectTimer = schedule(() => {
      reconnectTimer = null;
      connectWebSocket();
    }, delay);
  };
  const connectWebSocket = () => {
    websocketStarted = true;
    if (closed || !WebSocketConstructor || socket) {
      return;
    }
    let nextSocket: WebSocket;
    try {
      nextSocket = new WebSocketConstructor(realtimeWebSocketURL());
    } catch {
      scheduleSocketReconnect();
      reportConnection(true);
      return;
    }
    socket = nextSocket;
    nextSocket.onopen = () => {
      if (closed || socket !== nextSocket) {
        return;
      }
      attempts = 0;
      socketConnected = true;
      reportConnection();
    };
    nextSocket.onmessage = (event) => deliverMessage(event.data, options.onEvent);
    nextSocket.onerror = () => nextSocket.close();
    nextSocket.onclose = () => {
      if (socket !== nextSocket) {
        return;
      }
      socket = null;
      socketConnected = false;
      reportConnection();
      scheduleSocketReconnect();
    };
  };

  if (!EventSourceConstructor) {
    connectWebSocket();
    reportConnection(true);
  } else {
    try {
      source = new EventSourceConstructor('/api/realtime/events', { withCredentials: true });
    } catch {
      connectWebSocket();
      reportConnection(true);
    }
  }

  if (source) {
    source.onopen = () => {
      sseConnected = true;
      reportConnection();
      connectWebSocket();
    };
    source.onerror = () => {
      sseConnected = false;
      reportConnection();
      connectWebSocket();
    };
    for (const eventType of eventTypes) {
      source.addEventListener(eventType, (event) => deliverMessage((event as MessageEvent<string>).data, options.onEvent));
    }
  }

  return {
    close: () => {
      if (closed) {
        return;
      }
      closed = true;
      sseConnected = false;
      if (reconnectTimer != null) {
        cancel(reconnectTimer);
        reconnectTimer = null;
      }
      source?.close();
      source = null;
      closeSocket();
      reportConnection(true);
    },
  };
}

function deliverMessage(raw: unknown, onEvent: (message: RealtimeMessage) => void) {
  if (typeof raw !== 'string') {
    return;
  }
  try {
    const parsed = JSON.parse(raw) as Partial<RealtimeMessage>;
    if (typeof parsed.type === 'string') {
      onEvent({ type: parsed.type, payload: parsed.payload });
    }
  } catch {
    // A malformed realtime frame must not stop the active transport.
  }
}

function realtimeWebSocketURL() {
  const pageURL = new URL(globalThis.location?.href ?? 'http://localhost/');
  pageURL.protocol = pageURL.protocol === 'https:' ? 'wss:' : 'ws:';
  pageURL.pathname = '/api/realtime/ws';
  pageURL.search = '';
  pageURL.hash = '';
  return pageURL.toString();
}
