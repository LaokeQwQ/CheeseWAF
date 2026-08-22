import { beforeEach, describe, expect, it, vi } from 'vitest';
import { subscribeRealtimeEvents } from './realtime';

class MockEventSource {
  static instances: MockEventSource[] = [];
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  listeners = new Map<string, (event: MessageEvent<string>) => void>();
  close = vi.fn();

  constructor(public readonly url: string, public readonly init: EventSourceInit) {
    MockEventSource.instances.push(this);
  }

  addEventListener(type: string, listener: (event: MessageEvent<string>) => void) {
    this.listeners.set(type, listener);
  }
}

class MockWebSocket {
  static instances: MockWebSocket[] = [];
  onopen: (() => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: ((event: MessageEvent<string>) => void) | null = null;
  close = vi.fn();

  constructor(public readonly url: string) {
    MockWebSocket.instances.push(this);
  }
}

describe('subscribeRealtimeEvents', () => {
  beforeEach(() => {
    MockEventSource.instances = [];
    MockWebSocket.instances = [];
  });

  it('starts with credentialed SSE, then adds WebSocket and ignores malformed messages', () => {
    const onEvent = vi.fn();
    const onConnectionChange = vi.fn();
    const subscription = subscribeRealtimeEvents({
      onEvent,
      onConnectionChange,
      EventSource: MockEventSource as unknown as typeof EventSource,
      WebSocket: MockWebSocket as unknown as typeof WebSocket,
    });

    const source = MockEventSource.instances[0];
    expect(source.url).toBe('/api/realtime/events');
    expect(source.init).toEqual({ withCredentials: true });
    expect(MockWebSocket.instances).toHaveLength(0);

    source.onopen?.();
    expect(MockWebSocket.instances[0]?.url).toBe('ws://localhost:3000/api/realtime/ws');
    source.listeners.get('log')?.({ data: '{"type":"log","payload":{"id":"log-1"}}' } as MessageEvent<string>);
    source.listeners.get('log')?.({ data: '{broken' } as MessageEvent<string>);
    expect(onEvent).toHaveBeenCalledWith({ type: 'log', payload: { id: 'log-1' } });
    expect(onEvent).toHaveBeenCalledTimes(1);
    expect(onConnectionChange).toHaveBeenLastCalledWith(true);

    MockWebSocket.instances[0]?.onopen?.();
    MockWebSocket.instances[0]?.onmessage?.({ data: '{"type":"alert","payload":{"id":"alert-1"}}' } as MessageEvent<string>);
    expect(onEvent).toHaveBeenLastCalledWith({ type: 'alert', payload: { id: 'alert-1' } });

    subscription.close();
    expect(source.close).toHaveBeenCalledTimes(1);
    expect(MockWebSocket.instances[0]?.close).toHaveBeenCalledTimes(1);
    expect(onConnectionChange).toHaveBeenLastCalledWith(false);
  });

  it('keeps the WebSocket live when SSE drops and reconnects it with backoff', () => {
    const onConnectionChange = vi.fn();
    const reconnects: Array<() => void> = [];
    const delays: number[] = [];
    const subscription = subscribeRealtimeEvents({
      onEvent: vi.fn(),
      onConnectionChange,
      EventSource: MockEventSource as unknown as typeof EventSource,
      WebSocket: MockWebSocket as unknown as typeof WebSocket,
      setTimeout: ((callback: TimerHandler, delay?: number) => {
        reconnects.push(callback as () => void);
        delays.push(delay ?? 0);
        return reconnects.length;
      }) as unknown as typeof window.setTimeout,
      clearTimeout: vi.fn(),
    });

    const source = MockEventSource.instances[0];
    source.onopen?.();
    const firstSocket = MockWebSocket.instances[0];
    firstSocket.onopen?.();

    source.onerror?.();
    expect(firstSocket.close).not.toHaveBeenCalled();
    expect(onConnectionChange).toHaveBeenLastCalledWith(true);

    firstSocket.onclose?.();
    expect(onConnectionChange).toHaveBeenLastCalledWith(false);
    expect(delays).toEqual([1_000]);

    reconnects[0]?.();
    expect(MockWebSocket.instances).toHaveLength(2);
    MockWebSocket.instances[1]?.onopen?.();
    expect(onConnectionChange).toHaveBeenLastCalledWith(true);

    subscription.close();
  });

  it('falls back to WebSocket and then polling when EventSource is unavailable', () => {
    const onConnectionChange = vi.fn();
    const subscription = subscribeRealtimeEvents({
      onEvent: vi.fn(),
      onConnectionChange,
      EventSource: null,
      WebSocket: MockWebSocket as unknown as typeof WebSocket,
    });

    expect(MockWebSocket.instances).toHaveLength(1);
    expect(onConnectionChange).toHaveBeenLastCalledWith(false);
    MockWebSocket.instances[0]?.onopen?.();
    expect(onConnectionChange).toHaveBeenLastCalledWith(true);

    MockWebSocket.instances[0]?.onclose?.();
    expect(onConnectionChange).toHaveBeenLastCalledWith(false);
    subscription.close();
  });
});
