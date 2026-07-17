import { describe, expect, it, vi } from 'vitest';
import { appendTrack, leadingZeroBits, normalizePoint, solvePow, trackPoint } from './interaction';
describe('captcha interaction utilities', () => {
  it('normalizes coordinates and caps tracks at 128', () => { const rect = { left: 0, top: 0, width: 100, height: 100 } as DOMRect; expect(normalizePoint(50, 200, rect)).toEqual({ x: 5000, y: 10000 }); let track = [] as ReturnType<typeof trackPoint>[]; for (let i=0;i<200;i++) track=appendTrack(track,trackPoint({x:i,y:i},i)); expect(track.length).toBeLessThanOrEqual(128); });
  it('counts leading zero bits', () => { expect(leadingZeroBits(new Uint8Array([0, 0x10]))).toBe(11); });
  it('solves low difficulty proof using salt colon proof', async () => { const digest = vi.spyOn(crypto.subtle,'digest').mockResolvedValue(new Uint8Array(32).buffer); await expect(solvePow('salt',1,undefined,1)).resolves.toBe('0'); expect(new TextDecoder().decode(digest.mock.calls[0][1] as ArrayBuffer)).toBe('salt:0'); digest.mockRestore(); });
});
