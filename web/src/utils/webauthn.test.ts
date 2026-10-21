import { afterEach, describe, expect, it, vi } from 'vitest';
import { base64UrlToBuffer, bufferToBase64Url, isPasskeyCancellation, parsePasskeyCreationOptions, parsePasskeyRequestOptions, passkeyCredentialToJSON } from './webauthn';

const bytes = (...values: number[]) => Uint8Array.from(values).buffer;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('webauthn base64url conversion', () => {
  it('round-trips unpadded base64url payloads', () => {
    const buffer = bytes(0xfb, 0xff, 0x01, 0x02);
    const encoded = bufferToBase64Url(buffer);
    expect(encoded).toBe('-_8BAg');
    expect(Array.from(new Uint8Array(base64UrlToBuffer(encoded)))).toEqual([0xfb, 0xff, 0x01, 0x02]);
  });
});

describe('webauthn option parsing fallback', () => {
  it('decodes challenge and credential identifiers without a native parser', () => {
    vi.stubGlobal('PublicKeyCredential', class {});
    const request = parsePasskeyRequestOptions({
      challenge: 'AQID',
      allowCredentials: [{ id: 'BAUG', type: 'public-key', transports: ['internal'] }],
    });
    expect(Array.from(new Uint8Array(request.challenge as ArrayBuffer))).toEqual([1, 2, 3]);
    expect(Array.from(new Uint8Array(request.allowCredentials?.[0].id as ArrayBuffer))).toEqual([4, 5, 6]);
    expect(request.allowCredentials?.[0].transports).toEqual(['internal']);
  });

  it('decodes user handles for registration', () => {
    vi.stubGlobal('PublicKeyCredential', class {});
    const creation = parsePasskeyCreationOptions({
      challenge: 'AQID',
      user: { id: 'BwgJ', name: 'admin', displayName: 'Admin' },
      excludeCredentials: [{ id: 'BAUG' }],
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    });
    expect(Array.from(new Uint8Array(creation.user.id as ArrayBuffer))).toEqual([7, 8, 9]);
    expect(Array.from(new Uint8Array(creation.excludeCredentials?.[0].id as ArrayBuffer))).toEqual([4, 5, 6]);
  });
});

describe('webauthn credential serialization', () => {
  it('serializes assertion fields for the Go verifier', () => {
    const credential = {
      id: 'credential-id',
      rawId: bytes(1, 2, 3),
      type: 'public-key',
      authenticatorAttachment: null,
      getClientExtensionResults: () => ({}),
      response: {
        clientDataJSON: bytes(4, 5),
        authenticatorData: bytes(6, 7),
        signature: bytes(8, 9),
        userHandle: bytes(10),
      },
    } as unknown as PublicKeyCredential;
    const serialized = passkeyCredentialToJSON(credential) as {
      id: string;
      rawId: string;
      response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle: string };
    };
    expect(serialized.id).toBe('credential-id');
    expect(serialized.rawId).toBe('AQID');
    expect(serialized.response.clientDataJSON).toBe('BAU');
    expect(serialized.response.authenticatorData).toBe('Bgc');
    expect(serialized.response.signature).toBe('CAk');
    expect(serialized.response.userHandle).toBe('Cg');
  });

  it('uses the browser parser when available', () => {
    const native = vi.fn(() => ({ sentinel: true }));
    vi.stubGlobal('PublicKeyCredential', Object.assign(class {}, { parseRequestOptionsFromJSON: native }));
    const parsed = parsePasskeyRequestOptions({ challenge: 'AQID' }) as unknown as { sentinel: boolean };
    expect(parsed.sentinel).toBe(true);
    expect(native).toHaveBeenCalledWith({ challenge: 'AQID' });
  });
});

describe('passkey cancellation classification', () => {
  it('recognizes cancellation and timeout errors', () => {
    expect(isPasskeyCancellation(new DOMException('cancelled', 'NotAllowedError'))).toBe(true);
    expect(isPasskeyCancellation(new DOMException('timeout', 'TimeoutError'))).toBe(true);
    expect(isPasskeyCancellation(new Error('other'))).toBe(false);
  });
});
