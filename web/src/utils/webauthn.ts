import type { PasskeyCredentialDescriptorJSON, PasskeyPublicKeyOptions } from '../types/api';

type WebAuthnJSONParser = {
  parseCreationOptionsFromJSON?: (options: unknown) => PublicKeyCredentialCreationOptions;
  parseRequestOptionsFromJSON?: (options: unknown) => PublicKeyCredentialRequestOptions;
};

function webauthnJSONParser(): WebAuthnJSONParser | null {
  if (typeof window === 'undefined' || typeof window.PublicKeyCredential !== 'function') {
    return null;
  }
  return window.PublicKeyCredential as unknown as WebAuthnJSONParser;
}

export function isPasskeySupported() {
  return typeof navigator !== 'undefined'
    && typeof navigator.credentials?.create === 'function'
    && typeof navigator.credentials?.get === 'function'
    && webauthnJSONParser() !== null;
}

export function base64UrlToBuffer(value: string): ArrayBuffer {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

export function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunk = 0x8000;
  for (let index = 0; index < bytes.length; index += chunk) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunk));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeDescriptors(descriptors?: PasskeyCredentialDescriptorJSON[]): PublicKeyCredentialDescriptor[] | undefined {
  if (!descriptors || descriptors.length === 0) {
    return undefined;
  }
  return descriptors.map((descriptor) => ({
    id: base64UrlToBuffer(descriptor.id),
    type: (descriptor.type ?? 'public-key') as PublicKeyCredentialType,
    transports: descriptor.transports as AuthenticatorTransport[] | undefined,
  }));
}

function creationOptionsFromJSON(options: PasskeyPublicKeyOptions['publicKey']): PublicKeyCredentialCreationOptions {
  if (!options.user) {
    throw new Error('passkey creation options are missing the user handle');
  }
  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge),
    user: { ...options.user, id: base64UrlToBuffer(options.user.id) },
    excludeCredentials: decodeDescriptors(options.excludeCredentials),
  } as unknown as PublicKeyCredentialCreationOptions;
}

function requestOptionsFromJSON(options: PasskeyPublicKeyOptions['publicKey']): PublicKeyCredentialRequestOptions {
  return {
    ...options,
    challenge: base64UrlToBuffer(options.challenge),
    allowCredentials: decodeDescriptors(options.allowCredentials),
  } as unknown as PublicKeyCredentialRequestOptions;
}

/** Converts creation options using the browser parser when present. */
export function parsePasskeyCreationOptions(options: PasskeyPublicKeyOptions['publicKey']): PublicKeyCredentialCreationOptions {
  const parser = webauthnJSONParser()?.parseCreationOptionsFromJSON;
  return parser ? parser(options) : creationOptionsFromJSON(options);
}

/** Converts request options using the browser parser when present. */
export function parsePasskeyRequestOptions(options: PasskeyPublicKeyOptions['publicKey']): PublicKeyCredentialRequestOptions {
  const parser = webauthnJSONParser()?.parseRequestOptionsFromJSON;
  return parser ? parser(options) : requestOptionsFromJSON(options);
}

/**
 * Serializes a browser credential for the Go WebAuthn parser. Browsers with
 * PublicKeyCredential.toJSON keep the full field set; older browsers get the
 * fields the server actually verifies.
 */
export function passkeyCredentialToJSON(credential: PublicKeyCredential): Record<string, unknown> {
  const native = credential as unknown as { toJSON?: () => Record<string, unknown> };
  if (typeof native.toJSON === 'function') {
    return native.toJSON();
  }
  const base = {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
  const response = credential.response;
  if ('attestationObject' in response) {
    const attestation = response as AuthenticatorAttestationResponse;
    return {
      ...base,
      response: {
        clientDataJSON: bufferToBase64Url(attestation.clientDataJSON),
        attestationObject: bufferToBase64Url(attestation.attestationObject),
        transports: typeof attestation.getTransports === 'function' ? attestation.getTransports() : undefined,
      },
    };
  }
  const assertion = response as AuthenticatorAssertionResponse;
  return {
    ...base,
    response: {
      clientDataJSON: bufferToBase64Url(assertion.clientDataJSON),
      authenticatorData: bufferToBase64Url(assertion.authenticatorData),
      signature: bufferToBase64Url(assertion.signature),
      userHandle: assertion.userHandle ? bufferToBase64Url(assertion.userHandle) : null,
    },
  };
}

export function isPasskeyCancellation(error: unknown) {
  const name = error instanceof DOMException || error instanceof Error ? error.name : '';
  return name === 'NotAllowedError' || name === 'AbortError' || name === 'TimeoutError';
}
