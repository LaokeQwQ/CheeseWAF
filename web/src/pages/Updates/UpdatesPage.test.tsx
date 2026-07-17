import { describe, expect, it } from 'vitest';
import { fallbackSystem } from '../System/systemModel';
import {
  buildUpdatesSavePayload,
  CUSTOM_OTA_SERVER_OPTION,
  resolveOTAServerSelectValue,
  validateOTAServer,
} from './UpdatesPage';

describe('OTA custom source handling', () => {
  it('uses custom mode for unknown servers without treating the marker as a URL', () => {
    expect(resolveOTAServerSelectValue('https://updates.example.com/releases')).toBe(CUSTOM_OTA_SERVER_OPTION);
    expect(validateOTAServer(CUSTOM_OTA_SERVER_OPTION, CUSTOM_OTA_SERVER_OPTION)).toBeNull();
  });

  it('refuses to save the custom marker or non-HTTPS custom URLs', () => {
    expect(() => buildUpdatesSavePayload({
      ...fallbackSystem,
      update: { ota: { ...fallbackSystem.update.ota, server: '' } },
    }, CUSTOM_OTA_SERVER_OPTION)).toThrow('valid HTTPS URL');

    expect(() => buildUpdatesSavePayload({
      ...fallbackSystem,
      update: { ota: { ...fallbackSystem.update.ota, server: CUSTOM_OTA_SERVER_OPTION } },
    }, CUSTOM_OTA_SERVER_OPTION)).toThrow('valid HTTPS URL');

    expect(() => buildUpdatesSavePayload({
      ...fallbackSystem,
      update: { ota: { ...fallbackSystem.update.ota, server: 'http://updates.example.com/releases' } },
    }, CUSTOM_OTA_SERVER_OPTION)).toThrow('valid HTTPS URL');
  });

  it('saves a valid custom HTTPS URL instead of the custom marker', () => {
    const payload = buildUpdatesSavePayload({
      ...fallbackSystem,
      update: { ota: { ...fallbackSystem.update.ota, server: 'https://updates.example.com/releases' } },
    }, CUSTOM_OTA_SERVER_OPTION);

    expect(payload.update.ota.server).toBe('https://updates.example.com/releases');
    expect(payload.update.ota.server).not.toBe(CUSTOM_OTA_SERVER_OPTION);
  });
});
