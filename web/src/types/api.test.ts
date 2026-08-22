import { describe, expect, it } from 'vitest';
import type { ProtectionConfig } from './api';

describe('ProtectionConfig bot type', () => {
  it('exposes the fields aligned with internal/config BotProtectionConfig', () => {
    const bot: ProtectionConfig['bot'] = {
      enabled: true,
      risk_level: 2,
      risk_low_threshold: 30,
      risk_medium_threshold: 50,
      risk_high_threshold: 70,
      risk_block_threshold: 90,
      risk_confidence_min: 0.6,
      js_challenge: true,
      captcha: false,
      captcha_type: 'pow',
      captcha_types: ['pow'],
      captcha_challenge_ttl: 60,
      captcha_failure_window: 60,
      captcha_block_duration: 300,
      captcha_escalation_types: [],
      captcha_binding_mode: 'strict_ip_ua',
      captcha_policy_version: 'v1',
      captcha_max_attempts: 3,
      image_captcha_length: 4,
      image_captcha_width: 240,
      image_captcha_height: 120,
      image_captcha_audio_limit: 3,
      slider_captcha_width: 320,
      slider_captcha_height: 150,
      slider_captcha_piece: 42,
      slider_captcha_tolerance: 6,
      slider_captcha_min_drag: 400,
      slider_captcha_track_required: true,
      captcha_mobile_type: 'pow',
      challenge_difficulty: 1,
      altcha_max_number: 12000,
      altcha_header_name: 'X-CW-Altcha',
      clearance_header_enabled: true,
      clearance_header_name: 'X-API-Clearance',
      clearance_method_scope: true,
      clearance_state_capacity: 100,
      pow_max_difficulty: 2,
      pow_accept_legacy: false,
      clearance_accept_legacy: true,
      waiting_room: false,
      waiting_room_max_active: 100,
      waiting_room_ttl: 60,
      challenge_ttl: 60,
      cookie_name: 'cw_clearance',
      secret: 'test',
      path_prefixes: [],
      exempt_path_prefixes: [],
      allowed_user_agents: [],
      suspicious_user_agents: [],
    };

    expect(bot.risk_level).toBe(2);
    expect(bot.clearance_header_enabled).toBe(true);
    expect(bot.pow_max_difficulty).toBe(2);
    expect(bot.pow_accept_legacy).toBe(false);
    expect(bot.captcha_binding_mode).toBe('strict_ip_ua');
  });
});
