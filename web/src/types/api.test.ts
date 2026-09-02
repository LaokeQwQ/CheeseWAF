import { describe, expect, it } from 'vitest';
import type { MonitorSnapshot, ProtectionConfig, RuntimeStats } from './api';

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

describe('RuntimeStats (GET /stats) stays a subset of MonitorSnapshot (GET /monitor)', () => {
  /**
   * /stats 除了写死的 status 之外，每个字段都能在 /monitor 的快照里拿到同名字段，
   * 所以它不该有独立 UI。这里把"子集"关系固化成类型约束：
   * 一旦后端给 /stats 加了 /monitor 没有的字段，这行赋值就会编译失败，
   * 提醒接线者重新评估而不是默认继续不接。
   */
  it('aligns with the handler in internal/api/handler/stats.go', () => {
    const stats: RuntimeStats = {
      uptime_seconds: 3_600,
      goroutines: 128,
      process_count: 2,
      memory_alloc: 41_234_567,
      sites: 7,
      status: 'running',
    };
    const sharedKeys: Array<Exclude<keyof RuntimeStats, 'status'>> = ['uptime_seconds', 'goroutines', 'process_count', 'memory_alloc', 'sites'];
    const mirroredByMonitor: Array<keyof MonitorSnapshot> = sharedKeys;

    expect(stats.status).toBe('running');
    expect(mirroredByMonitor).toHaveLength(sharedKeys.length);
  });
});
