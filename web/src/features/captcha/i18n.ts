export type CaptchaLocale = 'zh-CN' | 'en-US';
const messages = {
  'zh-CN': { loading: '正在生成验证题', retry: '重新生成', close: '关闭', verify: '提交验证', verifying: '正在验证', drag: '拖动完成验证', draw: '按住并绘制轨迹', click: '按提示点击目标', scratch: '按住擦除图层', pow: '开始安全验证', solving: '正在完成安全验证', ready: '验证题已就绪', cancelled: '操作已取消', success: '验证通过', failed: '验证未通过，正在更换题目', error: '验证服务暂时不可用', remove: '撤销选择', cancel: '取消' },
  'en-US': { loading: 'Generating challenge', retry: 'New challenge', close: 'Close', verify: 'Verify', verifying: 'Verifying', drag: 'Drag to complete the challenge', draw: 'Press and draw the path', click: 'Select the requested target', scratch: 'Press and scratch the layer', pow: 'Start security check', solving: 'Completing security check', ready: 'Challenge ready', cancelled: 'Interaction cancelled', success: 'Verified', failed: 'Verification failed. Loading a new challenge', error: 'Verification service unavailable', remove: 'Clear selection', cancel: 'Cancel' },
} as const;
export type CaptchaMessageKey = keyof (typeof messages)['en-US'];
export function captchaText(locale: CaptchaLocale, key: CaptchaMessageKey) { return messages[locale][key]; }
