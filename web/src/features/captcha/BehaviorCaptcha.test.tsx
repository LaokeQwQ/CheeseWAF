import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { BehaviorCaptcha } from './BehaviorCaptcha';
import type { CaptchaChallenge, ResolvedCaptchaType } from './protocol';
const image='data:image/png;base64,iVBORw0KGgo=';
function challenge(type: ResolvedCaptchaType, extra: Partial<CaptchaChallenge['presentation']> = {}): CaptchaChallenge { return { type, token:`${type}-token`, expires_at:'2030-01-01T00:00:00Z', presentation:{kind:'image',image,...extra} }; }
function rect(element: HTMLElement){vi.spyOn(element,'getBoundingClientRect').mockReturnValue({left:0,top:0,width:200,height:100,right:200,bottom:100,x:0,y:0,toJSON:()=>({})});}
afterEach(() => {
  vi.useRealTimers();
  cleanup();
});
describe('BehaviorCaptcha responses',()=>{
  it('uses resolved random type and submits click point in Go shape',async()=>{const verify=vi.fn().mockResolvedValue({valid:true,type:'text_click'});render(<BehaviorCaptcha type="random" issue={vi.fn().mockResolvedValue(challenge('text_click'))} verify={verify} locale="en-US"/>);const surface=await screen.findByTestId('captcha-surface');rect(surface);fireEvent.click(surface,{clientX:100,clientY:50});fireEvent.click(screen.getByRole('button',{name:'Verify'}));await waitFor(()=>expect(verify).toHaveBeenCalledWith({token:'text_click-token',point:{x:5000,y:5000}},expect.any(AbortSignal)));});
  it('submits angle response shape',async()=>{const angleVerify=vi.fn().mockResolvedValue({valid:true});render(<BehaviorCaptcha type="angle" issue={vi.fn().mockResolvedValue(challenge('angle'))} verify={angleVerify} locale="en-US"/>);const range=await screen.findByRole('slider');fireEvent.pointerDown(range,{pointerId:1});fireEvent.change(range,{target:{value:'1167'}});fireEvent.pointerUp(range,{pointerId:1});await waitFor(()=>expect(angleVerify.mock.calls[0][0]).toMatchObject({token:'angle-token',angle:42,track:expect.any(Array)}));});
  it('pointercancel never submits',async()=>{const verify=vi.fn();render(<BehaviorCaptcha type="curve_draw" issue={vi.fn().mockResolvedValue(challenge('curve_draw'))} verify={verify} locale="en-US"/>);const surface=await screen.findByTestId('curve-draw-surface');rect(surface);fireEvent.pointerDown(surface,{pointerId:7,clientX:10,clientY:10});fireEvent.pointerCancel(surface,{pointerId:7});expect(verify).not.toHaveBeenCalled();});
  it('rejects unsafe image URLs',async()=>{render(<BehaviorCaptcha type="text_click" issue={vi.fn().mockResolvedValue(challenge('text_click',{image:'javascript:alert(1)'}))} verify={vi.fn()} locale="en-US"/>);expect((await screen.findByRole('alert')).textContent).toBe('Invalid or missing image data');expect(document.querySelector('img[src^="javascript:"]')).toBeNull();});
  it('uses the unified shell logo and optional close action',async()=>{const close=vi.fn();render(<BehaviorCaptcha type="text_click" issue={vi.fn().mockResolvedValue(challenge('text_click'))} verify={vi.fn()} locale="en-US" logoSrc="/custom-logo.png" onClose={close}/>);await screen.findByTestId('captcha-surface');expect(screen.getByLabelText('CheeseWAF').querySelector('img')?.getAttribute('src')).toBe('/custom-logo.png');fireEvent.click(screen.getByRole('button',{name:'Close'}));expect(close).toHaveBeenCalledOnce();});
  it('does not expose server reasons and replaces a failed challenge after one second',async()=>{const issue=vi.fn().mockResolvedValueOnce(challenge('text_click')).mockResolvedValueOnce({...challenge('text_click'),token:'replacement-token'});render(<BehaviorCaptcha type="text_click" issue={issue} verify={vi.fn().mockResolvedValue({valid:false,reason:'secret tolerance=180'})} locale="en-US"/>);const surface=await screen.findByTestId('captcha-surface');rect(surface);vi.useFakeTimers();fireEvent.click(surface,{clientX:100,clientY:50});fireEvent.click(screen.getByRole('button',{name:'Verify'}));await vi.advanceTimersByTimeAsync(0);expect(screen.getByRole('status').textContent).toContain('Verification failed');expect(screen.queryByText(/secret tolerance/)).toBeNull();await vi.advanceTimersByTimeAsync(999);expect(issue).toHaveBeenCalledTimes(1);await vi.advanceTimersByTimeAsync(1);await vi.advanceTimersByTimeAsync(0);expect(issue).toHaveBeenCalledTimes(2);});
  it('locks duplicate automatic submissions and freezes after success',async()=>{let resolveVerify:(value:{valid:boolean})=>void=()=>{};const verify=vi.fn().mockImplementation(()=>new Promise((resolve)=>{resolveVerify=resolve}));render(<BehaviorCaptcha type="angle" issue={vi.fn().mockResolvedValue(challenge('angle'))} verify={verify} locale="en-US"/>);const range=await screen.findByRole('slider') as HTMLInputElement;fireEvent.pointerDown(range,{pointerId:2});fireEvent.change(range,{target:{value:'4200'}});fireEvent.pointerUp(range,{pointerId:2});fireEvent.pointerUp(range,{pointerId:2});expect(verify).toHaveBeenCalledTimes(1);resolveVerify({valid:true});await screen.findByText('Verified');expect(range.disabled).toBe(true);expect((screen.getByRole('button',{name:'New challenge'}) as HTMLButtonElement).disabled).toBe(true);});
  it.each([
    ['curve_draw','curve-draw-surface'],['curve_slider','curve-slider-control'],['rotate','rotate-puzzle-challenge'],['angle','angle-challenge'],['restore_slider','restore-slider-challenge'],
  ] as const)('mounts the dedicated %s challenge component',async(type,testId)=>{render(<BehaviorCaptcha type={type} issue={vi.fn().mockResolvedValue(challenge(type,{version:2}))} verify={vi.fn()} locale="en-US"/>);expect(await screen.findByTestId(testId)).not.toBeNull();});

  it('keeps the shape slider range bound to its CSS module class', async () => {
    render(<BehaviorCaptcha type={'shape_slider'} issue={vi.fn().mockResolvedValue(challenge('shape_slider'))} verify={vi.fn()} locale={'en-US'} />);
    const range = await screen.findByRole('slider');
    expect(range.className.trim()).not.toBe('');
  });

  it('keeps the server-provided Chinese selection target visible', async () => {
    render(<BehaviorCaptcha type="text_click" issue={vi.fn().mockResolvedValue(challenge('text_click', { prompt: '请点击字符 7' }))} verify={vi.fn()} locale="zh-CN"/>);
    expect(await screen.findByText('请点击字符 7')).toBeTruthy();
    expect(screen.getByRole('button', { name: '请点击字符 7' })).toBeTruthy();
  });

  it('keeps a new challenge locked when an obsolete verification settles', async () => {
    let resolveOld: (value: { valid: boolean }) => void = () => {};
    let resolveCurrent: (value: { valid: boolean }) => void = () => {};
    const oldVerify = vi.fn(() => new Promise<{ valid: boolean }>((resolve) => { resolveOld = resolve; }));
    const currentVerify = vi.fn(() => new Promise<{ valid: boolean }>((resolve) => { resolveCurrent = resolve; }));
    const firstIssue = vi.fn().mockResolvedValue(challenge('angle'));
    const secondIssue = vi.fn().mockResolvedValue({ ...challenge('angle'), token: 'current-angle-token' });
    const view = render(<BehaviorCaptcha type="angle" issue={firstIssue} verify={oldVerify} locale="en-US"/>);
    const oldSlider = await screen.findByRole('slider');
    fireEvent.pointerDown(oldSlider, { pointerId: 3 });
    fireEvent.change(oldSlider, { target: { value: '1200' } });
    fireEvent.pointerUp(oldSlider, { pointerId: 3 });
    expect(oldVerify).toHaveBeenCalledTimes(1);

    view.rerender(<BehaviorCaptcha type="angle" issue={secondIssue} verify={currentVerify} locale="en-US"/>);
    await waitFor(() => expect(secondIssue).toHaveBeenCalledTimes(1));
    const currentSlider = await screen.findByRole('slider');
    fireEvent.pointerDown(currentSlider, { pointerId: 4 });
    fireEvent.change(currentSlider, { target: { value: '2200' } });
    fireEvent.pointerUp(currentSlider, { pointerId: 4 });
    expect(currentVerify).toHaveBeenCalledTimes(1);

    resolveOld({ valid: true });
    await Promise.resolve();
    fireEvent.pointerUp(currentSlider, { pointerId: 4 });
    expect(currentVerify).toHaveBeenCalledTimes(1);
    resolveCurrent({ valid: true });
    expect(await screen.findByText('Verified')).toBeTruthy();
  });

  it('uses product titles and translates the dynamic scratch target in English', async () => {
    render(<BehaviorCaptcha type="scratch" issue={vi.fn().mockResolvedValue(challenge('scratch', { prompt: '请刮出完整的奶酪后点击校验' }))} verify={vi.fn()} locale="en-US"/>);
    expect(await screen.findByText('Scratch Challenge')).toBeTruthy();
    expect(screen.getByText('Scratch to reveal “奶酪”, then verify')).toBeTruthy();
  });

  it('aborts an in-flight issue request when refreshed', async () => {
    let resolveReplacement: (value: CaptchaChallenge) => void = () => {};
    const replacement = new Promise<CaptchaChallenge>((resolve) => { resolveReplacement = resolve; });
    const issueSignals: AbortSignal[] = [];
    const issue = vi.fn()
      .mockImplementationOnce((_type, signal?: AbortSignal) => {
        if (signal) issueSignals.push(signal);
        return Promise.resolve(challenge('text_click'));
      })
      .mockImplementationOnce((_type, signal?: AbortSignal) => {
        if (signal) issueSignals.push(signal);
        return replacement;
      });

    render(<BehaviorCaptcha type={'text_click'} issue={issue} verify={vi.fn()} locale={'en-US'} />);
    expect(await screen.findByTestId('captcha-surface')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'New challenge' }));
    await waitFor(() => expect(issue).toHaveBeenCalledTimes(2));
    expect(issueSignals).toHaveLength(2);
    expect(issueSignals[0].aborted).toBe(true);
    expect(issueSignals[1].aborted).toBe(false);
    expect(screen.queryByTestId('captcha-surface')).toBeNull();

    resolveReplacement({ ...challenge('text_click'), token: 'fresh-token' });
    expect(await screen.findByTestId('captcha-surface')).toBeTruthy();
    expect(screen.getByText('Select the requested target')).toBeTruthy();
  });

  it('aborts an issue request when closed and unmounted', async () => {
    let resolveIssue: (value: CaptchaChallenge) => void = () => {};
    let issueSignal: AbortSignal | undefined;
    const issue = vi.fn((_type, signal?: AbortSignal) => {
      issueSignal = signal;
      return new Promise<CaptchaChallenge>((resolve) => { resolveIssue = resolve; });
    });
    const onClose = vi.fn();
    const view = render(<BehaviorCaptcha type={'text_click'} issue={issue} verify={vi.fn()} locale={'en-US'} onClose={onClose} />);

    await waitFor(() => expect(issue).toHaveBeenCalledTimes(1));
    expect(issueSignal?.aborted).toBe(false);
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(onClose).toHaveBeenCalledOnce();
    expect(issueSignal?.aborted).toBe(true);
    view.unmount();
    resolveIssue(challenge('text_click'));
    await Promise.resolve();

    expect(screen.queryByTestId('captcha-surface')).toBeNull();
  });

  it('aborts an in-flight verification when closed', async () => {
    let verifySignal: AbortSignal | undefined;
    const verify = vi.fn((_response, signal?: AbortSignal) => {
      verifySignal = signal;
      return new Promise<{ valid: boolean }>(() => {});
    });
    const onClose = vi.fn();
    render(<BehaviorCaptcha type={'text_click'} issue={vi.fn().mockResolvedValue(challenge('text_click'))} verify={verify} locale={'en-US'} onClose={onClose}/>);
    const surface = await screen.findByTestId('captcha-surface');
    rect(surface);
    fireEvent.click(surface, { clientX: 100, clientY: 50 });
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(verify).toHaveBeenCalledTimes(1));
    expect(verifySignal?.aborted).toBe(false);

    fireEvent.click(screen.getByRole('button', { name: 'Close' }));

    expect(onClose).toHaveBeenCalledOnce();
    expect(verifySignal?.aborted).toBe(true);
  });

  it('aborts an in-flight verification when refreshed', async () => {
    let verifySignal: AbortSignal | undefined;
    const verify = vi.fn((_response, signal?: AbortSignal) => {
      verifySignal = signal;
      return new Promise<{ valid: boolean }>(() => {});
    });
    render(<BehaviorCaptcha type={'text_click'} issue={vi.fn().mockResolvedValue(challenge('text_click'))} verify={verify} locale={'en-US'}/>);
    const surface = await screen.findByTestId('captcha-surface');
    rect(surface);
    fireEvent.click(surface, { clientX: 100, clientY: 50 });
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(verify).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole('button', { name: 'New challenge' }));

    expect(verifySignal?.aborted).toBe(true);
  });

  it('aborts an in-flight issue request when unmounted', async () => {
    let issueSignal: AbortSignal | undefined;
    const issue = vi.fn((_type, signal?: AbortSignal) => {
      issueSignal = signal;
      return new Promise<CaptchaChallenge>(() => {});
    });
    const view = render(<BehaviorCaptcha type={'text_click'} issue={issue} verify={vi.fn()} locale={'en-US'}/>);
    await waitFor(() => expect(issue).toHaveBeenCalledTimes(1));

    view.unmount();

    expect(issueSignal?.aborted).toBe(true);
  });

  it('aborts an in-flight verification when unmounted', async () => {
    let verifySignal: AbortSignal | undefined;
    const verify = vi.fn((_response, signal?: AbortSignal) => {
      verifySignal = signal;
      return new Promise<{ valid: boolean }>(() => {});
    });
    const view = render(<BehaviorCaptcha type={'text_click'} issue={vi.fn().mockResolvedValue(challenge('text_click'))} verify={verify} locale={'en-US'}/>);
    const surface = await screen.findByTestId('captcha-surface');
    rect(surface);
    fireEvent.click(surface, { clientX: 100, clientY: 50 });
    fireEvent.click(screen.getByRole('button', { name: 'Verify' }));
    await waitFor(() => expect(verify).toHaveBeenCalledTimes(1));

    view.unmount();

    expect(verifySignal?.aborted).toBe(true);
  });
});
