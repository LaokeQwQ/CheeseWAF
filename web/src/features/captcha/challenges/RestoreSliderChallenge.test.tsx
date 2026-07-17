import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { RestoreSliderChallenge, restoreOffsetForSlider } from './RestoreSliderChallenge';

afterEach(cleanup);
describe('RestoreSliderChallenge',()=>{
  it.each([{initial:-30,value:10000},{initial:30,value:0},{initial:-15,value:7500},{initial:15,value:2500}])('keeps the percentage offset contract reachable for $initial',({initial,value})=>{expect(restoreOffsetForSlider(initial,30,value)).toBe(0)});
  it('splits one image into top and bottom halves and starts at the published offset',()=>{render(<RestoreSliderChallenge challenge={{image:'/portrait.jpg',movingPart:'bottom',initialOffsetPercent:-20,maxOffsetPercent:30}} onComplete={vi.fn()}/>);expect(screen.getByTestId('restore-slider-challenge').querySelectorAll('img')).toHaveLength(2);expect(screen.getByTestId('restore-top').getAttribute('style')).toBeNull();expect(screen.getByTestId('restore-bottom').style.getPropertyValue('--captcha-offset')).toBe('-20%')});
  it.each([
    {initial:-30,slider:10000},
    {initial:30,slider:0},
    {initial:-15,slider:7500},
    {initial:15,slider:2500},
  ])('can restore an initial offset of $initial percent to zero',({initial,slider})=>{const onComplete=vi.fn();render(<RestoreSliderChallenge challenge={{image:'/portrait.jpg',initialOffsetPercent:initial,maxOffsetPercent:30}} onComplete={onComplete}/>);const input=screen.getByRole('slider');fireEvent.change(input,{target:{value:String(slider)}});fireEvent.pointerUp(input,{pointerId:5});expect(onComplete).toHaveBeenCalledWith(expect.objectContaining({offset:0,durationMs:expect.any(Number)}))});
  it('supports keyboard completion for accessibility',()=>{const onComplete=vi.fn();render(<RestoreSliderChallenge challenge={{image:'/portrait.jpg'}} onComplete={onComplete}/>);const slider=screen.getByRole('slider');fireEvent.change(slider,{target:{value:'5000'}});fireEvent.keyUp(slider,{key:'ArrowRight'});expect(onComplete).toHaveBeenCalledTimes(1)});
});
