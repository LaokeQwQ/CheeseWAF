import type { CSSProperties, PointerEvent as ReactPointerEvent } from 'react';
import { useRef, useState } from 'react';
import { MoveRight } from 'lucide-react';
import { appendTrack, trackPoint } from '../interaction';
import type { CaptchaPoint, CaptchaTrackPoint } from '../protocol';
import styles from './ChallengeSlider.module.css';

export interface RestoreSliderChallengeData { image:string; width?:number; height?:number; movingPart?:'top'|'bottom'; maxOffsetPercent?:number; initialOffsetPercent?:number }
export interface RestoreSliderAnswer { offset:number; point:CaptchaPoint; track:CaptchaTrackPoint[]; durationMs:number }
export interface RestoreSliderChallengeProps { challenge:RestoreSliderChallengeData; disabled?:boolean; label?:string; onChange?:(answer:RestoreSliderAnswer)=>void; onComplete:(answer:RestoreSliderAnswer)=>void }
const elapsed=(start:number)=>Math.max(0,Math.round(performance.now()-start));
export const restoreOffsetForSlider=(initial:number,max:number,value:number)=>initial+((value-5000)/5000)*max;

export function RestoreSliderChallenge({challenge,disabled,label='拖动滑块拼合上下图片',onChange,onComplete}:RestoreSliderChallengeProps){
  const [value,setValue]=useState(5000); const started=useRef(performance.now()); const pointer=useRef<number>(); const operation=useRef<CaptchaTrackPoint[]>([]);
  const moving=challenge.movingPart??'top'; const max=challenge.maxOffsetPercent??32; const initial=challenge.initialOffsetPercent??-max;
  const offset=restoreOffsetForSlider(initial,max,value); const answer=():RestoreSliderAnswer=>{const durationMs=elapsed(started.current);const point={x:value,y:5000};return{offset:Math.round(offset*100)/100,point,track:appendTrack(operation.current,trackPoint(point,durationMs,'up')),durationMs}};
  const width=challenge.width??320,height=challenge.height??180;
  const finish=(event?:ReactPointerEvent<HTMLInputElement>)=>{if(event&&pointer.current!==undefined&&pointer.current!==event.pointerId)return;pointer.current=undefined;const result=answer();operation.current=[];onComplete(result)};
  const movingStyle={'--captcha-offset':`${offset}%`} as CSSProperties;
  return <div className={styles.challenge} data-testid="restore-slider-challenge">
    <div className={`${styles.stage} ${styles.restoreStage}`} style={{aspectRatio:`${width} / ${height}`}}>
      <div className={styles.restoreHalf}><img className={`${styles.restoreImage} ${styles.restoreTop} ${moving==='top'?'':styles.restoreFixed}`} data-testid="restore-top" style={moving==='top'?movingStyle:undefined} src={challenge.image} alt="" draggable={false}/></div>
      <div className={styles.restoreHalf}><img className={`${styles.restoreImage} ${styles.restoreBottom} ${moving==='bottom'?'':styles.restoreFixed}`} data-testid="restore-bottom" style={moving==='bottom'?movingStyle:undefined} src={challenge.image} alt="" draggable={false}/></div>
      <span className={styles.seam} aria-hidden="true"/>
    </div>
    <div className={styles.controls}><span className={styles.dragIcon} aria-hidden="true"><MoveRight size={25}/></span><input className={styles.range} aria-label={label} type="range" min={0} max={10000} step={1} value={value} disabled={disabled} style={{'--captcha-progress':`${value/100}%`} as CSSProperties} onPointerDown={event=>{pointer.current=event.pointerId;started.current=performance.now();operation.current=[trackPoint({x:value,y:5000},0,'down')];event.currentTarget.setPointerCapture?.(event.pointerId)}} onChange={event=>{const next=Number(event.currentTarget.value);setValue(next);const nextOffset=restoreOffsetForSlider(initial,max,next);const point={x:next,y:5000};operation.current=appendTrack(operation.current,trackPoint(point,elapsed(started.current),'move'));onChange?.({offset:Math.round(nextOffset*100)/100,point,track:operation.current,durationMs:elapsed(started.current)})}} onPointerUp={finish} onPointerCancel={()=>{pointer.current=undefined;operation.current=[]}} onKeyUp={event=>{if(['ArrowLeft','ArrowRight','Home','End','PageUp','PageDown'].includes(event.key))finish()}}/></div>
  </div>
}
