/**
 * Shared threat colour + shape palette for every attack-map view
 * (MapLibre world fill, MapLibre point markers, Three.js globe texture,
 * SVG fallback, and the CSS legend tokens).
 *
 * Fixed values so the 2D and 3D views render the same risk language and so
 * the legend can remain colour-blind readable: each level is also carried by
 * a distinct shape glyph (low=circle, medium=diamond, high=triangle,
 * critical=star) plus its text label.
 */
import type { ThreatLevel } from './attackMapData';

export const threatLevels: ThreatLevel[] = ['low', 'medium', 'high', 'critical'];

export const threatPaletteHex: Record<ThreatLevel, string> = {
  low: '#2176d2',
  medium: '#d98912',
  high: '#f97316',
  critical: '#dd3b3b',
};

export const threatPaletteNeutralHex = '#94a3b8';

/** Same palette as RGB ints for the Three.js globe materials. */
export const threatPaletteRgb: Record<ThreatLevel, number> = {
  low: 0x2176d2,
  medium: 0xd98912,
  high: 0xf97316,
  critical: 0xdd3b3b,
};

/** Human-readable glyph substitute– text that carries the level independent of colour. */
export const threatShapeLabel: Record<ThreatLevel, string> = {
  low: '\u25cf', // ●
  medium: '\u25c6', // ◆
  high: '\u25b2', // ▲
  critical: '\u2605', // ★
};

/** CSS class for the legend marker shape. */
export const threatShapeClass: Record<ThreatLevel, string> = {
  low: 'circle',
  medium: 'diamond',
  high: 'triangle',
  critical: 'star',
};

/** Accessible shape description used as the marker's accessible name when needed. */
export const threatShapeAria: Record<ThreatLevel, string> = {
  low: 'circle',
  medium: 'diamond',
  high: 'triangle',
  critical: 'star',
};
