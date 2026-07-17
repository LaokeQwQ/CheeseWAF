package imageengine

import (
	"errors"
	"image"
	"image/color"
	"image/draw"
	"math"
)

type ShapeKind string

const (
	ShapePuzzle    ShapeKind = "puzzle"
	ShapeCircle    ShapeKind = "circle"
	ShapeTriangle  ShapeKind = "triangle"
	ShapeSquare    ShapeKind = "square"
	ShapeDiamond   ShapeKind = "diamond"
	ShapeTrapezoid ShapeKind = "trapezoid"
	ShapeShield    ShapeKind = "shield"
)

type ShapeMask struct {
	Kind    ShapeKind
	Alpha   *image.Alpha
	Padding int
}

func NewShapeMask(kind ShapeKind, size, padding int, limits Limits) (*ShapeMask, error) {
	limits = limits.normalized()
	if err := limits.validateDimensions(size, size); err != nil {
		return nil, err
	}
	if padding < 2 || padding*2 >= size-8 {
		return nil, errors.New("imageengine: invalid shape padding")
	}
	if !validShapeKind(kind) {
		return nil, errors.New("imageengine: unsupported shape")
	}
	mask := image.NewAlpha(image.Rect(0, 0, size, size))
	inner := float64(size - 2*padding)
	const samples = 4
	for y := padding; y < size-padding; y++ {
		for x := padding; x < size-padding; x++ {
			covered := 0
			for sy := 0; sy < samples; sy++ {
				for sx := 0; sx < samples; sx++ {
					u := (float64(x-padding) + (float64(sx)+0.5)/samples) / inner
					v := (float64(y-padding) + (float64(sy)+0.5)/samples) / inner
					if containsShape(kind, u, v) {
						covered++
					}
				}
			}
			if covered > 0 {
				mask.SetAlpha(x, y, color.Alpha{A: uint8(covered * 255 / (samples * samples))})
			}
		}
	}
	return &ShapeMask{Kind: kind, Alpha: mask, Padding: padding}, nil
}

func validShapeKind(kind ShapeKind) bool {
	switch kind {
	case ShapePuzzle, ShapeCircle, ShapeTriangle, ShapeSquare, ShapeDiamond, ShapeTrapezoid, ShapeShield:
		return true
	}
	return false
}

func containsShape(kind ShapeKind, x, y float64) bool {
	switch kind {
	case ShapeCircle:
		dx, dy := x-.5, y-.5
		return dx*dx+dy*dy <= .48*.48
	case ShapeTriangle:
		return pointInPolygon(x, y, [][2]float64{{.5, .03}, {.97, .94}, {.03, .94}})
	case ShapeSquare:
		return x >= .04 && x <= .96 && y >= .04 && y <= .96
	case ShapeDiamond:
		return math.Abs(x-.5)+math.Abs(y-.5) <= .47
	case ShapeTrapezoid:
		return pointInPolygon(x, y, [][2]float64{{.24, .05}, {.76, .05}, {.97, .94}, {.03, .94}})
	case ShapeShield:
		return pointInPolygon(x, y, [][2]float64{{.5, .03}, {.92, .18}, {.87, .63}, {.72, .84}, {.5, .97}, {.28, .84}, {.13, .63}, {.08, .18}})
	case ShapePuzzle:
		inside := x >= .16 && x <= .84 && y >= .16 && y <= .84
		topTab := circleContains(x, y, .5, .16, .17)
		rightTab := circleContains(x, y, .84, .5, .17)
		leftNotch := circleContains(x, y, .16, .5, .115)
		bottomNotch := circleContains(x, y, .5, .84, .115)
		return (inside || topTab || rightTab) && !leftNotch && !bottomNotch
	default:
		return false
	}
}

func circleContains(x, y, cx, cy, r float64) bool { dx, dy := x-cx, y-cy; return dx*dx+dy*dy <= r*r }

func pointInPolygon(x, y float64, points [][2]float64) bool {
	inside := false
	for i, j := 0, len(points)-1; i < len(points); j, i = i, i+1 {
		xi, yi := points[i][0], points[i][1]
		xj, yj := points[j][0], points[j][1]
		if (yi > y) != (yj > y) && x < (xj-xi)*(y-yi)/(yj-yi)+xi {
			inside = !inside
		}
	}
	return inside
}

func ExtractPiece(src image.Image, at image.Point, mask *ShapeMask) (*image.RGBA, error) {
	if src == nil || mask == nil || mask.Alpha == nil {
		return nil, ErrInvalidImage
	}
	size := mask.Alpha.Bounds().Size()
	sourceRect := image.Rectangle{Min: at, Max: at.Add(size)}
	if !sourceRect.In(src.Bounds()) {
		return nil, errors.New("imageengine: piece source outside image")
	}
	dst := image.NewRGBA(image.Rectangle{Max: size})
	draw.DrawMask(dst, dst.Bounds(), src, at, mask.Alpha, mask.Alpha.Bounds().Min, draw.Src)
	return dst, nil
}

func DrawSlot(dst *image.RGBA, at image.Point, mask *ShapeMask, fill, stroke color.Color, strokeWidth int) error {
	if dst == nil || mask == nil || mask.Alpha == nil || fill == nil || stroke == nil {
		return ErrInvalidImage
	}
	if strokeWidth < 1 || strokeWidth > mask.Padding {
		return errors.New("imageengine: invalid slot stroke width")
	}
	b := mask.Alpha.Bounds()
	for y := b.Min.Y - strokeWidth; y < b.Max.Y+strokeWidth; y++ {
		for x := b.Min.X - strokeWidth; x < b.Max.X+strokeWidth; x++ {
			target := image.Pt(at.X+x-b.Min.X, at.Y+y-b.Min.Y)
			if !target.In(dst.Bounds()) {
				continue
			}
			a := alphaAt(mask.Alpha, x, y)
			if a > 0 {
				blendPixel(dst, target.X, target.Y, withAlpha(fill, a))
				continue
			}
			if nearMask(mask.Alpha, x, y, strokeWidth) {
				blendPixel(dst, target.X, target.Y, color.RGBAModel.Convert(stroke).(color.RGBA))
			}
		}
	}
	return nil
}

func nearMask(mask *image.Alpha, x, y, radius int) bool {
	for oy := -radius; oy <= radius; oy++ {
		for ox := -radius; ox <= radius; ox++ {
			if ox*ox+oy*oy <= radius*radius && alphaAt(mask, x+ox, y+oy) > 0 {
				return true
			}
		}
	}
	return false
}
func alphaAt(mask *image.Alpha, x, y int) uint8 {
	if !image.Pt(x, y).In(mask.Bounds()) {
		return 0
	}
	return mask.AlphaAt(x, y).A
}
func withAlpha(value color.Color, alpha uint8) color.RGBA {
	c := color.RGBAModel.Convert(value).(color.RGBA)
	c.A = uint8(uint16(c.A) * uint16(alpha) / 255)
	return c
}
