package imageengine

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
)

// RandomSource permits deterministic tests while production uses crypto/rand.
type RandomSource interface {
	Uint64() (uint64, error)
	Read([]byte) (int, error)
}

type CryptoRandom struct{ Reader io.Reader }

func (r CryptoRandom) Uint64() (uint64, error) {
	reader := r.Reader
	if reader == nil {
		reader = rand.Reader
	}
	var data [8]byte
	if _, err := io.ReadFull(reader, data[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data[:]), nil
}

func (r CryptoRandom) Read(dst []byte) (int, error) {
	reader := r.Reader
	if reader == nil {
		reader = rand.Reader
	}
	return io.ReadFull(reader, dst)
}

func RandomInt(rng RandomSource, min, max int) (int, error) {
	if rng == nil {
		return 0, errors.New("imageengine: nil random source")
	}
	if max <= min {
		return 0, errors.New("imageengine: invalid random range")
	}
	span := uint64(max - min)
	limit := uint64(math.MaxUint64) - uint64(math.MaxUint64)%span
	for {
		value, err := rng.Uint64()
		if err != nil {
			return 0, err
		}
		if value < limit {
			return min + int(value%span), nil
		}
	}
}

func RandomFloat64(rng RandomSource) (float64, error) {
	if rng == nil {
		return 0, errors.New("imageengine: nil random source")
	}
	value, err := rng.Uint64()
	if err != nil {
		return 0, err
	}
	return float64(value>>11) / (1 << 53), nil
}
