package proxy

import (
	"encoding/binary"
	"testing"
)

func TestWebSocketFrameLengthEncodings(t *testing.T) {
	tunnel := &webSocketFrameTunnel{limit: 1 << 20}
	sixteen := func(opcode byte, n uint16) []byte {
		raw := []byte{0x80 | opcode, 126, 0, 0}
		binary.BigEndian.PutUint16(raw[2:], n)
		return raw
	}
	sixtyFour := func(opcode byte, n uint64) []byte {
		raw := []byte{0x80 | opcode, 127, 0, 0, 0, 0, 0, 0, 0, 0}
		binary.BigEndian.PutUint64(raw[2:], n)
		return raw
	}
	tests := []struct {
		name    string
		frame   []byte
		want    int
		wantErr bool
	}{
		{name: "7-bit", frame: []byte{0x81, 125}, want: 2 + 125},
		{name: "16-bit lower bound", frame: sixteen(0x2, 126), want: 4 + 126},
		{name: "16-bit 127 is canonical", frame: sixteen(0x2, 127), want: 4 + 127},
		{name: "16-bit below 126", frame: sixteen(0x2, 125), wantErr: true},
		{name: "64-bit lower bound", frame: sixtyFour(0x2, 65536), want: 10 + 65536},
		{name: "64-bit below 65536", frame: sixtyFour(0x2, 65535), wantErr: true},
		{name: "64-bit high bit", frame: []byte{0x82, 127, 0x80, 0, 0, 0, 0, 1, 0, 0}, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tunnel.frameLength(tc.frame, false)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("frameLength(%x) = %d, want error", tc.frame, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("frameLength(%x): %v", tc.frame, err)
			}
			if got != tc.want {
				t.Fatalf("frameLength(%x) = %d, want %d", tc.frame, got, tc.want)
			}
		})
	}
}
