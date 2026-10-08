package buf_test

import (
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

// BenchmarkReaderOwner isolates cursor construction and consumption overhead.
// The one-byte in-memory reader is not a readv or network throughput test.
func BenchmarkReaderOwner(b *testing.B) {
	for _, mode := range []string{"off", "on"} {
		for _, lifetime := range []string{"construct", "steady"} {
			b.Run(mode+"/"+lifetime, func(b *testing.B) {
				receipt := new(inspectionReceipt)
				makeReader := func() buf.Reader {
					if mode == "on" {
						return buf.NewInspectionReader(inspectionRepeatedReader{}, receipt, func() {})
					}
					return &buf.TimeoutWrapperReader{Reader: inspectionRepeatedReader{}}
				}
				reader := makeReader()
				finish := func(r buf.Reader) {
					if closer, ok := r.(interface{ Interrupt() }); ok {
						closer.Interrupt()
					}
				}
				defer finish(reader)
				b.ReportAllocs()
				b.SetBytes(1)
				for b.Loop() {
					if lifetime == "construct" {
						reader = makeReader()
					}
					mb, err := reader.ReadMultiBuffer()
					if err != nil || mb.Len() != 1 {
						b.Fatalf("read: %d %v", mb.Len(), err)
					}
					buf.ReleaseMulti(mb)
					if lifetime == "construct" {
						finish(reader)
					}
				}
				if mode == "on" && receipt.up.Load() != uint64(b.N) {
					b.Fatal("reader lost or duplicated byte credit")
				}
			})
		}
	}
}
