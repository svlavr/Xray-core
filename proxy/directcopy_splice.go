package proxy

const directCopySpliceQuantum = 1 << 20

type directCopyProgress interface {
	Progress(uint64)
}
