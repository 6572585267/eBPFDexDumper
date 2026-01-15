//go:build arm64

package main

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
)

func TestMethodSigCacheKeyNoCollision(t *testing.T) {
	beginA := uint64(0x1111111122223333)
	beginB := uint64(0x9999999922223333)
	methodIdx := uint32(42)

	keyA := methodSigCacheKey(beginA, methodIdx)
	keyB := methodSigCacheKey(beginB, methodIdx)

	if keyA == keyB {
		t.Fatalf("expected distinct keys for different begin values: %+v vs %+v", keyA, keyB)
	}
}

func TestProcessMethodEventSkipsOversizeBytecode(t *testing.T) {
	dumper := &DexDumper{recordBuffers: sync.Map{}}

	header := methodEventHeader{
		Begin:        0x1000,
		MethodIndex:  1,
		CodeitemSize: maxMethodBytecodeSize + 1,
	}

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, &header); err != nil {
		t.Fatalf("write header: %v", err)
	}

	dumper.processMethodEvent(buf.Bytes())

	var found bool
	dumper.recordBuffers.Range(func(_, _ any) bool {
		found = true
		return false
	})
	if found {
		t.Fatalf("expected no records for oversized bytecode")
	}
}
