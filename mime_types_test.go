package main

import (
	"mime"
	"testing"
)

func BenchmarkMimeTypeByExtensionStd(b *testing.B) {
	RegisterMimeTypes()
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = mime.TypeByExtension(".JPG")
		}
	})
}

func BenchmarkMimeTypeByExtensionLiner(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = GetMimeTypeByExtension(".JPG")
		}
	})
}
