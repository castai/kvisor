package grpczstd

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/encoding/gzip"
)

func TestCompressDecompress(t *testing.T) {
	r := require.New(t)

	testCases := []struct {
		name        string
		input       string
		expectedErr bool
	}{
		{
			name:  "empty string",
			input: "",
		},
		{
			name:  "short string",
			input: "hello",
		},
		{
			name:  "long string",
			input: strings.Repeat("hello", 1000),
		},
		{
			name:  "string with special characters",
			input: "hello world!@#$%^&*()_+=-`~[]{}|;':\",./<>?",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			c := encoding.GetCompressor(Name)
			// Compress
			var compressed bytes.Buffer
			wc, err := c.Compress(&compressed)
			r.NoError(err)

			_, err = wc.Write([]byte(tc.input))
			r.NoError(err)

			err = wc.Close()
			r.NoError(err)

			// Decompress
			reader, err := c.Decompress(&compressed)
			if tc.expectedErr {
				r.Error(err)
				return
			}

			r.NoError(err)

			decompressed, err := io.ReadAll(reader)
			r.NoError(err)

			// Verify
			r.Equal(tc.input, string(decompressed))
		})
	}
}

var (
	shortString   = "hello"
	longString    = strings.Repeat("hello", 1000)
	complexString = "hello world!@#$%^&*()_+=-`~[]\\{}|;':\",./<>?"
)

func benchmarkCompressDecompress(b *testing.B, compressorName string, data string) {
	var comp encoding.Compressor
	if compressorName == Name {
		comp = encoding.GetCompressor(Name)
	} else if compressorName == gzip.Name {
		comp = encoding.GetCompressor(gzip.Name)
	} else {
		b.Fatalf("unknown compressor: %s", compressorName)
	}

	b.ResetTimer()
	b.Run(compressorName, func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			// Compress
			var compressed bytes.Buffer
			wc, err := comp.Compress(&compressed)
			if err != nil {
				b.Fatalf("compress error: %v", err)
			}
			_, err = wc.Write([]byte(data))
			if err != nil {
				b.Fatalf("write error: %v", err)
			}
			err = wc.Close()
			if err != nil {
				b.Fatalf("close error: %v", err)
			}

			// Decompress
			reader, err := comp.Decompress(&compressed)
			if err != nil {
				b.Fatalf("decompress error: %v", err)
			}

			decompressed, err := io.ReadAll(reader)
			if err != nil {
				b.Fatalf("read all error: %v", err)
			}

			// Verify
			if string(decompressed) != data {
				b.Fatalf("decompressed data does not match original")
			}
		}
	})
}

func BenchmarkCompressDecompress(b *testing.B) {
	b.Run("Zstd_Short", func(b *testing.B) {
		benchmarkCompressDecompress(b, Name, shortString)
	})
	b.Run("Gzip_Short", func(b *testing.B) {
		benchmarkCompressDecompress(b, gzip.Name, shortString)
	})
	b.Run("Zstd_Long", func(b *testing.B) {
		benchmarkCompressDecompress(b, Name, longString)
	})
	b.Run("Gzip_Long", func(b *testing.B) {
		benchmarkCompressDecompress(b, gzip.Name, longString)
	})
	b.Run("Zstd_Complex", func(b *testing.B) {
		benchmarkCompressDecompress(b, Name, complexString)
	})
	b.Run("Gzip_Complex", func(b *testing.B) {
		benchmarkCompressDecompress(b, gzip.Name, complexString)
	})
}
