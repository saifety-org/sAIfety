// Package extract pulls model-visible text out of non-text files. A
// multimodal agent reads images, so an instruction hidden in PNG metadata,
// a JPEG comment or an SVG <text> element reaches it as surely as a line in
// README.md. Only metadata and embedded text are parsed here; pixels go
// through an optional OCR engine (see ocr.go).
package extract

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"io"
	"regexp"
	"strings"
)

// MaxText caps the extracted text size per file.
const MaxText = 1 << 20

var imageExt = map[string]bool{".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".svg": true}

// IsImage reports whether ext (lowercase, with dot) is a supported image type.
func IsImage(ext string) bool { return imageExt[ext] }

// ImageText returns human-readable text embedded in an image file: metadata
// chunks, comments, XMP/EXIF strings. SVG is returned as-is because it is
// XML and the text scanner handles it. ok is false when nothing was found.
func ImageText(name string, data []byte) (text string, ok bool) {
	var out string
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		out = pngText(data)
	case bytes.HasPrefix(data, []byte{0xff, 0xd8}):
		out = jpegText(data)
	case bytes.HasPrefix(data, []byte("GIF8")):
		out = gifText(data)
	case bytes.HasPrefix(data, []byte("RIFF")) && len(data) > 12 && string(data[8:12]) == "WEBP":
		out = webpText(data)
	case strings.HasSuffix(strings.ToLower(name), ".svg") || bytes.Contains(data[:min(len(data), 512)], []byte("<svg")):
		out = string(data)
	}
	if len(out) > MaxText {
		out = out[:MaxText]
	}
	return out, strings.TrimSpace(out) != ""
}

// pngText reads tEXt, zTXt and iTXt chunks.
func pngText(data []byte) string {
	var b strings.Builder
	pos := 8
	for pos+8 <= len(data) {
		length := int(binary.BigEndian.Uint32(data[pos:]))
		typ := string(data[pos+4 : pos+8])
		start := pos + 8
		end := start + length
		if length < 0 || end > len(data) {
			break
		}
		chunk := data[start:end]
		switch typ {
		case "tEXt":
			if k, v, ok := bytes.Cut(chunk, []byte{0}); ok {
				b.WriteString(string(k) + ": " + string(v) + "\n")
			}
		case "zTXt":
			if k, rest, ok := bytes.Cut(chunk, []byte{0}); ok && len(rest) > 1 {
				if v, err := inflate(rest[1:]); err == nil {
					b.WriteString(string(k) + ": " + string(v) + "\n")
				}
			}
		case "iTXt":
			// keyword\0 compflag compmethod lang\0 translated\0 text
			k, rest, ok := bytes.Cut(chunk, []byte{0})
			if !ok || len(rest) < 2 {
				break
			}
			compressed := rest[0] == 1
			rest = rest[2:]
			_, rest, ok = bytes.Cut(rest, []byte{0}) // language tag
			if !ok {
				break
			}
			_, rest, ok = bytes.Cut(rest, []byte{0}) // translated keyword
			if !ok {
				break
			}
			v := rest
			if compressed {
				if d, err := inflate(rest); err == nil {
					v = d
				} else {
					break
				}
			}
			b.WriteString(string(k) + ": " + string(v) + "\n")
		case "IEND":
			return b.String()
		}
		pos = end + 4 // skip CRC
	}
	return b.String()
}

// jpegText reads COM segments and printable strings from APPn metadata
// (EXIF, XMP, IPTC) without a full TIFF parse.
func jpegText(data []byte) string {
	var b strings.Builder
	pos := 2
	for pos+4 <= len(data) {
		if data[pos] != 0xff {
			pos++
			continue
		}
		marker := data[pos+1]
		if marker == 0xd8 || marker == 0x01 || (marker >= 0xd0 && marker <= 0xd7) {
			pos += 2
			continue
		}
		if marker == 0xda || marker == 0xd9 { // start of scan / end: metadata is before this
			break
		}
		length := int(binary.BigEndian.Uint16(data[pos+2:]))
		if length < 2 || pos+2+length > len(data) {
			break
		}
		seg := data[pos+4 : pos+2+length]
		switch {
		case marker == 0xfe: // COM
			b.WriteString("comment: " + string(seg) + "\n")
		case marker >= 0xe0 && marker <= 0xef: // APPn
			for _, s := range printableStrings(seg, 8) {
				b.WriteString(s + "\n")
			}
		}
		pos += 2 + length
	}
	return b.String()
}

// gifText reads comment extension blocks.
func gifText(data []byte) string {
	var b strings.Builder
	for i := 0; i+2 < len(data); i++ {
		if data[i] == 0x21 && data[i+1] == 0xfe {
			j := i + 2
			for j < len(data) {
				n := int(data[j])
				if n == 0 {
					break
				}
				if j+1+n > len(data) {
					break
				}
				b.Write(data[j+1 : j+1+n])
				j += 1 + n
			}
			b.WriteString("\n")
			i = j
		}
	}
	return b.String()
}

// webpText reads EXIF and XMP RIFF chunks.
func webpText(data []byte) string {
	var b strings.Builder
	pos := 12
	for pos+8 <= len(data) {
		fourcc := string(data[pos : pos+4])
		size := int(binary.LittleEndian.Uint32(data[pos+4:]))
		start := pos + 8
		end := start + size
		if size < 0 || end > len(data) {
			break
		}
		if fourcc == "EXIF" || fourcc == "XMP " {
			for _, s := range printableStrings(data[start:end], 8) {
				b.WriteString(s + "\n")
			}
		}
		pos = end + size%2
	}
	return b.String()
}

func inflate(b []byte) ([]byte, error) {
	r, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(io.LimitReader(r, MaxText))
}

var rePrintable = regexp.MustCompile(`[\x20-\x7e\t]+`)

// printableStrings returns ASCII runs of at least minLen bytes, plus any
// valid UTF-8 text between them is ignored on purpose: EXIF strings are
// ASCII, XMP is XML which is ASCII-heavy.
func printableStrings(b []byte, minLen int) []string {
	var out []string
	for _, m := range rePrintable.FindAll(b, -1) {
		if len(m) >= minLen {
			out = append(out, string(m))
		}
	}
	return out
}
