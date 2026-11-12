package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"math/bits"
	"os"
	"sync"
)

// A map's preview is the image its .scmap embeds right after the file's header. The header (version 2, every map the
// game and the vault ship) is:
//
//	"Map\x1a", int32 2, uint32 0xBEEFFEED, int32 2, float32 width, float32 height, int32 0, int16 0,
//	int32 length, then `length` bytes of a DDS file
//
// (little-endian). On every map checked (127, the game's and the vault's) the DDS is 256x256 uncompressed A8R8G8B8
// (BGRA bytes); DXT1/3/5 are read too, as DDS allows them.

const (
	scmapPreviewOffset = 30 // the int32 length; the DDS follows it
	ddsHeaderSize      = 128
	maxPreviewBytes    = 64 << 20
	maxPreviewSide     = 4096
)

var errNoPreview = errors.New("no preview image in the map file")

// scmapPreviewDDS reads the DDS bytes embedded in a .scmap.
func scmapPreviewDDS(r io.ReaderAt) ([]byte, error) {
	head := make([]byte, scmapPreviewOffset+4)
	if _, err := r.ReadAt(head, 0); err != nil {
		return nil, errNoPreview
	}
	if string(head[:4]) != "Map\x1a" {
		return nil, errors.New("not a .scmap file")
	}
	n := binary.LittleEndian.Uint32(head[scmapPreviewOffset:])
	if n < ddsHeaderSize || n > maxPreviewBytes {
		return nil, errNoPreview
	}
	dds := make([]byte, n)
	if _, err := r.ReadAt(dds, scmapPreviewOffset+4); err != nil {
		return nil, fmt.Errorf("the preview is cut short: %w", err)
	}
	return dds, nil
}

// scmapHasPreview checks a .scmap's preview header without reading its pixels.
func scmapHasPreview(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, scmapPreviewOffset+4+ddsHeaderSize)
	if _, err := f.ReadAt(head, 0); err != nil || string(head[:4]) != "Map\x1a" {
		return false
	}
	n := binary.LittleEndian.Uint32(head[scmapPreviewOffset:])
	if n < ddsHeaderSize || n > maxPreviewBytes {
		return false
	}
	_, _, _, err = ddsLayout(head[scmapPreviewOffset+4:])
	return err == nil
}

type ddsFormat struct {
	fourCC                 string // DXT1, DXT3, DXT5, or "" for uncompressed
	bitCount               int
	rMask, gMask, bMask, a uint32
}

// ddsLayout reads a DDS header: width, height and the pixel format.
func ddsLayout(dds []byte) (w, h int, f ddsFormat, err error) {
	if len(dds) < ddsHeaderSize || string(dds[:4]) != "DDS " {
		return 0, 0, f, errors.New("not a DDS image")
	}
	le := binary.LittleEndian
	h = int(le.Uint32(dds[12:]))
	w = int(le.Uint32(dds[16:]))
	if w < 1 || h < 1 || w > maxPreviewSide || h > maxPreviewSide {
		return 0, 0, f, fmt.Errorf("DDS size %dx%d", w, h)
	}
	pf := dds[76:108]
	flags := le.Uint32(pf[4:])
	switch {
	case flags&0x4 != 0: // DDPF_FOURCC
		f.fourCC = string(pf[8:12])
		if f.fourCC != "DXT1" && f.fourCC != "DXT3" && f.fourCC != "DXT5" {
			return 0, 0, f, fmt.Errorf("DDS format %q", f.fourCC)
		}
	case flags&0x40 != 0: // DDPF_RGB
		f.bitCount = int(le.Uint32(pf[12:]))
		f.rMask, f.gMask, f.bMask = le.Uint32(pf[16:]), le.Uint32(pf[20:]), le.Uint32(pf[24:])
		if flags&0x1 != 0 { // DDPF_ALPHAPIXELS
			f.a = le.Uint32(pf[28:])
		}
		if f.bitCount != 16 && f.bitCount != 24 && f.bitCount != 32 {
			return 0, 0, f, fmt.Errorf("DDS with %d bits a pixel", f.bitCount)
		}
	default:
		return 0, 0, f, errors.New("DDS pixel format neither RGB nor DXT")
	}
	return w, h, f, nil
}

// decodeDDS decodes a DDS image's first level. The preview is drawn opaque: the alpha some maps carry isn't a
// transparency the lobby shows.
func decodeDDS(dds []byte) (*image.NRGBA, error) {
	w, h, f, err := ddsLayout(dds)
	if err != nil {
		return nil, err
	}
	data := dds[ddsHeaderSize:]
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	if f.fourCC != "" {
		return img, decodeDXT(img, data, f.fourCC)
	}
	bpp := f.bitCount / 8
	if len(data) < w*h*bpp {
		return nil, fmt.Errorf("DDS data %d bytes for %dx%d at %d bits", len(data), w, h, f.bitCount)
	}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			off := (y*w + x) * bpp
			var v uint32
			for i := 0; i < bpp; i++ {
				v |= uint32(data[off+i]) << (8 * i)
			}
			img.SetNRGBA(x, y, color.NRGBA{maskByte(v, f.rMask), maskByte(v, f.gMask), maskByte(v, f.bMask), 255})
		}
	}
	return img, nil
}

// maskByte is the channel under mask, scaled to 0..255.
func maskByte(v, mask uint32) uint8 {
	if mask == 0 {
		return 0
	}
	shift := bits.TrailingZeros32(mask)
	width := bits.OnesCount32(mask)
	c := (v & mask) >> shift
	max := uint32(1)<<width - 1
	return uint8((c*255 + max/2) / max)
}

func rgb565(c uint16) [3]uint8 {
	r := uint32(c>>11) & 31
	g := uint32(c>>5) & 63
	b := uint32(c) & 31
	return [3]uint8{uint8((r*255 + 15) / 31), uint8((g*255 + 31) / 63), uint8((b*255 + 15) / 31)}
}

// decodeDXT decodes DXT1/3/5 blocks (4x4 pixels each) into img; the alpha blocks are skipped (drawn opaque).
func decodeDXT(img *image.NRGBA, data []byte, fourCC string) error {
	w, h := img.Rect.Dx(), img.Rect.Dy()
	blockBytes := 16
	if fourCC == "DXT1" {
		blockBytes = 8
	}
	bw, bh := (w+3)/4, (h+3)/4
	if len(data) < bw*bh*blockBytes {
		return fmt.Errorf("%s data %d bytes for %dx%d", fourCC, len(data), w, h)
	}
	le := binary.LittleEndian
	for by := 0; by < bh; by++ {
		for bx := 0; bx < bw; bx++ {
			block := data[(by*bw+bx)*blockBytes:]
			if blockBytes == 16 {
				block = block[8:] // the colour half follows the alpha half
			}
			c0, c1 := le.Uint16(block[0:]), le.Uint16(block[2:])
			p0, p1 := rgb565(c0), rgb565(c1)
			var pal [4][3]uint8
			pal[0], pal[1] = p0, p1
			for i := 0; i < 3; i++ {
				a, b := uint16(p0[i]), uint16(p1[i])
				if c0 > c1 || fourCC != "DXT1" {
					pal[2][i] = uint8((2*a + b) / 3)
					pal[3][i] = uint8((a + 2*b) / 3)
				} else {
					pal[2][i] = uint8((a + b) / 2)
					pal[3][i] = 0
				}
			}
			idx := le.Uint32(block[4:])
			for py := 0; py < 4; py++ {
				for px := 0; px < 4; px++ {
					x, y := bx*4+px, by*4+py
					if x >= w || y >= h {
						continue
					}
					c := pal[(idx>>(2*(py*4+px)))&3]
					img.SetNRGBA(x, y, color.NRGBA{c[0], c[1], c[2], 255})
				}
			}
		}
	}
	return nil
}

// previewCache keeps each map's preview as PNG, by the .scmap's path and stamp.
type previewCache struct {
	mu      sync.Mutex
	entries map[string]previewEntry
}

type previewEntry struct {
	stamp string
	png   []byte
	err   error
}

// maxCachedPreviews bounds the cache (a 256x256 preview is about 100 KB of PNG).
const maxCachedPreviews = 512

func (c *previewCache) get(scmapPath string) ([]byte, error) {
	if scmapPath == "" {
		return nil, errNoPreview
	}
	stamp := fileStamp(scmapPath)
	c.mu.Lock()
	if e, ok := c.entries[scmapPath]; ok && e.stamp == stamp {
		c.mu.Unlock()
		return e.png, e.err
	}
	c.mu.Unlock()
	out, err := previewPNG(scmapPath)
	c.mu.Lock()
	if c.entries == nil || len(c.entries) >= maxCachedPreviews {
		c.entries = map[string]previewEntry{}
	}
	c.entries[scmapPath] = previewEntry{stamp: stamp, png: out, err: err}
	c.mu.Unlock()
	return out, err
}

// previewPNG reads a .scmap's preview and encodes it as PNG.
func previewPNG(scmapPath string) ([]byte, error) {
	f, err := os.Open(scmapPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dds, err := scmapPreviewDDS(f)
	if err != nil {
		return nil, err
	}
	img, err := decodeDDS(dds)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
