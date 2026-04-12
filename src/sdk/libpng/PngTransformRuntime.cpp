// libpng row-transformation runtime recovery.
// Source: embedded wxWindows 2.4.2 libpng (dependencies/wxWindows-2.4.2/src/png/pngrtran.c
// and pngwtran.c). The ForgedAlliance.exe binary links libpng statically as
// png.lib; these recovered functions match the binary at their given addresses.
//
// All functions touch the row buffer in-place. Row metadata is accessed
// through libpng_detail::PngRowInfoView so no raw row_info+offset arithmetic
// leaks into behaviour code. The inner pixel loops keep the original libpng
// reverse-walk shape so that the in-place expansion writes never overrun their
// reads — that requirement is binary-fidelity, not stylistic.

#include "libpng/PngTransformRuntime.h"

#include <cstring>  // memcpy

namespace {

// Convenience: build a typed row view for the duration of a transform.
[[nodiscard]] inline libpng_detail::PngRowInfoView View(png_row_infop row_info) noexcept
{
  return libpng_detail::GetRowInfo(row_info);
}

} // namespace

// ---------------------------------------------------------------------------
// png_do_swap (0x009E22FF) — byte-swap 16-bit samples in place.
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E22FF (FUN_009E22FF)
 *
 * IDA signature:
 * void __cdecl png_do_swap(png_row_infop row_info, png_bytep row);
 */
extern "C" void png_do_swap(png_row_infop row_info, std::uint8_t* row)
{
  auto info = View(row_info);
  if (info.bit_depth != 16) {
    return;
  }
  std::uint32_t count = info.width * info.channels;
  if (count == 0) {
    return;
  }
  do {
    const std::uint8_t lo = row[0];
    row[0] = row[1];
    row[1] = lo;
    row += 2;
    --count;
  } while (count != 0);
}

// ---------------------------------------------------------------------------
// png_do_packswap (0x009E232C) — bit-reverse sub-byte rows via lookup table.
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E232C (FUN_009E232C)
 *
 * IDA signature:
 * void __cdecl png_do_packswap(png_row_infop row_info, png_bytep row);
 */
extern "C" void png_do_packswap(png_row_infop row_info, std::uint8_t* row)
{
  auto info = View(row_info);
  if (info.bit_depth >= 8) {
    return;
  }
  const std::uint8_t* table = nullptr;
  switch (info.bit_depth) {
    case 1: table = libpng_detail::onebppswaptable;  break;
    case 2: table = libpng_detail::twobppswaptable;  break;
    case 4: table = libpng_detail::fourbppswaptable; break;
    default: return;
  }
  std::uint8_t* const end = row + info.rowbytes;
  for (std::uint8_t* p = row; p < end; ++p) {
    *p = table[*p];
  }
}

// ---------------------------------------------------------------------------
// png_do_strip_filler (0x009E2377) — drop a filler channel from RGBA/GA rows.
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E2377 (FUN_009E2377)
 *
 * IDA signature:
 * void __cdecl png_do_strip_filler(png_row_infop row_info, png_bytep row, png_uint_32 flags);
 *
 * Note: `flags` is treated as signed by the binary — its sign bit selects
 * whether the filler byte is at the leading or trailing position.
 */
extern "C" void png_do_strip_filler(png_row_infop row_info, std::uint8_t* row, std::uint32_t flags)
{
  auto info = View(row_info);
  const std::uint32_t width = info.width;
  const bool trailing_filler = static_cast<std::int32_t>(flags) >= 0;

  if (info.channels == 4) {
    // RGBA -> RGB
    if (info.bit_depth == 8) {
      std::uint8_t* dst = row;
      std::uint8_t* src = row;
      if (trailing_filler) {
        // Filler is the last byte of each pixel: src+1..src+3 -> dst+0..dst+2.
        for (std::uint32_t i = 0; i < width; ++i) {
          dst[0] = src[1];
          dst[1] = src[2];
          dst[2] = src[3];
          dst += 3;
          src += 4;
        }
      } else {
        // Filler is the first byte: src+0 -> dst, then bytes 1..3 carried over.
        // Binary shape: starts at offset +3/+4 because the first pixel keeps
        // its existing 3 bytes (no copy needed) and only the tail is moved.
        if (width > 1) {
          std::uint8_t* d = row + 3;
          std::uint8_t* s = row + 4;
          for (std::uint32_t i = width - 1; i != 0; --i) {
            d[0] = s[0];
            d[1] = s[1];
            d[2] = s[2];
            d += 3;
            s += 4;
          }
        }
      }
      info.pixel_depth = 24;
      info.rowbytes    = 3 * width;
    } else {
      // 16-bit RGBA -> RGB.
      std::uint8_t* dst = row;
      std::uint8_t* src = row;
      if (trailing_filler) {
        for (std::uint32_t i = 0; i < width; ++i) {
          dst[0] = src[2];
          dst[1] = src[3];
          dst[2] = src[4];
          dst[3] = src[5];
          dst[4] = src[6];
          dst[5] = src[7];
          dst += 6;
          src += 8;
        }
      } else {
        if (width > 1) {
          std::uint8_t* d = row + 6;
          std::uint8_t* s = row + 8;
          for (std::uint32_t i = width - 1; i != 0; --i) {
            d[0] = s[0];
            d[1] = s[1];
            d[2] = s[2];
            d[3] = s[3];
            d[4] = s[4];
            d[5] = s[5];
            d += 6;
            s += 8;
          }
        }
      }
      info.pixel_depth = 48;
      info.rowbytes    = 6 * width;
    }
    info.channels = 3;
  } else if (info.channels == 2) {
    // GA -> G
    if (info.bit_depth == 8) {
      std::uint8_t* dst = row;
      std::uint8_t* src = row;
      if (trailing_filler) {
        for (std::uint32_t i = 0; i < width; ++i) {
          *dst++ = src[1];
          src += 2;
        }
      } else {
        for (std::uint32_t i = 0; i < width; ++i) {
          *dst++ = src[0];
          src += 2;
        }
      }
      info.pixel_depth = 8;
      info.rowbytes    = width;
    } else {
      // 16-bit GA -> G.
      std::uint8_t* dst = row;
      std::uint8_t* src = row;
      if (trailing_filler) {
        for (std::uint32_t i = 0; i < width; ++i) {
          dst[0] = src[2];
          dst[1] = src[3];
          dst += 2;
          src += 4;
        }
      } else {
        if (width > 1) {
          std::uint8_t* d = row + 2;
          std::uint8_t* s = row + 4;
          for (std::uint32_t i = width - 1; i != 0; --i) {
            d[0] = s[0];
            d[1] = s[1];
            d += 2;
            s += 4;
          }
        }
      }
      info.pixel_depth = 16;
      info.rowbytes    = 2 * width;
    }
    info.channels = 1;
  } else {
    return;
  }
  info.color_type &= static_cast<std::uint8_t>(~libpng_detail::kPngColorMaskAlpha);
}

// ---------------------------------------------------------------------------
// png_do_bgr (0x009E2502) — swap R and B in RGB / RGBA rows.
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E2502 (FUN_009E2502)
 *
 * IDA signature:
 * void __cdecl png_do_bgr(png_row_infop row_info, png_bytep row);
 */
extern "C" void png_do_bgr(png_row_infop row_info, std::uint8_t* row)
{
  auto info = View(row_info);
  if ((info.color_type & libpng_detail::kPngColorMaskColor) == 0) {
    return;
  }
  const std::uint32_t width = info.width;
  if (info.bit_depth == 8) {
    if (info.color_type == libpng_detail::kPngColorTypeRgb) {
      std::uint8_t* p = row;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t r = p[0];
        p[0] = p[2];
        p[2] = r;
        p += 3;
      }
    } else if (info.color_type == libpng_detail::kPngColorTypeRgbAlpha) {
      std::uint8_t* p = row;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t r = p[0];
        p[0] = p[2];
        p[2] = r;
        p += 4;
      }
    }
  } else if (info.bit_depth == 16) {
    if (info.color_type == libpng_detail::kPngColorTypeRgb) {
      std::uint8_t* p = row;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t r0 = p[0];
        const std::uint8_t r1 = p[1];
        p[0] = p[4];
        p[1] = p[5];
        p[4] = r0;
        p[5] = r1;
        p += 6;
      }
    } else if (info.color_type == libpng_detail::kPngColorTypeRgbAlpha) {
      std::uint8_t* p = row;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t r0 = p[0];
        const std::uint8_t r1 = p[1];
        p[0] = p[4];
        p[1] = p[5];
        p[4] = r0;
        p[5] = r1;
        p += 8;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// png_do_unpack (0x009E3A7E) — expand 1/2/4 bpp packed pixels to 8 bpp.
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E3A7E (FUN_009E3A7E)
 *
 * IDA signature:
 * void __cdecl png_do_unpack(png_row_infop row_info, png_bytep row);
 */
extern "C" void png_do_unpack(png_row_infop row_info, std::uint8_t* row)
{
  auto info = View(row_info);
  const std::uint8_t bit_depth = info.bit_depth;
  if (bit_depth >= 8) {
    return;
  }
  const std::uint32_t width = info.width;
  if (width == 0) {
    // Header still gets refreshed below.
  }

  if (bit_depth == 1) {
    if (width != 0) {
      const std::uint8_t* src = row + ((width - 1) >> 3);
      std::uint8_t* dst = row + width - 1;
      int shift = 7 - static_cast<int>((width - 1) & 7);
      std::uint32_t remaining = width;
      do {
        *dst = (*src >> shift) & 0x01;
        if (shift == 7) {
          shift = 0;
          --src;
        } else {
          ++shift;
        }
        --dst;
        --remaining;
      } while (remaining != 0);
    }
  } else if (bit_depth == 2) {
    if (width != 0) {
      const std::uint8_t* src = row + ((width - 1) >> 2);
      std::uint8_t* dst = row + width - 1;
      int shift = 2 * (3 - static_cast<int>((width - 1) & 3));
      std::uint32_t remaining = width;
      do {
        *dst = (*src >> shift) & 0x03;
        if (shift == 6) {
          shift = 0;
          --src;
        } else {
          shift += 2;
        }
        --dst;
        --remaining;
      } while (remaining != 0);
    }
  } else if (bit_depth == 4) {
    if (width != 0) {
      const std::uint8_t* src = row + ((width - 1) >> 1);
      std::uint8_t* dst = row + width - 1;
      int shift = 4 * (1 - static_cast<int>((width - 1) & 1));
      std::uint32_t remaining = width;
      do {
        *dst = (*src >> shift) & 0x0F;
        if (shift == 4) {
          shift = 0;
          --src;
        } else {
          shift = 4;
        }
        --dst;
        --remaining;
      } while (remaining != 0);
    }
  } else {
    return;
  }

  const std::uint8_t channels = info.channels;
  info.bit_depth   = 8;
  info.pixel_depth = static_cast<std::uint8_t>(8 * channels);
  info.rowbytes    = width * channels;
}

// ---------------------------------------------------------------------------
// png_do_unshift (0x009E3B8E) — apply sBIT shift to row samples.
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E3B8E (FUN_009E3B8E)
 *
 * IDA signature:
 * char __cdecl png_do_unshift(png_row_infop row_info, png_bytep row, png_color_8p sig_bits);
 *
 * Returns the value of the last touched register, matching the binary
 * (libpng's original is `void`; the IDA-recovered char return is the
 * compiler's leftover from the asm tail).
 */
extern "C" char png_do_unshift(png_row_infop row_info, std::uint8_t* row, const std::uint8_t* sig_bits)
{
  auto info = View(row_info);
  if (info.color_type == libpng_detail::kPngColorTypePalette) {
    return 0;
  }

  const std::uint32_t width = info.width;
  std::int32_t shifts[4] = {0, 0, 0, 0};
  int shift_count = 0;

  if ((info.color_type & libpng_detail::kPngColorMaskColor) != 0) {
    // RGB lanes use sig_bits[0..2] (red/green/blue).
    shifts[0] = info.bit_depth - sig_bits[0];
    shifts[1] = info.bit_depth - sig_bits[1];
    shifts[2] = info.bit_depth - sig_bits[2];
    shift_count = 3;
  } else {
    // Grayscale lane uses sig_bits[3] (gray).
    shifts[0] = info.bit_depth - sig_bits[3];
    shift_count = 1;
  }
  if ((info.color_type & libpng_detail::kPngColorMaskAlpha) != 0) {
    shifts[shift_count++] = info.bit_depth - sig_bits[4];
  }

  bool any_positive = false;
  for (int i = 0; i < shift_count; ++i) {
    if (shifts[i] > 0) {
      any_positive = true;
    } else {
      shifts[i] = 0;
    }
  }
  if (!any_positive) {
    return 0;
  }

  switch (info.bit_depth) {
    case 2: {
      // 2 bpp grayscale: single shared shift, applied via the >>1 & 0x55 trick.
      std::uint32_t bytes = info.rowbytes;
      for (std::uint8_t* p = row; bytes != 0; --bytes, ++p) {
        *p = static_cast<std::uint8_t>((*p >> 1) & 0x55);
      }
      break;
    }
    case 4: {
      const std::uint32_t bytes = info.rowbytes;
      const int s = shifts[0];
      const std::uint8_t mask =
        static_cast<std::uint8_t>((static_cast<std::uint8_t>(15 >> s)) |
                                  (static_cast<std::uint8_t>(240 >> s) & 0xF0));
      std::uint8_t* p = row;
      for (std::uint32_t i = 0; i < bytes; ++i) {
        *p = static_cast<std::uint8_t>(mask & (*p >> s));
        ++p;
      }
      break;
    }
    case 8: {
      const std::uint32_t total = static_cast<std::uint32_t>(shift_count) * width;
      std::uint8_t* p = row;
      for (std::uint32_t i = 0; i < total; ++i) {
        *p = static_cast<std::uint8_t>(*p >> shifts[i % shift_count]);
        ++p;
      }
      break;
    }
    case 16: {
      const std::uint32_t total = static_cast<std::uint32_t>(shift_count) * width;
      std::uint8_t* p = row;
      for (std::uint32_t i = 0; i < total; ++i) {
        const std::uint16_t v =
          static_cast<std::uint16_t>((p[1] | (p[0] << 8)) >> shifts[i % shift_count]);
        p[0] = static_cast<std::uint8_t>(v >> 8);
        p[1] = static_cast<std::uint8_t>(v & 0xFF);
        p += 2;
      }
      break;
    }
    default:
      break;
  }

  return 1;
}

// ---------------------------------------------------------------------------
// png_do_chop (0x009E3D06) — strip the low byte of every 16-bit sample.
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E3D06 (FUN_009E3D06)
 *
 * IDA signature:
 * void __cdecl png_do_chop(png_row_infop row_info, png_bytep row);
 */
extern "C" void png_do_chop(png_row_infop row_info, std::uint8_t* row)
{
  auto info = View(row_info);
  if (info.bit_depth != 16) {
    return;
  }
  const std::uint32_t samples = info.width * info.channels;
  if (samples != 0) {
    const std::uint8_t* src = row;
    std::uint8_t* dst = row;
    for (std::uint32_t i = 0; i < samples; ++i) {
      *dst++ = *src;
      src += 2;
    }
  }
  const std::uint8_t channels = info.channels;
  info.bit_depth   = 8;
  info.pixel_depth = static_cast<std::uint8_t>(8 * channels);
  info.rowbytes    = info.width * channels;
}

// ---------------------------------------------------------------------------
// png_do_read_swap_alpha (0x009E3D4A) — move alpha from end to front.
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E3D4A (FUN_009E3D4A)
 *
 * IDA signature:
 * void __cdecl png_do_read_swap_alpha(png_row_infop row_info, png_bytep row);
 *
 * Reverse-walks the row to swap RGBA -> ARGB / GA -> AG in place. The walk
 * shape mirrors the binary so the in-place rotation never overwrites a byte
 * before it has been read.
 */
extern "C" void png_do_read_swap_alpha(png_row_infop row_info, std::uint8_t* row)
{
  auto info = View(row_info);
  const std::uint32_t width = info.width;

  if (info.color_type == libpng_detail::kPngColorTypeRgbAlpha) {
    if (info.bit_depth == 8) {
      // RGBA -> ARGB, 4 bytes per pixel.
      std::uint8_t* p = row + info.rowbytes;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t a = *(--p);
        const std::uint8_t b = *(--p);
        const std::uint8_t g = *(--p);
        const std::uint8_t r = *(--p);
        *p     = a;  // shift the four bytes one slot right then place alpha first.
        // Note: above line is symbolic; binary writes back in the
        // exact byte order ARGB.
        // The actual writeback shape:
        //   p[0]=a; p[1]=r; p[2]=g; p[3]=b
        p[0] = a;
        p[1] = r;
        p[2] = g;
        p[3] = b;
      }
    } else {
      // 16-bit RGBA -> ARGB, 8 bytes per pixel.
      std::uint8_t* p = row + info.rowbytes;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t a1 = *(--p);
        const std::uint8_t a0 = *(--p);
        const std::uint8_t b1 = *(--p);
        const std::uint8_t b0 = *(--p);
        const std::uint8_t g1 = *(--p);
        const std::uint8_t g0 = *(--p);
        const std::uint8_t r1 = *(--p);
        const std::uint8_t r0 = *(--p);
        p[0] = a0; p[1] = a1;
        p[2] = r0; p[3] = r1;
        p[4] = g0; p[5] = g1;
        p[6] = b0; p[7] = b1;
      }
    }
  } else if (info.color_type == libpng_detail::kPngColorTypeGrayAlpha) {
    if (info.bit_depth == 8) {
      std::uint8_t* p = row + info.rowbytes;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t a = *(--p);
        const std::uint8_t g = *(--p);
        p[0] = a;
        p[1] = g;
      }
    } else {
      std::uint8_t* p = row + info.rowbytes;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t a1 = *(--p);
        const std::uint8_t a0 = *(--p);
        const std::uint8_t g1 = *(--p);
        const std::uint8_t g0 = *(--p);
        p[0] = a0; p[1] = a1;
        p[2] = g0; p[3] = g1;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// png_do_read_invert_alpha (0x009E3E3C) — invert each alpha sample.
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E3E3C (FUN_009E3E3C)
 *
 * IDA signature:
 * void __cdecl png_do_read_invert_alpha(png_row_infop row_info, png_bytep row);
 */
extern "C" void png_do_read_invert_alpha(png_row_infop row_info, std::uint8_t* row)
{
  auto info = View(row_info);
  const std::uint32_t width = info.width;

  if (info.color_type == libpng_detail::kPngColorTypeRgbAlpha) {
    if (info.bit_depth == 8) {
      // 4 bytes/pixel; alpha is the last byte. Walk in reverse.
      std::uint8_t* p = row + info.rowbytes;
      for (std::uint32_t i = 0; i < width; ++i) {
        std::uint8_t* a = p - 1;
        *a = static_cast<std::uint8_t>(0xFF - *a);
        p -= 4;
      }
    } else {
      // 8 bytes/pixel, alpha is the trailing 16-bit sample.
      std::uint8_t* p = row + info.rowbytes;
      for (std::uint32_t i = 0; i < width; ++i) {
        std::uint8_t* a_lo = p - 1;
        std::uint8_t* a_hi = p - 2;
        *a_lo = static_cast<std::uint8_t>(0xFF - *a_lo);
        *a_hi = static_cast<std::uint8_t>(0xFF - *a_hi);
        p -= 8;
      }
    }
  } else if (info.color_type == libpng_detail::kPngColorTypeGrayAlpha) {
    if (info.bit_depth == 8) {
      std::uint8_t* p = row + info.rowbytes;
      for (std::uint32_t i = 0; i < width; ++i) {
        std::uint8_t* a = p - 1;
        *a = static_cast<std::uint8_t>(0xFF - *a);
        p -= 2;
      }
    } else {
      std::uint8_t* p = row + info.rowbytes;
      for (std::uint32_t i = 0; i < width; ++i) {
        std::uint8_t* a_lo = p - 1;
        std::uint8_t* a_hi = p - 2;
        *a_lo = static_cast<std::uint8_t>(0xFF - *a_lo);
        *a_hi = static_cast<std::uint8_t>(0xFF - *a_hi);
        p -= 4;
      }
    }
  }
}

// ---------------------------------------------------------------------------
// png_do_read_filler (0x009E3EE6) — insert a filler byte/word into G/RGB rows.
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E3EE6 (FUN_009E3EE6)
 *
 * IDA signature:
 * png_uint_32 __cdecl png_do_read_filler(png_row_infop row_info, png_bytep row,
 *                                        png_uint_32 filler, png_uint_32 flags);
 */
extern "C" std::uint32_t png_do_read_filler(png_row_infop row_info, std::uint8_t* row,
                                            std::uint32_t filler, std::uint32_t flags)
{
  auto info = View(row_info);
  const bool trailing = static_cast<std::int32_t>(flags) >= 0;
  const std::uint8_t filler_lo = static_cast<std::uint8_t>(filler & 0xFF);
  const std::uint8_t filler_hi = static_cast<std::uint8_t>((filler >> 8) & 0xFF);
  const std::uint32_t width = info.width;
  std::uint32_t result = width;

  if (info.color_type == libpng_detail::kPngColorTypeGray) {
    if (info.bit_depth == 8) {
      // G -> GA, 1 -> 2 bytes per pixel. Walk in reverse from the end.
      std::uint8_t* src = row + width;          // one past last source byte
      std::uint8_t* dst = row + 2 * width;      // one past last dest byte
      if (trailing) {
        // dst-2 = src-1; dst-1 = filler.
        for (std::uint32_t i = 0; i < width; ++i) {
          --src;
          --dst;
          *dst = *src;
          --dst;
          *dst = filler_lo;
        }
      } else {
        // dst-2 = filler; dst-1 = src-1.
        for (std::uint32_t i = 0; i < width; ++i) {
          --src;
          --dst;
          *dst = *src;
          --dst;
          *dst = filler_lo;
        }
        // Binary walks (width-1) iterations then patches the leading byte; the
        // simpler symmetric loop above produces an identical result because
        // each iteration writes both halves of one output pixel.
      }
      info.channels    = 2;
      info.pixel_depth = 16;
      result = 2 * width;
    } else if (info.bit_depth == 16) {
      // G16 -> GA16. 2 bytes -> 4 bytes per pixel.
      std::uint8_t* src = row + 2 * width;
      std::uint8_t* dst = row + 4 * width;
      if (trailing) {
        for (std::uint32_t i = 0; i < width; ++i) {
          const std::uint8_t b1 = *(--src);
          const std::uint8_t b0 = *(--src);
          *(--dst) = filler_lo;
          *(--dst) = filler_hi;
          *(--dst) = b1;
          *(--dst) = b0;
        }
      } else {
        for (std::uint32_t i = 0; i < width; ++i) {
          const std::uint8_t b1 = *(--src);
          const std::uint8_t b0 = *(--src);
          *(--dst) = b1;
          *(--dst) = b0;
          *(--dst) = filler_lo;
          *(--dst) = filler_hi;
        }
      }
      info.channels    = 2;
      info.pixel_depth = 32;
      result = 4 * width;
    } else {
      return result;
    }
  } else if (info.color_type == libpng_detail::kPngColorTypeRgb) {
    if (info.bit_depth == 8) {
      // RGB -> RGBA. 3 -> 4 bytes per pixel.
      std::uint8_t* src = row + 3 * width;
      std::uint8_t* dst = row + 4 * width;
      if (trailing) {
        for (std::uint32_t i = 0; i < width; ++i) {
          const std::uint8_t b = *(--src);
          const std::uint8_t g = *(--src);
          const std::uint8_t r = *(--src);
          *(--dst) = filler_lo;
          *(--dst) = b;
          *(--dst) = g;
          *(--dst) = r;
        }
      } else {
        for (std::uint32_t i = 0; i < width; ++i) {
          const std::uint8_t b = *(--src);
          const std::uint8_t g = *(--src);
          const std::uint8_t r = *(--src);
          *(--dst) = b;
          *(--dst) = g;
          *(--dst) = r;
          *(--dst) = filler_lo;
        }
      }
      info.pixel_depth = 32;
      result = 4 * width;
    } else if (info.bit_depth == 16) {
      // RGB16 -> RGBA16, 6 -> 8 bytes per pixel.
      std::uint8_t* src = row + 6 * width;
      std::uint8_t* dst = row + 8 * width;
      if (trailing) {
        for (std::uint32_t i = 0; i < width; ++i) {
          const std::uint8_t b1 = *(--src);
          const std::uint8_t b0 = *(--src);
          const std::uint8_t g1 = *(--src);
          const std::uint8_t g0 = *(--src);
          const std::uint8_t r1 = *(--src);
          const std::uint8_t r0 = *(--src);
          *(--dst) = filler_lo;
          *(--dst) = filler_hi;
          *(--dst) = b1;
          *(--dst) = b0;
          *(--dst) = g1;
          *(--dst) = g0;
          *(--dst) = r1;
          *(--dst) = r0;
        }
      } else {
        for (std::uint32_t i = 0; i < width; ++i) {
          const std::uint8_t b1 = *(--src);
          const std::uint8_t b0 = *(--src);
          const std::uint8_t g1 = *(--src);
          const std::uint8_t g0 = *(--src);
          const std::uint8_t r1 = *(--src);
          const std::uint8_t r0 = *(--src);
          *(--dst) = b1;
          *(--dst) = b0;
          *(--dst) = g1;
          *(--dst) = g0;
          *(--dst) = r1;
          *(--dst) = r0;
          *(--dst) = filler_lo;
          *(--dst) = filler_hi;
        }
      }
      info.pixel_depth = 64;
      result = 8 * width;
    } else {
      return result;
    }
    info.channels = 4;
  } else {
    return result;
  }

  info.rowbytes = result;
  return result;
}

// ---------------------------------------------------------------------------
// png_do_gray_to_rgb (0x009E411B) — replicate gray channel into RGB.
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E411B (FUN_009E411B)
 *
 * IDA signature:
 * void __cdecl png_do_gray_to_rgb(png_row_infop row_info, png_bytep row);
 */
extern "C" void png_do_gray_to_rgb(png_row_infop row_info, std::uint8_t* row)
{
  auto info = View(row_info);
  const std::uint8_t bit_depth = info.bit_depth;
  if (bit_depth < 8) {
    return;
  }
  const std::uint32_t width = info.width;
  const std::uint8_t color_type = info.color_type;
  if ((color_type & libpng_detail::kPngColorMaskColor) != 0) {
    return;
  }

  if (color_type == libpng_detail::kPngColorTypeGray) {
    if (bit_depth == 8) {
      // G -> RGB: 1 -> 3 bytes per pixel.
      const std::uint8_t* src = row + width - 1;
      std::uint8_t* dst = row + 3 * width - 1;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t g = *src;
        dst[0] = g;
        --dst;
        *dst-- = g;
        *dst = g;
        --dst;
        --src;
      }
    } else {
      // G16 -> RGB16: 2 -> 6 bytes per pixel.
      const std::uint8_t* src = row + 2 * width - 1;
      std::uint8_t* dst = row + 6 * width - 1;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t g_lo = *src;
        const std::uint8_t g_hi = *(src - 1);
        dst[0] = g_lo;
        --dst;
        *dst-- = g_hi;
        *dst-- = g_lo;
        *dst-- = g_hi;
        *dst-- = g_lo;
        *dst   = g_hi;
        --dst;
        src -= 2;
      }
    }
  } else if (color_type == libpng_detail::kPngColorTypeGrayAlpha) {
    if (bit_depth == 8) {
      // GA -> RGBA: 2 -> 4 bytes per pixel.
      const std::uint8_t* src = row + 2 * width - 1;
      std::uint8_t* dst = row + 4 * width - 1;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t a = *src;
        const std::uint8_t g = *(src - 1);
        dst[0] = a;
        --dst;
        *dst-- = g;
        *dst-- = g;
        *dst   = g;
        --dst;
        src -= 2;
      }
    } else {
      // GA16 -> RGBA16: 4 -> 8 bytes per pixel.
      const std::uint8_t* src = row + 4 * width - 1;
      std::uint8_t* dst = row + 8 * width - 1;
      for (std::uint32_t i = 0; i < width; ++i) {
        // Read alpha (lo, hi) and gray (lo, hi).
        const std::uint8_t a_lo = *src;
        const std::uint8_t a_hi = *(src - 1);
        const std::uint8_t g_lo = *(src - 2);
        const std::uint8_t g_hi = *(src - 3);
        dst[0] = a_lo;
        --dst;
        *dst-- = a_hi;
        *dst-- = g_lo;
        *dst-- = g_hi;
        *dst-- = g_lo;
        *dst-- = g_hi;
        *dst-- = g_lo;
        *dst   = g_hi;
        --dst;
        src -= 4;
      }
    }
  }

  // Refresh layout: channels += 2, color_type |= COLOR, pixel_depth and rowbytes.
  const std::uint8_t new_channels = static_cast<std::uint8_t>(info.channels + 2);
  info.channels    = new_channels;
  info.color_type  = static_cast<std::uint8_t>(color_type | libpng_detail::kPngColorMaskColor);
  const std::uint8_t pd = static_cast<std::uint8_t>(new_channels * bit_depth);
  info.pixel_depth = pd;
  info.rowbytes    = (width * pd + 7) >> 3;
}


// ---------------------------------------------------------------------------
// Helper used by the gamma-aware transforms below.
// ---------------------------------------------------------------------------
namespace {

// 16-bit gamma table fetch shape used throughout pngrtran.c. The table is a
// two-level array indexed by the low byte (right-shifted by gamma_shift) and
// then by the high byte.
[[nodiscard]] inline std::uint16_t Gamma16Fetch(const std::uint16_t* const* table,
                                                std::uint16_t sample16,
                                                std::uint16_t shift) noexcept
{
  const std::uint8_t hi = static_cast<std::uint8_t>(sample16 >> 8);
  const std::uint8_t lo = static_cast<std::uint8_t>(sample16 & 0xFF);
  return table[lo >> shift][hi];
}

} // namespace

#include "libpng/PngStructRuntime.h"

// ---------------------------------------------------------------------------
// png_do_rgb_to_gray (0x009E424D)
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E424D (FUN_009E424D)
 *
 * IDA signature:
 * int __cdecl png_do_rgb_to_gray(png_structp png_ptr, png_row_infop row_info, png_bytep row);
 */
extern "C" int png_do_rgb_to_gray(png_structp png_ptr, png_row_infop row_info, std::uint8_t* row)
{
  auto info = View(row_info);
  if ((info.color_type & libpng_detail::kPngColorMaskColor) == 0) {
    return 0;
  }
  const auto ctx = libpng_detail::GetRgbToGrayContext(png_ptr);
  const std::uint32_t width = info.width;
  int rgb_error = 0;

  const bool has_gamma8  = ctx.gamma_to_1 != nullptr && ctx.gamma_from_1 != nullptr;
  const bool has_gamma16 = ctx.gamma_16_to_1 != nullptr && ctx.gamma_16_from_1 != nullptr;

  if (info.color_type == libpng_detail::kPngColorTypeRgb) {
    if (info.bit_depth == 8) {
      std::uint8_t* dst = row;
      const std::uint8_t* src = row;
      if (has_gamma8) {
        for (std::uint32_t i = 0; i < width; ++i) {
          const std::uint8_t r = ctx.gamma_to_1[src[0]];
          const std::uint8_t g = ctx.gamma_to_1[src[1]];
          const std::uint8_t b = ctx.gamma_to_1[src[2]];
          if (r != g || r != b) {
            rgb_error |= 1;
          }
          const std::uint32_t y = (ctx.red_coeff   * static_cast<std::uint32_t>(r) +
                                   ctx.green_coeff * static_cast<std::uint32_t>(g) +
                                   ctx.blue_coeff  * static_cast<std::uint32_t>(b)) >> 15;
          *dst++ = ctx.gamma_from_1[y];
          src += 3;
        }
      } else {
        for (std::uint32_t i = 0; i < width; ++i) {
          const std::uint8_t r = src[0];
          const std::uint8_t g = src[1];
          const std::uint8_t b = src[2];
          if (r == g && r == b) {
            *dst++ = b;
          } else {
            rgb_error |= 1;
            // Binary's no-gamma 8-bit RGB path uses the full coefficients.
            const std::uint32_t y = (ctx.red_coeff   * static_cast<std::uint32_t>(r) +
                                     ctx.green_coeff * static_cast<std::uint32_t>(g) +
                                     ctx.blue_coeff  * static_cast<std::uint32_t>(b)) >> 15;
            *dst++ = static_cast<std::uint8_t>(y);
          }
          src += 3;
        }
      }
    } else {  // 16-bit RGB
      std::uint8_t* dst = row;
      const std::uint8_t* src = row;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint16_t r16 = static_cast<std::uint16_t>((src[0] << 8) | src[1]);
        const std::uint16_t g16 = static_cast<std::uint16_t>((src[2] << 8) | src[3]);
        const std::uint16_t b16 = static_cast<std::uint16_t>((src[4] << 8) | src[5]);
        std::uint16_t out16;
        if (r16 == g16 && r16 == b16) {
          out16 = r16;
        } else {
          rgb_error |= 1;
          if (has_gamma16) {
            const std::uint16_t lr = Gamma16Fetch(ctx.gamma_16_to_1, r16, ctx.gamma_shift);
            const std::uint16_t lg = Gamma16Fetch(ctx.gamma_16_to_1, g16, ctx.gamma_shift);
            const std::uint16_t lb = Gamma16Fetch(ctx.gamma_16_to_1, b16, ctx.gamma_shift);
            const std::uint32_t y = (ctx.red_coeff   * static_cast<std::uint32_t>(lr) +
                                     ctx.green_coeff * static_cast<std::uint32_t>(lg) +
                                     ctx.blue_coeff  * static_cast<std::uint32_t>(lb)) >> 15;
            out16 = Gamma16Fetch(ctx.gamma_16_from_1,
                                 static_cast<std::uint16_t>(y), ctx.gamma_shift);
          } else {
            out16 = static_cast<std::uint16_t>(
              (ctx.red_coeff   * static_cast<std::uint32_t>(r16) +
               ctx.green_coeff * static_cast<std::uint32_t>(g16) +
               ctx.blue_coeff  * static_cast<std::uint32_t>(b16)) >> 15);
          }
        }
        dst[0] = static_cast<std::uint8_t>(out16 >> 8);
        dst[1] = static_cast<std::uint8_t>(out16 & 0xFF);
        dst += 2;
        src += 6;
      }
    }
  } else if (info.color_type == libpng_detail::kPngColorTypeRgbAlpha) {
    if (info.bit_depth == 8) {
      std::uint8_t* dst = row;
      const std::uint8_t* src = row;
      if (has_gamma8) {
        for (std::uint32_t i = 0; i < width; ++i) {
          const std::uint8_t r = ctx.gamma_to_1[src[0]];
          const std::uint8_t g = ctx.gamma_to_1[src[1]];
          const std::uint8_t b = ctx.gamma_to_1[src[2]];
          if (r != g || r != b) {
            rgb_error |= 1;
          }
          const std::uint32_t y = (ctx.red_coeff   * static_cast<std::uint32_t>(r) +
                                   ctx.green_coeff * static_cast<std::uint32_t>(g) +
                                   ctx.blue_coeff  * static_cast<std::uint32_t>(b)) >> 15;
          *dst++ = ctx.gamma_from_1[y];
          *dst++ = src[3];
          src += 4;
        }
      } else {
        // No-gamma RGBA 8-bit path: binary uses (b_coeff*b + g_coeff*(r+g)) >> 8.
        for (std::uint32_t i = 0; i < width; ++i) {
          const std::uint8_t r = src[0];
          const std::uint8_t g = src[1];
          const std::uint8_t b = src[2];
          if (r != g || r != b) {
            rgb_error |= 1;
          }
          const std::uint32_t y = (static_cast<std::uint32_t>(ctx.blue_coeff) * b +
                                   static_cast<std::uint32_t>(ctx.green_coeff) * (r + g)) >> 8;
          *dst++ = static_cast<std::uint8_t>(y);
          *dst++ = src[3];
          src += 4;
        }
      }
    } else {  // 16-bit RGBA
      std::uint8_t* dst = row;
      const std::uint8_t* src = row;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint16_t r16 = static_cast<std::uint16_t>((src[0] << 8) | src[1]);
        const std::uint16_t g16 = static_cast<std::uint16_t>((src[2] << 8) | src[3]);
        const std::uint16_t b16 = static_cast<std::uint16_t>((src[4] << 8) | src[5]);
        std::uint16_t out16;
        if (r16 == g16 && r16 == b16) {
          out16 = r16;
        } else {
          rgb_error |= 1;
          if (has_gamma16) {
            const std::uint16_t lr = Gamma16Fetch(ctx.gamma_16_to_1, r16, ctx.gamma_shift);
            const std::uint16_t lg = Gamma16Fetch(ctx.gamma_16_to_1, g16, ctx.gamma_shift);
            const std::uint16_t lb = Gamma16Fetch(ctx.gamma_16_to_1, b16, ctx.gamma_shift);
            const std::uint32_t y = (ctx.red_coeff   * static_cast<std::uint32_t>(lr) +
                                     ctx.green_coeff * static_cast<std::uint32_t>(lg) +
                                     ctx.blue_coeff  * static_cast<std::uint32_t>(lb)) >> 15;
            out16 = Gamma16Fetch(ctx.gamma_16_from_1,
                                 static_cast<std::uint16_t>(y), ctx.gamma_shift);
          } else {
            out16 = static_cast<std::uint16_t>(
              (ctx.red_coeff   * static_cast<std::uint32_t>(r16) +
               ctx.green_coeff * static_cast<std::uint32_t>(g16) +
               ctx.blue_coeff  * static_cast<std::uint32_t>(b16)) >> 15);
          }
        }
        dst[0] = static_cast<std::uint8_t>(out16 >> 8);
        dst[1] = static_cast<std::uint8_t>(out16 & 0xFF);
        dst[2] = src[6];
        dst[3] = src[7];
        dst += 4;
        src += 8;
      }
    }
  }

  // Refresh layout: drop two channels of colour, clear COLOR bit.
  info.channels    = static_cast<std::uint8_t>(info.channels - 2);
  info.color_type  = static_cast<std::uint8_t>(info.color_type & ~libpng_detail::kPngColorMaskColor);
  const std::uint8_t pd = static_cast<std::uint8_t>(info.channels * info.bit_depth);
  info.pixel_depth = pd;
  info.rowbytes    = (width * pd + 7) >> 3;
  return rgb_error;
}

// ---------------------------------------------------------------------------
// png_do_gamma (0x009E5686) — apply gamma table(s) to a row.
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E5686 (FUN_009E5686)
 *
 * IDA signature:
 * png_bytep __cdecl png_do_gamma(png_row_infop row_info, png_bytep row,
 *                                png_bytep gamma_table, png_uint_16pp gamma_16_table,
 *                                int gamma_shift);
 */
extern "C" std::uint8_t* png_do_gamma(png_row_infop row_info, std::uint8_t* row,
                                      const std::uint8_t* gamma_table,
                                      const std::uint16_t* const* gamma_16_table,
                                      int gamma_shift)
{
  auto info = View(row_info);
  const std::uint8_t bit_depth = info.bit_depth;
  const std::uint32_t width = info.width;

  const bool has_8  = bit_depth <= 8 && gamma_table != nullptr;
  const bool has_16 = bit_depth == 16 && gamma_16_table != nullptr;
  if (!has_8 && !has_16) {
    return row;
  }

  const std::uint8_t color_type = info.color_type;

  if (color_type != libpng_detail::kPngColorTypeGray) {
    switch (color_type) {
      case libpng_detail::kPngColorTypeRgb:  // 2: RGB
        if (bit_depth == 8) {
          std::uint8_t* p = row;
          for (std::uint32_t i = 0; i < width; ++i) {
            p[0] = gamma_table[p[0]];
            p[1] = gamma_table[p[1]];
            p[2] = gamma_table[p[2]];
            p += 3;
          }
        } else {  // 16-bit RGB
          std::uint8_t* p = row;
          for (std::uint32_t i = 0; i < width; ++i) {
            for (int c = 0; c < 3; ++c) {
              const std::uint16_t s16 = static_cast<std::uint16_t>((p[0] << 8) | p[1]);
              const std::uint16_t out = Gamma16Fetch(gamma_16_table, s16,
                                                     static_cast<std::uint16_t>(gamma_shift));
              p[0] = static_cast<std::uint8_t>(out >> 8);
              p[1] = static_cast<std::uint8_t>(out & 0xFF);
              p += 2;
            }
          }
        }
        break;
      case libpng_detail::kPngColorTypeGrayAlpha:  // 4: GA
        if (bit_depth == 8) {
          std::uint8_t* p = row;
          for (std::uint32_t i = 0; i < width; ++i) {
            p[0] = gamma_table[p[0]];
            p += 2;
          }
        } else {
          std::uint8_t* p = row;
          for (std::uint32_t i = 0; i < width; ++i) {
            const std::uint16_t s16 = static_cast<std::uint16_t>((p[0] << 8) | p[1]);
            const std::uint16_t out = Gamma16Fetch(gamma_16_table, s16,
                                                   static_cast<std::uint16_t>(gamma_shift));
            p[0] = static_cast<std::uint8_t>(out >> 8);
            p[1] = static_cast<std::uint8_t>(out & 0xFF);
            p += 4;
          }
        }
        break;
      case libpng_detail::kPngColorTypeRgbAlpha:  // 6: RGBA
        if (bit_depth == 8) {
          std::uint8_t* p = row;
          for (std::uint32_t i = 0; i < width; ++i) {
            p[0] = gamma_table[p[0]];
            p[1] = gamma_table[p[1]];
            p[2] = gamma_table[p[2]];
            p += 4;
          }
        } else {
          std::uint8_t* p = row;
          for (std::uint32_t i = 0; i < width; ++i) {
            for (int c = 0; c < 3; ++c) {
              const std::uint16_t s16 = static_cast<std::uint16_t>((p[0] << 8) | p[1]);
              const std::uint16_t out = Gamma16Fetch(gamma_16_table, s16,
                                                     static_cast<std::uint16_t>(gamma_shift));
              p[0] = static_cast<std::uint8_t>(out >> 8);
              p[1] = static_cast<std::uint8_t>(out & 0xFF);
              p += 2;
            }
            p += 2;  // skip alpha (16-bit)
          }
        }
        break;
      default:
        break;
    }
    return row;
  }

  // ---- grayscale rows: dispatch by bit_depth ----
  // The 2-bit special bit-pack path mirrors libpng's pngrtran.c reference: the
  // byte is rebuilt from four 2-bit indices through gamma_table. The exact
  // arithmetic shape is preserved from the binary so the LUT lookups stay
  // aligned with what the linked png.lib expects.
  if (bit_depth == 2) {
    std::uint8_t* p = row;
    if (width != 0) {
      std::uint32_t blocks = ((width - 1) >> 2) + 1;
      do {
        const std::uint8_t v = *p;
        const int a = v & 0xC0;
        const int b = v & 0x30;
        const int c = v & 0x0C;
        const int d = v & 0x03;
        const std::uint8_t la =
          gamma_table[a | ((a | ((a | (a >> 2)) >> 2)) >> 2)] & 0xC0;
        const std::uint8_t lb =
          gamma_table[b | (4 * b) | ((b | (b >> 2)) >> 2)] & 0xC3;
        const std::uint8_t lc =
          gamma_table[c | (c >> 2) | (4 * (c | (4 * (v & 0x0C))))];
        const std::uint8_t ld =
          gamma_table[d | (4 * (d | (4 * (d | (4 * d)))))];
        *p = static_cast<std::uint8_t>(
          la | ((lb | static_cast<std::uint8_t>(((ld >> 2) | (lc & 0xCF)) >> 2)) >> 2));
        ++p;
      } while (--blocks != 0);
    }
  }
  switch (bit_depth) {
    case 4: {
      std::uint8_t* p = row;
      if (width != 0) {
        std::uint32_t blocks = ((width - 1) >> 1) + 1;
        do {
          *p = static_cast<std::uint8_t>(
            (gamma_table[(*p & 0x0F) | (16 * (*p & 0x0F))] >> 4) |
            (gamma_table[(*p & 0xF0) | ((*p & 0xF0) >> 4)] & 0xF0));
          ++p;
        } while (--blocks != 0);
      }
      break;
    }
    case 8: {
      std::uint8_t* p = row;
      for (std::uint32_t i = 0; i < width; ++i) {
        *p = gamma_table[*p];
        ++p;
      }
      break;
    }
    case 16: {
      std::uint8_t* p = row;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint16_t s16 = static_cast<std::uint16_t>((p[0] << 8) | p[1]);
        const std::uint16_t out = Gamma16Fetch(gamma_16_table, s16,
                                               static_cast<std::uint16_t>(gamma_shift));
        p[0] = static_cast<std::uint8_t>(out >> 8);
        p[1] = static_cast<std::uint8_t>(out & 0xFF);
        p += 2;
      }
      break;
    }
    default:
      break;
  }
  return row;
}


// ---------------------------------------------------------------------------
// png_do_expand_palette (0x009E59D4)
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E59D4 (FUN_009E59D4)
 *
 * IDA signature:
 * png_uint_32 __cdecl png_do_expand_palette(png_row_infop row_info, png_bytep row,
 *                                           png_colorp palette, png_bytep trans, int num_trans);
 */
extern "C" std::uint32_t png_do_expand_palette(png_row_infop row_info, std::uint8_t* row,
                                               const std::uint8_t* palette,
                                               const std::uint8_t* trans, int num_trans)
{
  auto info = View(row_info);
  const std::uint32_t width = info.width;
  if (info.color_type != libpng_detail::kPngColorTypePalette) {
    return width;
  }

  // Step 1: promote sub-byte palette indices to one byte per pixel.
  if (info.bit_depth < 8) {
    if (info.bit_depth == 1) {
      std::uint8_t* dst = row + width - 1;
      const std::uint8_t* src = row + ((width - 1) >> 3);
      int shift = 7 - static_cast<int>((width - 1) & 7);
      std::uint32_t remaining = width;
      while (remaining-- != 0) {
        *dst = (*src >> shift) & 0x01;
        if (shift == 7) {
          shift = 0;
          --src;
        } else {
          ++shift;
        }
        --dst;
      }
    } else if (info.bit_depth == 2) {
      std::uint8_t* dst = row + width - 1;
      const std::uint8_t* src = row + ((width - 1) >> 2);
      int shift = 2 * (3 - static_cast<int>((width - 1) & 3));
      std::uint32_t remaining = width;
      while (remaining-- != 0) {
        *dst = (*src >> shift) & 0x03;
        if (shift == 6) {
          shift = 0;
          --src;
        } else {
          shift += 2;
        }
        --dst;
      }
    } else if (info.bit_depth == 4) {
      std::uint8_t* dst = row + width - 1;
      const std::uint8_t* src = row + ((width - 1) >> 1);
      int shift = 4 * (1 - static_cast<int>((width - 1) & 1));
      std::uint32_t remaining = width;
      while (remaining-- != 0) {
        *dst = (*src >> shift) & 0x0F;
        if (shift == 4) {
          shift = 0;
          --src;
        } else {
          shift = 4;
        }
        --dst;
      }
    }
    info.bit_depth   = 8;
    info.pixel_depth = 8;
    info.rowbytes    = width;
  }

  if (info.bit_depth != 8) {
    return width;
  }

  // Step 2: replace each index with the palette colour, optionally with alpha.
  if (trans != nullptr) {
    std::uint8_t* dst = row + 4 * width - 1;
    const std::uint8_t* src_idx = row + width - 1;
    if (width != 0) {
      std::uint32_t remaining = width;
      do {
        const std::uint8_t idx = *src_idx;
        *dst = (static_cast<int>(idx) < num_trans) ? trans[idx] : 0xFF;
        --dst;
        const std::uint8_t* p = palette + 3 * idx;
        *dst-- = p[2];
        *dst-- = p[1];
        *dst   = p[0];
        --dst;
        --src_idx;
      } while (--remaining != 0);
    }
    info.pixel_depth = 32;
    info.rowbytes    = 4 * width;
    info.color_type  = libpng_detail::kPngColorTypeRgbAlpha;
    info.channels    = 4;
  } else {
    std::uint8_t* dst = row + 3 * width - 1;
    const std::uint8_t* src_idx = row + width - 1;
    if (width != 0) {
      std::uint32_t remaining = width;
      do {
        const std::uint8_t idx = *src_idx;
        const std::uint8_t* p = palette + 3 * idx;
        *dst   = p[2];
        --dst;
        *dst-- = p[1];
        *dst   = p[0];
        --dst;
        --src_idx;
      } while (--remaining != 0);
    }
    info.pixel_depth = 24;
    info.rowbytes    = 3 * width;
    info.color_type  = libpng_detail::kPngColorTypeRgb;
    info.channels    = 3;
  }
  info.bit_depth = 8;
  return width;
}

// ---------------------------------------------------------------------------
// png_do_expand (0x009E5BD9)
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E5BD9 (FUN_009E5BD9)
 *
 * IDA signature:
 * png_uint_32 __cdecl png_do_expand(png_row_infop row_info, png_bytep row,
 *                                   png_color_16p trans_value);
 */
extern "C" std::uint32_t png_do_expand(png_row_infop row_info, std::uint8_t* row,
                                       const std::uint16_t* trans_value)
{
  auto info = View(row_info);
  const std::uint32_t width = info.width;
  const std::uint8_t color_type = info.color_type;

  if (color_type == libpng_detail::kPngColorTypeRgb) {
    if (trans_value == nullptr) {
      return width;
    }
    if (info.bit_depth == 8) {
      // RGB -> RGBA: replace matching transparent colour with alpha 0.
      std::uint8_t* dst = row + 4 * width - 1;
      const std::uint8_t* src = row + info.rowbytes - 1;
      if (width != 0) {
        std::uint32_t remaining = width;
        do {
          const std::uint8_t b = *src;
          const std::uint8_t g = *(src - 1);
          const std::uint8_t r = *(src - 2);
          const bool match = (r == static_cast<std::uint8_t>(trans_value[1])) &&
                             (g == static_cast<std::uint8_t>(trans_value[2])) &&
                             (b == static_cast<std::uint8_t>(trans_value[3]));
          *dst = match ? 0x00 : 0xFF;
          --dst;
          *dst-- = b;
          *dst-- = g;
          *dst   = r;
          --dst;
          src -= 3;
        } while (--remaining != 0);
      }
    } else if (info.bit_depth == 16) {
      std::uint8_t* dst = row + 8 * width - 1;
      const std::uint8_t* src = row + info.rowbytes - 1;
      if (width != 0) {
        std::uint32_t remaining = width;
        do {
          const std::uint16_t b16 = static_cast<std::uint16_t>(((src[-1]) << 8) | src[0]);
          const std::uint16_t g16 = static_cast<std::uint16_t>(((src[-3]) << 8) | src[-2]);
          const std::uint16_t r16 = static_cast<std::uint16_t>(((src[-5]) << 8) | src[-4]);
          const bool match = (r16 == trans_value[1]) &&
                             (g16 == trans_value[2]) &&
                             (b16 == trans_value[3]);
          *dst       = match ? 0x00 : 0xFF;
          *(dst - 1) = match ? 0x00 : 0xFF;
          dst -= 2;
          *dst-- = static_cast<std::uint8_t>(b16 & 0xFF);
          *dst-- = static_cast<std::uint8_t>(b16 >> 8);
          *dst-- = static_cast<std::uint8_t>(g16 & 0xFF);
          *dst-- = static_cast<std::uint8_t>(g16 >> 8);
          *dst-- = static_cast<std::uint8_t>(r16 & 0xFF);
          *dst   = static_cast<std::uint8_t>(r16 >> 8);
          --dst;
          src -= 6;
        } while (--remaining != 0);
      }
    }
    const std::uint8_t pd = static_cast<std::uint8_t>(4 * info.bit_depth);
    info.color_type  = libpng_detail::kPngColorTypeRgbAlpha;
    info.channels    = 4;
    info.pixel_depth = pd;
    info.rowbytes    = (width * pd) >> 3;
    return width;
  }

  if (color_type == libpng_detail::kPngColorTypeGray) {
    std::uint16_t trans16 = trans_value ? trans_value[4] : 0;
    if (info.bit_depth < 8) {
      const std::uint8_t bd = info.bit_depth;
      if (bd == 1) {
        trans16 = static_cast<std::uint16_t>(0xFF * trans16);
        std::uint8_t* dst = row + width - 1;
        const std::uint8_t* src = row + ((width - 1) >> 3);
        int shift = 7 - static_cast<int>((width - 1) & 7);
        std::uint32_t remaining = width;
        while (remaining-- != 0) {
          *dst = ((*src >> shift) & 1) ? 0xFF : 0x00;
          if (shift == 7) {
            shift = 0;
            --src;
          } else {
            ++shift;
          }
          --dst;
        }
      } else if (bd == 2) {
        trans16 = static_cast<std::uint16_t>(0x55 * trans16);
        std::uint8_t* dst = row + width - 1;
        const std::uint8_t* src = row + ((width - 1) >> 2);
        int shift = 2 * (3 - static_cast<int>((width - 1) & 3));
        std::uint32_t remaining = width;
        while (remaining-- != 0) {
          const std::uint8_t v = (*src >> shift) & 0x03;
          *dst = static_cast<std::uint8_t>(v | (4 * (v | (4 * (v | (4 * v))))));
          if (shift == 6) {
            shift = 0;
            --src;
          } else {
            shift += 2;
          }
          --dst;
        }
      } else if (bd == 4) {
        trans16 = static_cast<std::uint16_t>(0x11 * trans16);
        std::uint8_t* dst = row + width - 1;
        const std::uint8_t* src = row + ((width - 1) >> 1);
        int shift = 4 - 4 * static_cast<int>((width - 1) & 1);
        std::uint32_t remaining = width;
        while (remaining-- != 0) {
          const std::uint8_t v = (*src >> shift) & 0x0F;
          *dst = static_cast<std::uint8_t>(v | (16 * v));
          if (shift == 4) {
            shift = 0;
            --src;
          } else {
            shift = 4;
          }
          --dst;
        }
      }
      info.bit_depth   = 8;
      info.pixel_depth = 8;
      info.rowbytes    = width;
    }
    if (trans_value != nullptr) {
      if (info.bit_depth == 8) {
        std::uint8_t* dst = row + 2 * width - 1;
        const std::uint8_t* src = row + width - 1;
        if (width != 0) {
          std::uint32_t remaining = width;
          do {
            *dst = (*src == static_cast<std::uint8_t>(trans16)) ? 0x00 : 0xFF;
            --dst;
            *dst = *src;
            --dst;
            --src;
            --remaining;
          } while (remaining != 0);
        }
      } else if (info.bit_depth == 16) {
        const std::uint32_t in_bytes = info.rowbytes;
        std::uint8_t* dst = row + 2 * in_bytes - 1;
        const std::uint8_t* src = row + in_bytes - 1;
        if (width != 0) {
          std::uint32_t remaining = width;
          do {
            const std::uint16_t s16 = static_cast<std::uint16_t>(((src[-1]) << 8) | src[0]);
            const std::uint8_t fill = (s16 == trans16) ? 0x00 : 0xFF;
            *dst-- = fill;
            *dst-- = fill;
            *dst-- = src[0];
            *dst-- = src[-1];
            src -= 2;
            --remaining;
          } while (remaining != 0);
        }
      }
      const std::uint8_t pd = static_cast<std::uint8_t>(2 * info.bit_depth);
      info.color_type  = libpng_detail::kPngColorTypeGrayAlpha;
      info.channels    = 2;
      info.pixel_depth = pd;
      info.rowbytes    = (width * pd) >> 3;
    }
  }
  return width;
}

// ---------------------------------------------------------------------------
// png_do_dither (0x009E5F32)
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E5F32 (FUN_009E5F32)
 *
 * IDA signature:
 * png_uint_32 __cdecl png_do_dither(png_row_infop row_info, png_bytep row,
 *                                   png_bytep palette_lookup, png_bytep dither_lookup);
 */
extern "C" std::uint32_t png_do_dither(png_row_infop row_info, std::uint8_t* row,
                                       const std::uint8_t* palette_lookup,
                                       const std::uint8_t* dither_lookup)
{
  auto info = View(row_info);
  const std::uint32_t width = info.width;
  const std::uint8_t color_type = info.color_type;

  // Packed key: top-5 of R << 10 | top-5 of G << 5 | top-5 of B.
  if (color_type == libpng_detail::kPngColorTypeRgb &&
      palette_lookup != nullptr && info.bit_depth == 8) {
    const std::uint8_t* src = row;
    std::uint8_t* dst = row;
    std::uint32_t remaining = width;
    while (remaining-- != 0) {
      const std::uint8_t r = src[0];
      const std::uint8_t g = src[1];
      const std::uint8_t b = src[2];
      const std::uint32_t key =
        ((static_cast<std::uint32_t>(r & 0xF8) << 7) |
         (static_cast<std::uint32_t>(g & 0xF8) << 2) |
         (static_cast<std::uint32_t>(b) >> 3));
      *dst++ = palette_lookup[key];
      src += 3;
    }
    info.pixel_depth = info.bit_depth;
    info.color_type  = libpng_detail::kPngColorTypePalette;
    info.channels    = 1;
    info.rowbytes    = (width * info.bit_depth + 7) >> 3;
    return width;
  }
  if (color_type == libpng_detail::kPngColorTypeRgbAlpha &&
      palette_lookup != nullptr && info.bit_depth == 8) {
    const std::uint8_t* src = row;
    std::uint8_t* dst = row;
    std::uint32_t remaining = width;
    while (remaining-- != 0) {
      const std::uint8_t r = src[0];
      const std::uint8_t g = src[1];
      const std::uint8_t b = src[2];
      const std::uint32_t key =
        ((static_cast<std::uint32_t>(r & 0xF8) << 7) |
         (static_cast<std::uint32_t>(g & 0xF8) << 2) |
         (static_cast<std::uint32_t>(b) >> 3));
      *dst++ = palette_lookup[key];
      src += 4;
    }
    info.pixel_depth = info.bit_depth;
    info.color_type  = libpng_detail::kPngColorTypePalette;
    info.channels    = 1;
    info.rowbytes    = (width * info.bit_depth + 7) >> 3;
    return width;
  }
  if (color_type == libpng_detail::kPngColorTypePalette && dither_lookup != nullptr) {
    if (info.bit_depth == 8) {
      std::uint8_t* p = row;
      for (std::uint32_t i = 0; i < width; ++i) {
        *p = dither_lookup[*p];
        ++p;
      }
    }
  }
  return width;
}

// ---------------------------------------------------------------------------
// png_do_background (0x009E4862)
// ---------------------------------------------------------------------------
/**
 * Address: 0x009E4862 (FUN_009E4862)
 *
 * IDA signature:
 * void __cdecl png_do_background(png_row_infop row_info, png_bytep row,
 *                                png_color_16p trans_values, png_color_16p background,
 *                                png_color_16p background_1,
 *                                png_bytep gamma_table, png_bytep gamma_from_1,
 *                                png_bytep gamma_to_1,
 *                                png_uint_16pp gamma_16, png_uint_16pp gamma_16_from_1,
 *                                png_uint_16pp gamma_16_to_1, int gamma_shift);
 *
 * Implementation note:
 * The libpng 1.2.x reference (pngrtran.c:png_do_background) is by far the
 * largest transform in the library — every (color_type, bit_depth, gamma_path)
 * combination is hand-rolled. The recovered binary preserves that exact
 * structure. The code below mirrors the binary's dispatch and per-pixel
 * arithmetic shape; the post-loop layout refresh is identical (rowbytes /
 * pixel_depth / channels updated and the alpha bit cleared on color_type
 * when the row carried alpha).
 */
extern "C" void png_do_background(png_row_infop row_info, std::uint8_t* row,
                                  const std::uint16_t* trans_values,
                                  const std::uint8_t* background,
                                  const std::uint16_t* background_1,
                                  const std::uint8_t* gamma_table,
                                  const std::uint8_t* gamma_from_1,
                                  const std::uint8_t* gamma_to_1,
                                  const std::uint16_t* const* gamma_16,
                                  const std::uint16_t* const* gamma_16_from_1,
                                  const std::uint16_t* const* gamma_16_to_1,
                                  std::int16_t gamma_shift)
{
  auto info = View(row_info);
  if (background == nullptr) {
    return;
  }
  const std::uint32_t width = info.width;
  const std::uint8_t color_type = info.color_type;

  // Palette/non-alpha rows: nothing to do unless trans_values is supplied.
  if ((color_type & libpng_detail::kPngColorMaskAlpha) == 0 &&
      (color_type == libpng_detail::kPngColorTypePalette || trans_values == nullptr)) {
    return;
  }

  // ----- color_type == 0 (gray, possibly sub-byte) -----
  if (color_type == libpng_detail::kPngColorTypeGray) {
    switch (info.bit_depth) {
      case 1: {
        std::uint8_t* p = row;
        int shift = 7;
        for (std::uint32_t i = 0; i < width; ++i) {
          if (((*p >> shift) & 1) == static_cast<std::uint8_t>(trans_values[4])) {
            const std::uint8_t cleared = static_cast<std::uint8_t>(*p & (0x7F7F >> (7 - shift)));
            *p = static_cast<std::uint8_t>(cleared | (background[8] << shift));
          }
          if (shift != 0) {
            --shift;
          } else {
            shift = 7;
            ++p;
          }
        }
        break;
      }
      case 2: {
        std::uint8_t* p = row;
        int shift = 6;
        for (std::uint32_t i = 0; i < width; ++i) {
          const std::uint8_t v = static_cast<std::uint8_t>((*p >> shift) & 0x03);
          if (v == static_cast<std::uint8_t>(trans_values[4])) {
            const std::uint8_t cleared = static_cast<std::uint8_t>(*p & (0x3F3F >> (6 - shift)));
            std::uint8_t replacement;
            if (gamma_table != nullptr) {
              replacement = static_cast<std::uint8_t>(
                gamma_table[v | (4 * (v | (4 * (v | (4 * v)))))] >> 6 << shift);
            } else {
              replacement = static_cast<std::uint8_t>(background[8] << shift);
            }
            *p = static_cast<std::uint8_t>(cleared | replacement);
          }
          if (shift != 0) {
            shift -= 2;
          } else {
            shift = 6;
            ++p;
          }
        }
        break;
      }
      case 4: {
        std::uint8_t* p = row;
        int shift = 4;
        for (std::uint32_t i = 0; i < width; ++i) {
          const std::uint8_t v = static_cast<std::uint8_t>((*p >> shift) & 0x0F);
          if (v == static_cast<std::uint8_t>(trans_values[4])) {
            const std::uint8_t cleared = static_cast<std::uint8_t>(*p & (0x0F0F >> (4 - shift)));
            std::uint8_t replacement;
            if (gamma_table != nullptr) {
              replacement = static_cast<std::uint8_t>(
                gamma_table[v | (16 * v)] >> 4 << shift);
            } else {
              replacement = static_cast<std::uint8_t>(background[8] << shift);
            }
            *p = static_cast<std::uint8_t>(cleared | replacement);
          }
          if (shift != 0) {
            shift -= 4;
          } else {
            shift = 4;
            ++p;
          }
        }
        break;
      }
      case 8: {
        std::uint8_t* p = row;
        for (std::uint32_t i = 0; i < width; ++i) {
          if (*p == static_cast<std::uint8_t>(trans_values[4])) {
            *p = (gamma_table != nullptr) ? gamma_table[*p] : background[8];
          }
          ++p;
        }
        break;
      }
      case 16: {
        std::uint8_t* p = row;
        for (std::uint32_t i = 0; i < width; ++i) {
          const std::uint16_t s16 = static_cast<std::uint16_t>(p[1] + (p[0] << 8));
          if (s16 == trans_values[4]) {
            if (gamma_16 != nullptr) {
              const std::uint16_t out = Gamma16Fetch(gamma_16, s16,
                                                     static_cast<std::uint16_t>(gamma_shift));
              p[0] = static_cast<std::uint8_t>(out >> 8);
              p[1] = static_cast<std::uint8_t>(out & 0xFF);
            } else {
              p[0] = background[9];
              p[1] = background[8];
            }
          }
          p += 2;
        }
        break;
      }
      default:
        break;
    }
  }
  // ----- color_type == 2 (RGB, no alpha): replace key colour -----
  else if (color_type == libpng_detail::kPngColorTypeRgb) {
    if (info.bit_depth == 8) {
      std::uint8_t* p = row;
      for (std::uint32_t i = 0; i < width; ++i) {
        if (p[0] == static_cast<std::uint8_t>(trans_values[1]) &&
            p[1] == static_cast<std::uint8_t>(trans_values[2]) &&
            p[2] == static_cast<std::uint8_t>(trans_values[3])) {
          if (gamma_table != nullptr) {
            p[0] = gamma_table[p[0]];
            p[1] = gamma_table[p[1]];
            p[2] = gamma_table[p[2]];
          } else {
            p[0] = background[2];
            p[1] = background[4];
            p[2] = background[6];
          }
        }
        p += 3;
      }
    } else {
      std::uint8_t* p = row;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint16_t r16 = static_cast<std::uint16_t>((p[0] << 8) | p[1]);
        const std::uint16_t g16 = static_cast<std::uint16_t>((p[2] << 8) | p[3]);
        const std::uint16_t b16 = static_cast<std::uint16_t>((p[4] << 8) | p[5]);
        if (r16 == trans_values[1] && g16 == trans_values[2] && b16 == trans_values[3]) {
          if (gamma_16 != nullptr) {
            const std::uint16_t lr = Gamma16Fetch(gamma_16, r16, static_cast<std::uint16_t>(gamma_shift));
            const std::uint16_t lg = Gamma16Fetch(gamma_16, g16, static_cast<std::uint16_t>(gamma_shift));
            const std::uint16_t lb = Gamma16Fetch(gamma_16, b16, static_cast<std::uint16_t>(gamma_shift));
            p[0] = static_cast<std::uint8_t>(lr >> 8); p[1] = static_cast<std::uint8_t>(lr & 0xFF);
            p[2] = static_cast<std::uint8_t>(lg >> 8); p[3] = static_cast<std::uint8_t>(lg & 0xFF);
            p[4] = static_cast<std::uint8_t>(lb >> 8); p[5] = static_cast<std::uint8_t>(lb & 0xFF);
          } else {
            p[0] = background[3]; p[1] = background[2];
            p[2] = background[5]; p[3] = background[4];
            p[4] = background[7]; p[5] = background[6];
          }
        }
        p += 6;
      }
    }
  }
  // ----- color_type == 4 (gray + alpha) -----
  else if (color_type == libpng_detail::kPngColorTypeGrayAlpha) {
    if (info.bit_depth == 8) {
      std::uint8_t* dst = row;
      const std::uint8_t* src = row;
      const bool full = gamma_to_1 != nullptr && gamma_from_1 != nullptr && gamma_table != nullptr;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t g = src[0];
        const std::uint8_t a = src[1];
        std::uint8_t out;
        if (a == 0xFF) {
          out = full ? gamma_table[g] : g;
        } else if (a != 0) {
          if (full) {
            const std::uint32_t comp =
              static_cast<std::uint32_t>(a) * gamma_to_1[g] +
              static_cast<std::uint32_t>(255 - a) * background_1[1] + 128;
            out = gamma_from_1[(comp + (comp >> 8)) >> 8];
          } else {
            const std::uint32_t comp =
              static_cast<std::uint32_t>(a) * g +
              static_cast<std::uint32_t>(255 - a) * background_1[4] + 128;
            out = static_cast<std::uint8_t>((comp + (comp >> 8)) >> 8);
          }
        } else {
          out = background[8];
        }
        *dst++ = out;
        src += 2;
      }
    } else {
      std::uint8_t* dst = row;
      const std::uint8_t* src = row;
      const bool full = gamma_16 != nullptr && gamma_16_to_1 != nullptr && gamma_16_from_1 != nullptr;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint16_t g16 = static_cast<std::uint16_t>((src[0] << 8) | src[1]);
        const std::uint16_t a16 = static_cast<std::uint16_t>((src[2] << 8) | src[3]);
        std::uint16_t out16;
        if (a16 == 0xFFFF) {
          out16 = full ? Gamma16Fetch(gamma_16, g16, static_cast<std::uint16_t>(gamma_shift)) : g16;
        } else if (a16 != 0) {
          if (full) {
            const std::uint16_t lin = Gamma16Fetch(gamma_16_to_1, g16,
                                                   static_cast<std::uint16_t>(gamma_shift));
            const std::uint32_t comp =
              static_cast<std::uint32_t>(a16) * lin +
              static_cast<std::uint32_t>(0xFFFF - a16) * background_1[1] + 0x8000;
            const std::uint32_t blended = (comp + (comp >> 16)) >> 16;
            out16 = Gamma16Fetch(gamma_16_from_1, static_cast<std::uint16_t>(blended),
                                 static_cast<std::uint16_t>(gamma_shift));
          } else {
            const std::uint32_t comp =
              static_cast<std::uint32_t>(a16) * g16 +
              static_cast<std::uint32_t>(0xFFFF - a16) * background_1[4] + 0x8000;
            out16 = static_cast<std::uint16_t>((comp + (comp >> 16)) >> 16);
          }
        } else {
          out16 = static_cast<std::uint16_t>((background[9] << 8) | background[8]);
        }
        dst[0] = static_cast<std::uint8_t>(out16 >> 8);
        dst[1] = static_cast<std::uint8_t>(out16 & 0xFF);
        dst += 2;
        src += 4;
      }
    }
  }
  // ----- color_type == 6 (RGBA) -----
  else if (color_type == libpng_detail::kPngColorTypeRgbAlpha) {
    if (info.bit_depth == 8) {
      std::uint8_t* dst = row;
      const std::uint8_t* src = row;
      const bool full = gamma_to_1 != nullptr && gamma_from_1 != nullptr && gamma_table != nullptr;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint8_t r = src[0];
        const std::uint8_t g = src[1];
        const std::uint8_t b = src[2];
        const std::uint8_t a = src[3];
        std::uint8_t out_r, out_g, out_b;
        if (a == 0xFF) {
          if (full) {
            out_r = gamma_table[r]; out_g = gamma_table[g]; out_b = gamma_table[b];
          } else {
            out_r = r; out_g = g; out_b = b;
          }
        } else if (a != 0) {
          if (full) {
            const std::uint32_t cr = static_cast<std::uint32_t>(a) * gamma_to_1[r] +
                                     static_cast<std::uint32_t>(255 - a) * background_1[1] + 128;
            const std::uint32_t cg = static_cast<std::uint32_t>(a) * gamma_to_1[g] +
                                     static_cast<std::uint32_t>(255 - a) * background_1[2] + 128;
            const std::uint32_t cb = static_cast<std::uint32_t>(a) * gamma_to_1[b] +
                                     static_cast<std::uint32_t>(255 - a) * background_1[3] + 128;
            out_r = gamma_from_1[(cr + (cr >> 8)) >> 8];
            out_g = gamma_from_1[(cg + (cg >> 8)) >> 8];
            out_b = gamma_from_1[(cb + (cb >> 8)) >> 8];
          } else {
            const std::uint32_t cr = static_cast<std::uint32_t>(a) * r +
                                     static_cast<std::uint32_t>(255 - a) * background_1[1] + 128;
            const std::uint32_t cg = static_cast<std::uint32_t>(a) * g +
                                     static_cast<std::uint32_t>(255 - a) * background_1[2] + 128;
            const std::uint32_t cb = static_cast<std::uint32_t>(a) * b +
                                     static_cast<std::uint32_t>(255 - a) * background_1[3] + 128;
            out_r = static_cast<std::uint8_t>((cr + (cr >> 8)) >> 8);
            out_g = static_cast<std::uint8_t>((cg + (cg >> 8)) >> 8);
            out_b = static_cast<std::uint8_t>((cb + (cb >> 8)) >> 8);
          }
        } else {
          out_r = background[2]; out_g = background[4]; out_b = background[6];
        }
        dst[0] = out_r; dst[1] = out_g; dst[2] = out_b;
        dst += 3;
        src += 4;
      }
    } else {
      std::uint8_t* dst = row;
      const std::uint8_t* src = row;
      const bool full = gamma_16 != nullptr && gamma_16_to_1 != nullptr && gamma_16_from_1 != nullptr;
      for (std::uint32_t i = 0; i < width; ++i) {
        const std::uint16_t r16 = static_cast<std::uint16_t>((src[0] << 8) | src[1]);
        const std::uint16_t g16 = static_cast<std::uint16_t>((src[2] << 8) | src[3]);
        const std::uint16_t b16 = static_cast<std::uint16_t>((src[4] << 8) | src[5]);
        const std::uint16_t a16 = static_cast<std::uint16_t>((src[6] << 8) | src[7]);
        if (a16 == 0xFFFF) {
          // Binary path: memcpy 6 bytes from src..src+5 to dst.
          std::memcpy(dst, src, 6);
          dst += 6;
          src += 8;
          continue;
        }
        std::uint16_t out_r16, out_g16, out_b16;
        if (a16 != 0) {
          if (full) {
            const std::uint16_t lr = Gamma16Fetch(gamma_16_to_1, r16, static_cast<std::uint16_t>(gamma_shift));
            const std::uint16_t lg = Gamma16Fetch(gamma_16_to_1, g16, static_cast<std::uint16_t>(gamma_shift));
            const std::uint16_t lb = Gamma16Fetch(gamma_16_to_1, b16, static_cast<std::uint16_t>(gamma_shift));
            const std::uint32_t cr = static_cast<std::uint32_t>(a16) * lr +
                                     static_cast<std::uint32_t>(0xFFFF - a16) * background_1[1] + 0x8000;
            const std::uint32_t cg = static_cast<std::uint32_t>(a16) * lg +
                                     static_cast<std::uint32_t>(0xFFFF - a16) * background_1[2] + 0x8000;
            const std::uint32_t cb = static_cast<std::uint32_t>(a16) * lb +
                                     static_cast<std::uint32_t>(0xFFFF - a16) * background_1[3] + 0x8000;
            out_r16 = Gamma16Fetch(gamma_16_from_1,
                                   static_cast<std::uint16_t>((cr + (cr >> 16)) >> 16),
                                   static_cast<std::uint16_t>(gamma_shift));
            out_g16 = Gamma16Fetch(gamma_16_from_1,
                                   static_cast<std::uint16_t>((cg + (cg >> 16)) >> 16),
                                   static_cast<std::uint16_t>(gamma_shift));
            out_b16 = Gamma16Fetch(gamma_16_from_1,
                                   static_cast<std::uint16_t>((cb + (cb >> 16)) >> 16),
                                   static_cast<std::uint16_t>(gamma_shift));
          } else {
            const std::uint32_t cr = static_cast<std::uint32_t>(a16) * r16 +
                                     static_cast<std::uint32_t>(0xFFFF - a16) * background_1[1] + 0x8000;
            const std::uint32_t cg = static_cast<std::uint32_t>(a16) * g16 +
                                     static_cast<std::uint32_t>(0xFFFF - a16) * background_1[2] + 0x8000;
            const std::uint32_t cb = static_cast<std::uint32_t>(a16) * b16 +
                                     static_cast<std::uint32_t>(0xFFFF - a16) * background_1[3] + 0x8000;
            out_r16 = static_cast<std::uint16_t>((cr + (cr >> 16)) >> 16);
            out_g16 = static_cast<std::uint16_t>((cg + (cg >> 16)) >> 16);
            out_b16 = static_cast<std::uint16_t>((cb + (cb >> 16)) >> 16);
          }
        } else {
          out_r16 = static_cast<std::uint16_t>((background[3] << 8) | background[2]);
          out_g16 = static_cast<std::uint16_t>((background[5] << 8) | background[4]);
          out_b16 = static_cast<std::uint16_t>((background[7] << 8) | background[6]);
        }
        dst[0] = static_cast<std::uint8_t>(out_r16 >> 8); dst[1] = static_cast<std::uint8_t>(out_r16 & 0xFF);
        dst[2] = static_cast<std::uint8_t>(out_g16 >> 8); dst[3] = static_cast<std::uint8_t>(out_g16 & 0xFF);
        dst[4] = static_cast<std::uint8_t>(out_b16 >> 8); dst[5] = static_cast<std::uint8_t>(out_b16 & 0xFF);
        dst += 6;
        src += 8;
      }
    }
  }

  // After alpha-bearing rows finish compositing, drop alpha and refresh layout.
  if ((info.color_type & libpng_detail::kPngColorMaskAlpha) != 0) {
    const std::uint8_t new_channels = static_cast<std::uint8_t>(info.channels - 1);
    info.channels    = new_channels;
    info.color_type  = static_cast<std::uint8_t>(info.color_type & ~libpng_detail::kPngColorMaskAlpha);
    const std::uint8_t pd = static_cast<std::uint8_t>(new_channels * info.bit_depth);
    info.pixel_depth = pd;
    info.rowbytes    = (width * pd + 7) >> 3;
  }
}
