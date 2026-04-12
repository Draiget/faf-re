#pragma once

#include <cstddef>
#include <cstdint>

#include "libpng/PngCommonRuntime.h"  // png_memcmp
#include "libpng/PngInfoRuntime.h"    // png_infop, png_infopp
#include "libpng/PngWriteRuntime.h"

// ============================================================================
// libpng read-side runtime helpers recovered from ForgedAlliance.exe.
//
// Evidence lives alongside the implementation; field-level png_struct access
// is routed through the typed views defined in PngStructRuntime.h.
// ============================================================================

/**
 * Address: 0x009E09AA (FUN_009E09AA)
 *
 * IDA signature:
 * void *__cdecl png_get_io_ptr(png_structp png_ptr);
 *
 * What it does:
 * Returns the user-supplied IO state pointer stored inside png_struct. The
 * wxWidgets PNG handler uses this to recover its wxPNGInfoStruct from inside
 * read/write/error/warning callbacks.
 */
extern "C" void* png_get_io_ptr(png_structp png_ptr);

/**
 * Address: 0x009E0A5E (FUN_009E0A5E)
 *
 * IDA signature:
 * int __cdecl png_handle_as_unknown(png_structp png_ptr, const png_byte *chunk_name);
 *
 * What it does:
 * Looks up how a PNG chunk should be handled according to the user-registered
 * "keep" list (png_set_keep_unknown_chunks). Scans the 5-byte-per-entry keep
 * table in reverse, returning the stored keep value (last-match-wins) for a
 * matching 4-byte chunk name. Returns 0 when the table is empty, either
 * argument is null, or no entry matches.
 */
extern "C" int png_handle_as_unknown(png_structp png_ptr, const std::uint8_t* chunk_name);

/**
 * Address: 0x009E0ACC (FUN_009E0ACC)
 *
 * IDA signature:
 * void __cdecl png_init_mmx_flags(png_structp png_ptr);
 *
 * What it does:
 * Zeroes the MMX-assembly dispatch fields on png_struct (asm_flags low byte,
 * mmx_bitdepth_threshold, mmx_rowbytes_threshold). Called from
 * png_create_read_struct_2 / png_create_write_struct_2 when the MMX assembly
 * path is disabled at runtime, effectively turning off all MMX code routes.
 */
extern "C" void png_init_mmx_flags(png_structp png_ptr);

// libpng external function pointer typedefs.
using png_error_ptr  = void (*)(png_structp, const char*);
using png_malloc_ptr = void* (*)(png_structp, std::uint32_t);
using png_free_ptr   = void  (*)(png_structp, void*);
using png_voidp      = void*;

/**
 * Address: 0x009E0AE9 (FUN_009E0AE9)
 * Mangled: png_create_info_struct
 *
 * IDA signature:
 * png_infop __cdecl png_create_info_struct(png_structp png_ptr);
 *
 * What it does:
 * Allocates and zero-initialises a fresh png_info struct, using the
 * memory functions stored on png_ptr (mem_ptr / malloc_fn at offsets
 * 0x244 / 0x248). Returns nullptr if the allocator fails. Forwarded
 * through png_create_struct_2 + png_info_init_3.
 */
extern "C" png_infop png_create_info_struct(png_structp png_ptr);

/**
 * Address: 0x009E0B6E (FUN_009E0B6E)
 * Mangled: png_create_read_struct_2
 *
 * IDA signature:
 * png_structp __cdecl png_create_read_struct_2(
 *     png_const_charp user_png_ver,
 *     png_voidp error_ptr,
 *     png_error_ptr error_fn,
 *     png_error_ptr warn_fn,
 *     png_voidp mem_ptr,
 *     png_malloc_ptr malloc_fn,
 *     png_free_ptr free_fn);
 *
 * What it does:
 * Allocates and initialises a libpng read-side png_struct. Resets the MMX
 * flags, installs user mem/error callbacks, validates the application-side
 * libpng version against the embedded "1.2.5rc3" string (warning + fatal on
 * mismatch), allocates the 0x2000-byte zlib input buffer, wires the libpng
 * zalloc/zfree thunks into the zstream, runs zlib inflateInit_, and finally
 * installs the default read callback. Returns nullptr if the initial alloc
 * fails or the setjmp recovery branch fires.
 */
extern "C" png_structp png_create_read_struct_2(
  const char*    user_png_ver,
  void*          error_ptr,
  png_error_ptr  error_fn,
  png_error_ptr  warn_fn,
  void*          mem_ptr,
  png_malloc_ptr malloc_fn,
  png_free_ptr   free_fn
);

/**
 * Address: 0x009E1FED (FUN_009E1FED)
 * Mangled: png_create_read_struct
 *
 * IDA signature:
 * png_structp __cdecl png_create_read_struct(
 *     png_const_charp user_png_ver,
 *     png_voidp error_ptr,
 *     png_error_ptr error_fn,
 *     png_error_ptr warn_fn);
 *
 * What it does:
 * Convenience wrapper that calls png_create_read_struct_2 with NULL
 * mem_ptr / malloc_fn / free_fn (using libpng's default allocator).
 */
extern "C" png_structp png_create_read_struct(
  const char*   user_png_ver,
  void*         error_ptr,
  png_error_ptr error_fn,
  png_error_ptr warn_fn
);

/**
 * Address: 0x009E1383 (FUN_009E1383)
 * Mangled: png_read_row
 *
 * IDA signature:
 * void __cdecl png_read_row(png_structp png_ptr, png_bytep row, png_bytep dsp_row);
 *
 * What it does:
 * Reads and decodes one image row from the libpng read state. Handles the
 * Adam7 interlace pass skip table, drives zlib inflate against the IDAT
 * chunk stream (chasing CRC tails and consuming consecutive IDATs as
 * needed), unfilters the freshly inflated row, runs the optional intrapixel
 * MNG transformation, applies the configured read transformations, and
 * combines the produced row into both the user row and dsp_row buffers
 * according to the current pass mask. Finally calls the optional row
 * notification callback if installed.
 */
extern "C" void png_read_row(png_structp png_ptr, std::uint8_t* row, std::uint8_t* dsp_row);

/**
 * Address: 0x009E1809 (FUN_009E1809)
 * Mangled: png_read_image
 *
 * IDA signature:
 * void __cdecl png_read_image(png_structp png_ptr, png_bytepp image);
 *
 * What it does:
 * Reads an entire PNG image (all interlace passes) into the supplied row
 * pointer table. Calls png_set_interlace_handling to determine the number
 * of passes (1 or 7), then walks every pass / row pair calling png_read_row
 * with dsp_row=nullptr.
 */
extern "C" void png_read_image(png_structp png_ptr, std::uint8_t** image);

/**
 * Address: 0x009E0E93 (FUN_009E0E93)
 * Mangled: png_read_info
 *
 * IDA signature:
 * void __cdecl png_read_info(png_structp png_ptr, png_infop info_ptr);
 *
 * What it does:
 * Reads the leading PNG chunks (signature + IHDR + ancillary chunks up to
 * the first IDAT). Validates the 8-byte file signature, then loops chunk
 * headers running per-chunk handlers (png_handle_IHDR, png_handle_PLTE,
 * png_handle_*) until the first IDAT is encountered. The IDAT chunk is
 * left undeleted in the input stream so png_read_row can take over.
 */
extern "C" void png_read_info(png_structp png_ptr, png_infop info_ptr);

/**
 * Address: 0x009E1856 (FUN_009E1856)
 * Mangled: png_read_end
 *
 * IDA signature:
 * void __cdecl png_read_end(png_structp png_ptr, png_infop info_ptr);
 *
 * What it does:
 * Consumes any chunks following the IDAT stream up to and including IEND.
 * Per-chunk dispatch routes ancillary chunks to their dedicated handlers
 * (bKGD, cHRM, gAMA, hIST, oFFs, pCAL, sCAL, pHYs, sBIT, sRGB, iCCP, sPLT,
 * tEXt, tIME, tRNS, zTXt) and unknown chunks through png_handle_unknown.
 */
extern "C" void png_read_end(png_structp png_ptr, png_infop info_ptr);

/**
 * Address: 0x009E1C4A (FUN_009E1C4A)
 * Mangled: png_read_destroy
 *
 * IDA signature:
 * void __cdecl png_read_destroy(png_structp png_ptr, png_infop info_ptr, png_infop end_info_ptr);
 *
 * What it does:
 * Tears down a libpng read state. Releases the optional info / end_info
 * structs, frees every dynamically-allocated buffer the read path may
 * have created (transformation tables, palette, gamma tables, IDAT
 * scratch, history rows, …), unwinds the inflate stream, and finally
 * zero-resets the png_struct in place while preserving the jmpbuf, the
 * memory function pointers, and the error handler slots.
 */
extern "C" void png_read_destroy(png_structp png_ptr, png_infop info_ptr, png_infop end_info_ptr);

/**
 * Address: 0x009E20D5 (FUN_009E20D5)
 * Mangled: png_destroy_read_struct
 *
 * IDA signature:
 * void __cdecl png_destroy_read_struct(
 *     png_structpp png_ptr_ptr, png_infopp info_ptr_ptr, png_infopp end_info_ptr_ptr);
 *
 * What it does:
 * Releases a libpng read state allocated by png_create_read_struct[_2],
 * along with its optional info / end_info structures. Forwards through
 * png_read_destroy and the matching png_free_data + png_destroy_struct_2
 * pair, then nulls out the caller's pointer slots so the API contract is
 * upheld even if the caller forgets.
 */
extern "C" void png_destroy_read_struct(
  png_structp* png_ptr_ptr,
  png_infop*   info_ptr_ptr,
  png_infop*   end_info_ptr_ptr
);
