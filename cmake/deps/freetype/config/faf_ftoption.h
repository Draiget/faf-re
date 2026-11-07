/* FreeType's options, minus everything MSDF text doesn't use (issue #305): a font can come from a
 * mod, so a parser that isn't compiled in can't be attacked. Outlines load with FT_LOAD_NO_SCALE. */
#ifndef FAF_FTOPTION_H
#define FAF_FTOPTION_H

#include <freetype/config/ftoption.h>

/* No settings from the FREETYPE_PROPERTIES environment variable. */
#undef FT_CONFIG_OPTION_ENVIRONMENT_PROPERTIES

/* No compressed or Mac-wrapped font files; only plain sfnt files reach FreeType. */
#undef FT_CONFIG_OPTION_USE_LZW
#undef FT_CONFIG_OPTION_USE_ZLIB
#undef FT_CONFIG_OPTION_MAC_FONTS
#undef FT_CONFIG_OPTION_GUESSING_EMBEDDED_RFORK
#undef FT_CONFIG_OPTION_INCREMENTAL

/* No embedded bitmaps, colour layers or SVG glyphs: outlines only. */
#undef FT_CONFIG_OPTION_SVG
#undef TT_CONFIG_OPTION_EMBEDDED_BITMAPS
#undef TT_CONFIG_OPTION_COLOR_LAYERS
#undef TT_CONFIG_OPTION_BDF

/* A font's hinting programs don't run: no bytecode interpreter. */
#undef TT_CONFIG_OPTION_BYTECODE_INTERPRETER
#undef TT_CONFIG_OPTION_SUBPIXEL_HINTING

/* Variable fonts load at their default instance. CVE-2025-27363 was in this code. */
#undef TT_CONFIG_OPTION_GX_VAR_SUPPORT
#undef TT_CONFIG_OPTION_VARC

#endif
