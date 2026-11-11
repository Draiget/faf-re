// Engine addition (issue #255): stb_image and stb_image_write's implementations for the Linux
// client, which reads and writes PNG, BMP and JPG with them where Windows uses WIC
// (gpg/gal/backends/common/ImageCodecDirectXTex.cpp). Only the formats the game uses are built.

#define STBI_ONLY_PNG
#define STBI_ONLY_BMP
#define STBI_ONLY_JPEG
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "stb_image_write.h"
