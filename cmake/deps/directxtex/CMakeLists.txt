# DirectXTex may2026 (MIT, LICENSE in the tree): decodes and encodes textures when d3dx11_43.dll
# is missing (gpg/gal/backends/common/ImageCodecDirectXTex.cpp, issue #318). dependencies/DirectXTex
# is the tag's source archive, pinned by SHA256 in cmake/FafDependencies.cmake. A static library of
# its CPU code: no Direct3D 11/12 helpers, no GPU compressor (its shaders aren't built here), no
# OpenMP. FAF_DIRECTXTEX_DIR is for a tree that can't write to its dependencies folder.

set(FAF_DIRECTXTEX_DIR "${FAF_DEPENDENCIES_DIR}/DirectXTex" CACHE PATH "Where the DirectXTex release is unpacked")
set(_dxtex "${FAF_DIRECTXTEX_DIR}/DirectXTex")
if(NOT EXISTS "${_dxtex}/DirectXTex.h")
  message(FATAL_ERROR "Dependencies: DirectXTex not found in ${FAF_DIRECTXTEX_DIR}")
endif()

add_library(faf_directxtex STATIC
  "${_dxtex}/BC.cpp"
  "${_dxtex}/BC4BC5.cpp"
  "${_dxtex}/BC6HBC7.cpp"
  "${_dxtex}/DirectXTexCompress.cpp"
  "${_dxtex}/DirectXTexConvert.cpp"
  "${_dxtex}/DirectXTexDDS.cpp"
  "${_dxtex}/DirectXTexFlipRotate.cpp"
  "${_dxtex}/DirectXTexHDR.cpp"
  "${_dxtex}/DirectXTexImage.cpp"
  "${_dxtex}/DirectXTexMipmaps.cpp"
  "${_dxtex}/DirectXTexMisc.cpp"
  "${_dxtex}/DirectXTexNormalMaps.cpp"
  "${_dxtex}/DirectXTexPMAlpha.cpp"
  "${_dxtex}/DirectXTexResize.cpp"
  "${_dxtex}/DirectXTexTGA.cpp"
  "${_dxtex}/DirectXTexUtil.cpp"
  "${_dxtex}/DirectXTexWIC.cpp")
target_include_directories(faf_directxtex SYSTEM PUBLIC "${_dxtex}")
target_compile_options(faf_directxtex PRIVATE /W0)
target_link_libraries(faf_directxtex PRIVATE faf_codegen PUBLIC windowscodecs ole32)
set_target_properties(faf_directxtex PROPERTIES FOLDER "dependencies")
