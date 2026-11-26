# faf-re-lua.nx2: FAF UI Lua that faf-re ships until FAF releases it (data/fa-lua, written by
# tools/fa-lua/refresh.py; the engine side is src/moho/misc/FafLuaOverrides.h). The archive is a
# zip of manifest.txt and files/, packed again whenever one of them changes, and copied next to
# the executable of every target passed to faf_stage_fa_lua_archive.

include_guard(GLOBAL)

set(_faf_fa_lua_dir "${PROJECT_SOURCE_DIR}/data/fa-lua")
# A cache entry, not a plain variable: include_guard keeps a second include() (tests/) from
# running this file again, and a plain variable would exist only in the first one's directory.
set(FAF_FA_LUA_ARCHIVE "${CMAKE_BINARY_DIR}/fa-lua/faf-re-lua.nx2" CACHE INTERNAL "faf-re-lua.nx2 as the build packs it")
file(GLOB_RECURSE _faf_fa_lua_files CONFIGURE_DEPENDS "${_faf_fa_lua_dir}/files/*")

# Sorted names and a fixed time stamp (faf_pack_zip), so the same files give the same archive.
list(SORT _faf_fa_lua_files)
set(_faf_fa_lua_entries "manifest.txt")
foreach(_file IN LISTS _faf_fa_lua_files)
  file(RELATIVE_PATH _entry "${_faf_fa_lua_dir}" "${_file}")
  list(APPEND _faf_fa_lua_entries "${_entry}")
endforeach()

# Not `cmake -E tar --format=zip`: its entries leave their sizes to a data descriptor, which the
# engine's zip reader skips, as the shipped game's does (tools/fa-lua/pack_zip.cpp).
add_executable(faf_pack_zip "${PROJECT_SOURCE_DIR}/tools/fa-lua/pack_zip.cpp")
set_target_properties(faf_pack_zip PROPERTIES FOLDER "Tools")

add_custom_command(
  OUTPUT "${FAF_FA_LUA_ARCHIVE}"
  COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_BINARY_DIR}/fa-lua"
  COMMAND "$<TARGET_FILE:faf_pack_zip>" "${FAF_FA_LUA_ARCHIVE}" "${_faf_fa_lua_dir}" ${_faf_fa_lua_entries}
  DEPENDS faf_pack_zip "${_faf_fa_lua_dir}/manifest.txt" ${_faf_fa_lua_files}
  COMMENT "Packing faf-re-lua.nx2"
  VERBATIM)
add_custom_target(faf_fa_lua_archive DEPENDS "${FAF_FA_LUA_ARCHIVE}")
# Puts the archive in `directory` (the folder `target`'s executable is built into) on every build,
# also when only the Lua changed and the executable isn't linked again.
function(faf_stage_fa_lua_archive target directory)
  set(_staged "${directory}/faf-re-lua.nx2")
  add_custom_command(
    OUTPUT "${_staged}"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${FAF_FA_LUA_ARCHIVE}" "${_staged}"
    DEPENDS "${FAF_FA_LUA_ARCHIVE}"
    VERBATIM)
  add_custom_target(${target}_fa_lua DEPENDS "${_staged}")
  add_dependencies(${target} ${target}_fa_lua)
endfunction()
