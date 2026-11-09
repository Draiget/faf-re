# wxWindows 2.4.2, static MSW Unicode build (wxmswu) and the libraries its
# nmake build archives beside it (png, jpeg, tiff, regex, zlib).
#
# Mirrors `nmake -f makefile.vc FINAL=1 DLL=0 UNICODE=1 NOMAIN=1` in
# dependencies/wxWindows-2.4.2/src/msw (see dependencies/patches/
# wxwindows_2_4_2_faf_required.md): the object lists are the makefiles' own
# (GENERICOBJS, COMMONOBJS, MSWOBJS, HTMLOBJS in src/msw/makefile.vc, OBJECTS
# in src/{png,jpeg,tiff,regex}/makefile.vc, LIBOBJECTS in src/zlib/makefile.vc),
# and the flags are makevc.env's CPPFLAGS for FINAL=1: /O1, no C++ exceptions
# (/GX-), WINVER 0x0400, NOMAIN (the engine has its own WinMain, 0x008D44A0,
# and calls wxEntry itself). The configuration is the tree's lib/mswu/wx/
# setup.h, the copy of include/wx/msw/setup.h the nmake build stamps.
#
# The source tree is shared and read-only here; everything is built into this
# binary directory. The FAF patches (required, x64, x64 pointers) are already
# applied to that tree; the x64 ones are no-ops on Win32.

set(WX_ROOT "${FAF_DEPENDENCIES_DIR}/wxWindows-2.4.2")
set(WX_SRC "${WX_ROOT}/src")
if(NOT EXISTS "${WX_ROOT}/lib/mswu/wx/setup.h")
  message(FATAL_ERROR "wxWindows 2.4.2 not found or not configured: ${WX_ROOT}/lib/mswu/wx/setup.h is missing.")
endif()

# True when the tree carries wxwindows_2_4_2_faf_x64_pointers.patch: only then
# may the x64 image use addresses above 2 GB.
file(STRINGS "${WX_ROOT}/include/wx/defs.h" _wx_pointer_marker
     REGEX "^typedef unsigned __int64 WXWPARAM;" LIMIT_COUNT 1)
if(_wx_pointer_marker)
  set(FAF_WX_X64_POINTERS ON PARENT_SCOPE)
else()
  set(FAF_WX_X64_POINTERS OFF PARENT_SCOPE)
endif()

# Flags every library of the wx build shares (makevc.env WINFLAGS + CPPFLAGS2).
add_library(faf_wx_build_flags INTERFACE)
target_compile_definitions(faf_wx_build_flags INTERFACE
  WIN32 __WIN32__ _WINDOWS WINVER=0x0400 __WIN95__ STRICT
  __WXMSW__ __WINDOWS__ NOMAIN
  # FINAL=1 has no __WXDEBUG__ (makevc.env DEBUG_FLAGS is empty, CRT /MD). A
  # Debug preset compiles against the debug CRT, whose _DEBUG wx/debug.h would
  # turn into __WXDEBUG__; NDEBUG overrides it there, as platform/WxWidgets.h
  # does for the engine's own TUs. Otherwise wxApp::CheckBuildOptions aborts
  # at startup ("library used 2.4 (debug), program used 2.4 (no debug)").
  NDEBUG)
target_include_directories(faf_wx_build_flags INTERFACE
  "${WX_ROOT}/lib/mswu"
  "${WX_ROOT}/include"
  "${WX_ROOT}/contrib/include"
  "${WX_SRC}/regex"
  "${WX_SRC}/png"
  "${WX_SRC}/zlib"
  "${WX_SRC}/jpeg"
  "${WX_SRC}/tiff")
target_compile_options(faf_wx_build_flags INTERFACE
  /O1
  /EHs-c-
  # 2002-era code: keep the build log for the engine's own diagnostics.
  /W0
  # What cl accepts with a warning and clang rejects by default: narrowing in
  # braced initialisers and case labels (wx truncates, as cl did).
  -Wno-c++11-narrowing)
target_link_libraries(faf_wx_build_flags INTERFACE faf_codegen)

function(faf_wx_library name)
  list(TRANSFORM ARGN PREPEND "${WX_SRC}/")
  add_library(${name} STATIC ${ARGN})
  target_link_libraries(${name} PRIVATE faf_wx_build_flags)
  # nmake ran cl without /std, i.e. C++14 (wx 2.4.2 still uses `register`).
  set_target_properties(${name} PROPERTIES FOLDER "dependencies/wxWindows" CXX_STANDARD 14)
endfunction()

# --- zlib 1.1.4 (wx's copy) ------------------------------------------------------
# The engine links this one on Win32, as the shipped exe does; x64 links
# zlib 1.2.3 (cmake/deps/zlib).
faf_wx_library(wx_zlib
  zlib/adler32.c zlib/compress.c zlib/crc32.c zlib/gzio.c zlib/uncompr.c
  zlib/deflate.c zlib/trees.c zlib/zutil.c zlib/inflate.c zlib/infblock.c
  zlib/inftrees.c zlib/infcodes.c zlib/infutil.c zlib/inffast.c)
# src/zlib/makefile.vc builds with its own CFLAGS: -O2, not makevc.env's /O1.
target_compile_options(wx_zlib PRIVATE /O2)

# --- libpng ----------------------------------------------------------------------
faf_wx_library(wx_png
  png/png.c png/pngerror.c png/pngget.c png/pngmem.c png/pngpread.c
  png/pngread.c png/pngrio.c png/pngrtran.c png/pngrutil.c png/pngset.c
  png/pngtrans.c png/pngwio.c png/pngwrite.c png/pngwtran.c png/pngwutil.c)

# --- libjpeg (OBJECTS = CLIBOBJECTS DLIBOBJECTS COMOBJECTS, SYSDEPMEM jmemnobs) ---
faf_wx_library(wx_jpeg
  jpeg/jcapimin.c jpeg/jcapistd.c jpeg/jctrans.c jpeg/jcparam.c jpeg/jdatadst.c
  jpeg/jcinit.c jpeg/jcmaster.c jpeg/jcmarker.c jpeg/jcmainct.c jpeg/jcprepct.c
  jpeg/jccoefct.c jpeg/jccolor.c jpeg/jcsample.c jpeg/jchuff.c jpeg/jcphuff.c
  jpeg/jcdctmgr.c jpeg/jfdctfst.c jpeg/jfdctflt.c jpeg/jfdctint.c
  jpeg/jdapimin.c jpeg/jdapistd.c jpeg/jdtrans.c jpeg/jdatasrc.c jpeg/jdmaster.c
  jpeg/jdinput.c jpeg/jdmarker.c jpeg/jdhuff.c jpeg/jdphuff.c jpeg/jdmainct.c
  jpeg/jdcoefct.c jpeg/jdpostct.c jpeg/jddctmgr.c jpeg/jidctfst.c jpeg/jidctflt.c
  jpeg/jidctint.c jpeg/jidctred.c jpeg/jdsample.c jpeg/jdcolor.c jpeg/jquant1.c
  jpeg/jquant2.c jpeg/jdmerge.c
  jpeg/jcomapi.c jpeg/jutils.c jpeg/jerror.c jpeg/jmemmgr.c jpeg/jmemnobs.c)

# --- libtiff ---------------------------------------------------------------------
faf_wx_library(wx_tiff
  tiff/tif_aux.c tiff/tif_close.c tiff/tif_codec.c tiff/tif_compress.c
  tiff/tif_dir.c tiff/tif_dirinfo.c tiff/tif_dirread.c tiff/tif_dirwrite.c
  tiff/tif_dumpmode.c tiff/tif_error.c tiff/tif_fax3.c tiff/tif_fax3sm.c
  tiff/tif_flush.c tiff/tif_getimage.c tiff/tif_jpeg.c tiff/tif_luv.c
  tiff/tif_lzw.c tiff/tif_next.c tiff/tif_open.c tiff/tif_packbits.c
  tiff/tif_pixarlog.c tiff/tif_predict.c tiff/tif_print.c tiff/tif_read.c
  tiff/tif_strip.c tiff/tif_swab.c tiff/tif_thunder.c tiff/tif_tile.c
  tiff/tif_version.c tiff/tif_warning.c tiff/tif_win32.c tiff/tif_write.c
  tiff/tif_zip.c)

# --- Henry Spencer regex ---------------------------------------------------------
faf_wx_library(wx_regex
  regex/regcomp.c regex/regexec.c regex/regerror.c regex/regfree.c)

# --- wxmswu ----------------------------------------------------------------------
faf_wx_library(wxmswu
  # DUMMYOBJ
  msw/dummy.cpp
  # COMMONOBJS
  common/y_tab.c common/appcmn.cpp common/artprov.cpp common/artstd.cpp
  common/choiccmn.cpp common/clipcmn.cpp common/clntdata.cpp common/cmdline.cpp
  common/cmdproc.cpp common/cmndata.cpp common/config.cpp common/containr.cpp
  common/cshelp.cpp common/ctrlcmn.cpp common/ctrlsub.cpp common/datetime.cpp
  common/datstrm.cpp common/db.cpp common/dbgrid.cpp common/dbtable.cpp
  common/dcbase.cpp common/dircmn.cpp common/dlgcmn.cpp common/dndcmn.cpp
  common/dobjcmn.cpp common/docmdi.cpp common/docview.cpp common/dseldlg.cpp
  common/dynarray.cpp common/dynlib.cpp common/dynload.cpp common/effects.cpp
  common/encconv.cpp common/event.cpp common/extended.c common/fddlgcmn.cpp
  common/ffile.cpp common/file.cpp common/fileconf.cpp common/filefn.cpp
  common/filename.cpp common/filesys.cpp common/fontcmn.cpp common/fontmap.cpp
  common/framecmn.cpp common/fs_inet.cpp common/fs_mem.cpp common/fs_zip.cpp
  common/ftp.cpp common/gaugecmn.cpp common/gdicmn.cpp common/geometry.cpp
  common/gifdecod.cpp common/hash.cpp common/hashmap.cpp common/helpbase.cpp
  common/http.cpp common/iconbndl.cpp common/imagall.cpp common/imagbmp.cpp
  common/image.cpp common/imagfill.cpp common/imaggif.cpp common/imagiff.cpp
  common/imagjpeg.cpp common/imagpcx.cpp common/imagpng.cpp common/imagpnm.cpp
  common/imagtiff.cpp common/imagxpm.cpp common/intl.cpp common/ipcbase.cpp
  common/layout.cpp common/lboxcmn.cpp common/list.cpp common/log.cpp
  common/longlong.cpp common/matrix.cpp common/memory.cpp common/menucmn.cpp
  common/mimecmn.cpp common/module.cpp common/msgout.cpp common/mstream.cpp
  common/nbkbase.cpp common/object.cpp common/odbc.cpp common/paper.cpp
  common/popupcmn.cpp common/prntbase.cpp common/process.cpp common/protocol.cpp
  common/quantize.cpp common/radiocmn.cpp common/regex.cpp common/resource.cpp
  common/rgncmn.cpp common/sckaddr.cpp common/sckfile.cpp common/sckipc.cpp
  common/sckstrm.cpp common/settcmn.cpp common/sizer.cpp common/socket.cpp
  common/statbar.cpp common/strconv.cpp common/stream.cpp common/string.cpp
  common/sysopt.cpp common/tbarbase.cpp common/textbuf.cpp common/textcmn.cpp
  common/textfile.cpp common/timercmn.cpp common/tokenzr.cpp common/toplvcmn.cpp
  common/treebase.cpp common/txtstrm.cpp common/unzip.c common/url.cpp
  common/utilscmn.cpp common/valgen.cpp common/validate.cpp common/valtext.cpp
  common/variant.cpp common/wfstream.cpp common/wincmn.cpp common/wxchar.cpp
  common/wxexpr.cpp common/xpmdecod.cpp common/zipstrm.cpp common/zstream.cpp
  # GENERICOBJS
  generic/busyinfo.cpp generic/calctrl.cpp generic/choicdgg.cpp generic/dcbuffer.cpp
  generic/dcpsg.cpp generic/dirctrlg.cpp generic/dragimgg.cpp generic/grid.cpp
  generic/gridctrl.cpp generic/gridsel.cpp generic/laywin.cpp generic/logg.cpp
  generic/numdlgg.cpp generic/panelg.cpp generic/progdlgg.cpp generic/prop.cpp
  generic/propform.cpp generic/proplist.cpp generic/sashwin.cpp generic/scrlwing.cpp
  generic/spinctlg.cpp generic/splash.cpp generic/splitter.cpp generic/statusbr.cpp
  generic/tbarsmpl.cpp generic/textdlgg.cpp generic/tipdlg.cpp generic/tipwin.cpp
  generic/treelistctrl.cpp generic/treectlg.cpp generic/treelay.cpp generic/wizard.cpp
  # MSWOBJS
  msw/accel.cpp msw/app.cpp msw/ole/automtn.cpp msw/bitmap.cpp msw/bmpbuttn.cpp
  msw/brush.cpp msw/button.cpp msw/caret.cpp msw/checkbox.cpp msw/checklst.cpp
  msw/choice.cpp msw/clipbrd.cpp msw/colordlg.cpp msw/colour.cpp msw/combobox.cpp
  msw/control.cpp msw/curico.cpp msw/cursor.cpp msw/data.cpp msw/ole/dataobj.cpp
  msw/dc.cpp msw/dcclient.cpp msw/dcmemory.cpp msw/dcprint.cpp msw/dcscreen.cpp
  msw/dde.cpp msw/dialog.cpp msw/dialup.cpp msw/dib.cpp msw/dibutils.cpp
  msw/dir.cpp msw/dirdlg.cpp msw/dragimag.cpp msw/ole/dropsrc.cpp msw/ole/droptgt.cpp
  msw/enhmeta.cpp msw/evtloop.cpp msw/fdrepdlg.cpp msw/filedlg.cpp msw/font.cpp
  msw/fontdlg.cpp msw/fontenum.cpp msw/fontutil.cpp msw/frame.cpp msw/gauge95.cpp
  msw/gdiimage.cpp msw/gdiobj.cpp msw/glcanvas.cpp msw/gsocket.c msw/gsockmsw.c
  msw/helpbest.cpp msw/helpchm.cpp msw/helpwin.cpp msw/icon.cpp msw/imaglist.cpp
  msw/iniconf.cpp msw/joystick.cpp msw/listbox.cpp msw/listctrl.cpp msw/main.cpp
  msw/mdi.cpp msw/menu.cpp msw/menuitem.cpp msw/metafile.cpp msw/mimetype.cpp
  msw/minifram.cpp msw/msgdlg.cpp msw/mslu.cpp msw/nativdlg.cpp msw/notebook.cpp
  msw/ole/oleutils.cpp msw/ownerdrw.cpp msw/palette.cpp msw/pen.cpp msw/penwin.cpp
  msw/popupwin.cpp msw/printdlg.cpp msw/printwin.cpp msw/radiobox.cpp msw/radiobut.cpp
  msw/regconf.cpp msw/region.cpp msw/registry.cpp msw/scrolbar.cpp msw/settings.cpp
  msw/slider95.cpp msw/snglinst.cpp msw/spinbutt.cpp msw/spinctrl.cpp msw/statbmp.cpp
  msw/statbox.cpp msw/statbr95.cpp msw/statline.cpp msw/stattext.cpp msw/tabctrl.cpp
  msw/taskbar.cpp msw/tbar95.cpp msw/textctrl.cpp msw/tglbtn.cpp msw/thread.cpp
  msw/timer.cpp msw/tooltip.cpp msw/toplevel.cpp msw/treectrl.cpp msw/utils.cpp
  msw/utilsexc.cpp msw/ole/uuid.cpp msw/uxtheme.cpp msw/volume.cpp msw/wave.cpp
  msw/window.cpp
  # HTMLOBJS
  html/helpctrl.cpp html/helpdata.cpp html/helpfrm.cpp html/htmlcell.cpp
  html/htmlfilt.cpp html/htmlpars.cpp html/htmltag.cpp html/htmlwin.cpp
  html/htmprint.cpp html/m_dflist.cpp html/m_fonts.cpp html/m_hline.cpp
  html/m_image.cpp html/m_layout.cpp html/m_links.cpp html/m_list.cpp
  html/m_pre.cpp html/m_style.cpp html/m_tables.cpp html/winpars.cpp)
# The y_tab.obj rule: `cl $(CPPFLAGS2) /c y_tab.c -DUSE_DEFINE -DYY_USE_PROTOS`.
set_source_files_properties("${WX_SRC}/common/y_tab.c" TARGET_DIRECTORY wxmswu
  PROPERTIES COMPILE_DEFINITIONS "USE_DEFINE;YY_USE_PROTOS")

# What the engine compiles and links against.
add_library(faf_wx INTERFACE)
add_library(faf::wx ALIAS faf_wx)
target_include_directories(faf_wx INTERFACE "${WX_ROOT}/include" "${WX_ROOT}/lib/mswu")
target_link_libraries(faf_wx INTERFACE wxmswu wx_regex wx_png wx_jpeg wx_tiff
  # makevc.env WINLIBS: the system libraries wx itself calls into.
  comctl32 comdlg32 winspool winmm shell32 ole32 oleaut32 uuid rpcrt4 advapi32 wsock32 odbc32)
set(FAF_WX_INCLUDE_DIR "${WX_ROOT}/include" PARENT_SCOPE)
