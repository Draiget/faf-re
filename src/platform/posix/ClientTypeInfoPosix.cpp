// Engine addition (dedicated-server plan WPL.5, WPL.6): the type_info objects of client
// classes the simulation names but never instantiates, for the Linux build.
//
// The sim registers reflection types and Lua conversions keyed by `typeid(T)` for a few user
// world classes (moho::UserUnit: UserUnitTypeInfo.cpp, SCR_FromLua_UserUnit). MSVC emits a
// class's type descriptor in every object that uses typeid; the Itanium ABI emits it only with
// the vtable, in the translation unit of the class's key function - here a client file the
// Linux build leaves out. The definitions below are static data (no initialiser to order):
// a plain __class_type_info with the class's mangled name, enough for typeid's identity
// (name, ==, hash). No object of these classes exists in the Linux programs, so nothing
// dynamic_casts through them.

#if !defined(_WIN32)

// FAF_CLIENT_TYPEINFO(mangled name): typeinfo `_ZTI<name>` and its name string `_ZTS<name>`.
#define FAF_CLIENT_TYPEINFO(NAME)                                         \
  asm(".section .rodata._ZTS" NAME ",\"aG\",@progbits,_ZTS" NAME ",comdat\n" \
      ".weak _ZTS" NAME "\n"                                              \
      "_ZTS" NAME ":\n"                                                   \
      ".asciz \"" NAME "\"\n"                                             \
      ".section .data.rel.ro._ZTI" NAME ",\"awG\",@progbits,_ZTI" NAME ",comdat\n" \
      ".weak _ZTI" NAME "\n"                                              \
      ".p2align 3\n"                                                      \
      "_ZTI" NAME ":\n"                                                   \
      ".quad _ZTVN10__cxxabiv117__class_type_infoE+16\n"                  \
      ".quad _ZTS" NAME "\n"                                              \
      ".text\n");

FAF_CLIENT_TYPEINFO("N4moho8UserUnitE")

#endif // !defined(_WIN32)
