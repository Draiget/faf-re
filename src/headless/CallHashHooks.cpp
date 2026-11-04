// The hooks -finstrument-functions calls in a FAF_CALL_HASH_BUILD (CMakeLists.txt). They do
// nothing: the flag is there because its entry call takes each function's address, which keeps
// each internal function's calling convention and parameters as its PDB signature says.
extern "C" __attribute__((no_instrument_function)) void __cyg_profile_func_enter(void*, void*) {}
extern "C" __attribute__((no_instrument_function)) void __cyg_profile_func_exit(void*, void*) {}
