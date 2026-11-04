// The direct-call lane for the spec rows: a machine-code builder that turns
// one spec entry into a cdecl stub (in -> the ABI the spec describes -> out),
// so a whole spec file of retail functions is callable without a hand-written
// thunk each. See spec_stub.h, SPEC_FORMAT.md and the difffuzz README.
//
// ABI notes (x86):
// - A register argument is set before the stack arguments are pushed (the
//   pushes must not clobber a register already loaded; each register is
//   written once, and the push sequence touches only esp).
// - Float stack arguments: the MSVC8 game passes floats and doubles on the
//   stack as their raw 4/8 bytes (cdecl), never through st0; a prototype's
//   st0 arguments are Hex-Rays' guess at an __stdcall register passing.
// - The result is read from eax / edx:eax / st0 as the spec says; st0 is
//   stored with fstp, and a NaN output is canonicalised by the caller.
// - The retail entry is called with a `call` through a register, and after it
//   returns the stub executes a plain `ret` while esp points past the last
//   pushed dword, so a callee-pops entry leaves its own pop bytes on the
//   stack; the epilogue restores esp from ebp, so nothing leaks either way.

#include "spec_stub.h"

#include <cstring>

namespace difffuzz
{
  namespace spec
  {
    // Register encodings for the mod/rm and SIB-free forms used below.
    constexpr unsigned kRegEax = 0, kRegEcx = 1, kRegEdx = 2, kRegEbx = 3, kRegEsp = 4, kRegEbp = 5, kRegEsi = 6, kRegEdi = 7;

    int BuildStub(const Entry& entry, unsigned char* code)
    {
      unsigned char* p = code;

      const auto emit8 = [&p](const unsigned char b) { *p++ = b; };
      const auto emit32 = [&p](const std::uint32_t v) {
        std::memcpy(p, &v, 4);
        p += 4;
      };
      // mov reg, imm32
      const auto movRegImm = [&](const unsigned reg, const std::uint32_t v) {
        emit8(0xB8 + reg);
        emit32(v);
      };
      // mov reg, [ebp+8] (the `in` pointer); mov reg, [reg + 4*wordIndex].
      // The cdecl stub's first argument is the pointer, so the words are one
      // dereference away. 4*wordIndex < 128 (kMaxSpecWords), so disp8 fits.
      const auto loadIn = [&](const int wordIndex, const unsigned reg) {
        emit8(0x8B);
        emit8(static_cast<unsigned char>(0x45 | (reg << 3))); // mov reg, [ebp+8]
        emit8(0x08);
        emit8(0x8B);
        emit8(static_cast<unsigned char>(0x40 | (reg << 3))); // mov reg, [reg+disp8]
        emit8(static_cast<unsigned char>(4 * wordIndex));
      };

      // Prologue: push ebp; mov ebp, esp; push ebx; push esi; push edi; sub esp, N
      emit8(0x55); // push ebp
      emit8(0x8B); emit8(0xEC); // mov ebp, esp
      emit8(0x53); // push ebx
      emit8(0x56); // push esi
      emit8(0x57); // push edi

      // Count the stack words the ABI needs.
      int stackWords = 0;
      for (const Arg& a : entry.args) {
        if ((a.location & 0x80u) != 0u) {
          stackWords += a.words;
        }
      }
      if (stackWords > 0) {
        emit8(0x81); emit8(0xEC); emit32(static_cast<std::uint32_t>(stackWords * 4)); // sub esp, N
      }

      // Stack arguments: spec slot n (0x80|n) is the nth dword above the
      // callee's return address, i.e. callee [esp+4+4n] = pre-call [esp+4n].
      // The `in` word order for a multi-word argument is little-endian:
      // in[i], in[i+1]. eax is scratch here (a register argument is loaded
      // only after this loop).
      int nextIn = 0;
      for (const Arg& a : entry.args) {
        const int words = a.words;
        if ((a.location & 0x80u) == 0u) {
          nextIn += words;
          continue;
        }
        const int slot = a.location & 0x7Fu; // stack dword index above the return address
        for (int w = 0; w < words; ++w) {
          // mov eax, in[nextIn]; mov [esp + 4*(slot+w)], eax
          loadIn(nextIn, kRegEax);
          const int offset = 4 * (slot + w);
          emit8(0x89); // mov [esp or esp+disp8], eax (rm=100: SIB follows)
          emit8(offset == 0 ? 0x04 : 0x44);
          emit8(0x24); // SIB: base esp, no index
          if (offset != 0) {
            emit8(static_cast<unsigned char>(offset));
          }
          ++nextIn;
        }
      }

      // Register arguments: the selector keeps register-argument entries out
      // of the auto rows, so a selected stub has none; the loader stays for a
      // hand-run against a review-list entry and writes the word into the
      // register the spec names.
      int regIn = nextIn;
      for (const Arg& a : entry.args) {
        if ((a.location & 0x80u) != 0u || a.location > 6) {
          continue;
        }
        loadIn(regIn, a.location);
        ++regIn;
      }

      // Call the retail entry through ebx (saved in the prologue; the
      // selector keeps register-argument entries out of the auto rows, so no
      // selected stub has an input in ebx).
      movRegImm(kRegEbx, entry.va); // the image is mapped at the VA
      // call ebx
      emit8(0xFF);
      emit8(0xD3);

      // Result: eax, edx:eax, or st0 stored through a saved pointer.
      // For st0: outWords at ebp+12. Store with fstp dword/qword [edi], with
      // edi = outWords loaded before the call (edi is not an argument register
      // in the selected rows; it is saved in the prologue).
      if (entry.ret == kRetSt0Float || entry.ret == kRetSt0Double) {
        // mov edi, [ebp+12]
        emit8(0x8B); emit8(0x7D); emit8(0x0C);
        if (entry.ret == kRetSt0Float) {
          emit8(0xD9); emit8(0x1F); // fstp dword ptr [edi]
        } else {
          emit8(0xDD); emit8(0x1F); // fstp qword ptr [edi]
        }
      } else if (entry.ret == kRetEdxEax) {
        // mov edi, [ebp+12]; mov [edi], eax; mov [edi+4], edx
        emit8(0x8B); emit8(0x7D); emit8(0x0C);
        emit8(0x89); emit8(0x07);
        emit8(0x89); emit8(0x57); emit8(0x04);
      } else if (entry.ret == kRetEax) {
        emit8(0x8B); emit8(0x7D); emit8(0x0C); // mov edi, [ebp+12]
        emit8(0x89); emit8(0x07); // mov [edi], eax
      }
      // A callee-pops entry has already advanced esp past its arguments, so
      // esp is restored from the frame, never incremented by hand.
      emit8(0x8D); emit8(0x65); emit8(0xF4); // lea esp, [ebp-12]
      emit8(0x5F); // pop edi
      emit8(0x5E); // pop esi
      emit8(0x5B); // pop ebx
      emit8(0x5D); // pop ebp
      emit8(0xC3); // ret

      return static_cast<int>(p - code);
    }
  } // namespace spec
} // namespace difffuzz
