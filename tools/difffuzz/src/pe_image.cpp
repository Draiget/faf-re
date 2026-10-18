#include "pe_image.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace difffuzz
{
  namespace
  {
    constexpr std::uint32_t kExpectedBase = 0x00400000u;
    constexpr DWORD kImportTrapException = 0xE0F1A001u;

    std::vector<std::string> gImportNames;

    /**
     * Reached from a per-import stub (`push index; mov eax, ImportTrap;
     * call eax`): the stub's own call pushed a return into the stub, and the
     * retail caller's return address sits one slot above the index.
     */
    extern "C" void __cdecl ImportTrap(const std::uint32_t index, const std::uint32_t callerReturn)
    {
      const char* const name = index < gImportNames.size() ? gImportNames[index].c_str() : "?";
      std::fprintf(stderr, "  !! unresolved import %s (called from retail 0x%08X)\n", name, callerReturn);
      std::fflush(stderr);
      RaiseException(kImportTrapException, 0, 0, nullptr);
    }

    [[nodiscard]] DWORD SectionProtection(const DWORD characteristics) noexcept
    {
      const bool exec = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
      const bool write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
      if (exec) {
        return write ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
      }
      return write ? PAGE_READWRITE : PAGE_READONLY;
    }

    void DescribeRegion(const std::uint32_t va, std::string& error)
    {
      MEMORY_BASIC_INFORMATION mbi{};
      if (VirtualQuery(reinterpret_cast<void*>(static_cast<std::uintptr_t>(va)), &mbi, sizeof(mbi)) != 0) {
        char buf[256];
        std::snprintf(
          buf, sizeof(buf), " (VirtualQuery 0x%08X: state=0x%lX base=0x%p size=0x%IX type=0x%lX)", va, mbi.State,
          mbi.AllocationBase, mbi.RegionSize, mbi.Type
        );
        error += buf;
      }
    }
  } // namespace

  bool RetailImage::Load(const std::string& path, std::string& error)
  {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
      error = "cannot open " + path;
      return false;
    }
    const std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (bytes.size() < sizeof(IMAGE_DOS_HEADER)) {
      error = "file too small";
      return false;
    }

    const auto* const dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > bytes.size()) {
      error = "not an MZ image";
      return false;
    }
    const auto* const nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_I386
        || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
      error = "not a PE32 i386 image";
      return false;
    }
    const IMAGE_OPTIONAL_HEADER32& opt = nt->OptionalHeader;
    if (opt.ImageBase != kExpectedBase) {
      error = "unexpected ImageBase (this loader does not relocate)";
      return false;
    }

    // MEM_RESERVE|MEM_COMMIT at exactly the preferred base; the image has no
    // .reloc, so it only works mapped there.
    void* const want = reinterpret_cast<void*>(static_cast<std::uintptr_t>(opt.ImageBase));
    void* mapped = VirtualAlloc(want, opt.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (mapped == nullptr) {
      // A launcher parent may already have committed the range for us
      // (RelaunchWithPreclaimedImage): accept exactly that allocation.
      MEMORY_BASIC_INFORMATION mbi{};
      if (VirtualQuery(want, &mbi, sizeof(mbi)) != 0 && mbi.AllocationBase == want && mbi.Type == MEM_PRIVATE
          && mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE && mbi.RegionSize >= opt.SizeOfImage) {
        mapped = want;
      }
    }
    if (mapped != want) {
      char buf[160];
      std::snprintf(
        buf, sizeof(buf), "VirtualAlloc(0x%08lX, 0x%lX) failed (GetLastError=%lu): the retail image range is taken",
        opt.ImageBase, opt.SizeOfImage, GetLastError()
      );
      error = buf;
      DescribeRegion(opt.ImageBase, error);
      return false;
    }
    auto* const base = static_cast<std::uint8_t*>(mapped);
    mBase = opt.ImageBase;
    mSizeOfImage = opt.SizeOfImage;

    std::memcpy(base, bytes.data(), opt.SizeOfHeaders);
    const IMAGE_SECTION_HEADER* const sections = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
      const IMAGE_SECTION_HEADER& s = sections[i];
      const DWORD rawCopy = s.SizeOfRawData < s.Misc.VirtualSize || s.Misc.VirtualSize == 0 ? s.SizeOfRawData
                                                                                             : s.Misc.VirtualSize;
      if (rawCopy != 0) {
        if (static_cast<std::size_t>(s.PointerToRawData) + rawCopy > bytes.size()) {
          error = "section raw data past end of file";
          return false;
        }
        std::memcpy(base + s.VirtualAddress, bytes.data() + s.PointerToRawData, rawCopy);
      }
    }

    // Imports: leave every IAT slot pointing at a trap stub.
    const IMAGE_DATA_DIRECTORY& importDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress != 0) {
      std::vector<std::uint32_t*> slots;
      for (auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + importDir.VirtualAddress);
           desc->Name != 0; ++desc) {
        const char* const dll = reinterpret_cast<const char*>(base + desc->Name);
        const DWORD lookupRva = desc->OriginalFirstThunk != 0 ? desc->OriginalFirstThunk : desc->FirstThunk;
        auto* lookup = reinterpret_cast<const std::uint32_t*>(base + lookupRva);
        auto* iat = reinterpret_cast<std::uint32_t*>(base + desc->FirstThunk);
        for (; *lookup != 0; ++lookup, ++iat) {
          std::string name = dll;
          if ((*lookup & IMAGE_ORDINAL_FLAG32) != 0) {
            name += "!#" + std::to_string(*lookup & 0xFFFFu);
          } else {
            name += "!";
            name += reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + *lookup)->Name;
          }
          gImportNames.push_back(std::move(name));
          slots.push_back(iat);
        }
      }

      // push imm32 (5) ; mov eax, imm32 (5) ; call eax (2) ; pad to 16.
      constexpr std::size_t kStubSize = 16;
      auto* const stubs = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, slots.size() * kStubSize + 16, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)
      );
      if (stubs == nullptr) {
        error = "cannot allocate import trap stubs";
        return false;
      }
      const auto trap = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&ImportTrap));
      for (std::size_t i = 0; i < slots.size(); ++i) {
        std::uint8_t* p = stubs + i * kStubSize;
        const auto index = static_cast<std::uint32_t>(i);
        *p++ = 0x68;
        std::memcpy(p, &index, 4);
        p += 4;
        *p++ = 0xB8;
        std::memcpy(p, &trap, 4);
        p += 4;
        *p++ = 0xFF;
        *p++ = 0xD0;
        while (p < stubs + (i + 1) * kStubSize) {
          *p++ = 0xCC;
        }
        *slots[i] = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(stubs + i * kStubSize));
      }
      mImportCount = static_cast<unsigned>(slots.size());
    }

    // Page protections: headers read-only, sections per their characteristics.
    DWORD oldProtect = 0;
    VirtualProtect(base, opt.SizeOfHeaders, PAGE_READONLY, &oldProtect);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
      const IMAGE_SECTION_HEADER& s = sections[i];
      const DWORD size = s.Misc.VirtualSize != 0 ? s.Misc.VirtualSize : s.SizeOfRawData;
      if (size != 0 && !VirtualProtect(base + s.VirtualAddress, size, SectionProtection(s.Characteristics), &oldProtect)) {
        error = "VirtualProtect failed for a section";
        return false;
      }
    }
    FlushInstructionCache(GetCurrentProcess(), base, opt.SizeOfImage);
    return true;
  }

  bool ReadImageExtent(const std::string& path, std::uint32_t& base, std::uint32_t& size)
  {
    std::ifstream file(path, std::ios::binary);
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS32 nt{};
    if (!file.read(reinterpret_cast<char*>(&dos), sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
      return false;
    }
    file.seekg(dos.e_lfanew);
    if (!file.read(reinterpret_cast<char*>(&nt), sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) {
      return false;
    }
    base = nt.OptionalHeader.ImageBase;
    size = nt.OptionalHeader.SizeOfImage;
    return true;
  }

  int RelaunchWithPreclaimedImage(const std::uint32_t base, const std::uint32_t size)
  {
    // The NLS views and process heaps that land at 0x00400000 are created
    // while the process initialises, after CreateProcess returns. A child
    // started suspended still has that range free, so commit it there
    // first; RetailImage::Load in the child adopts the allocation.
    char exe[MAX_PATH];
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    SetEnvironmentVariableA("DIFFFUZZ_CHILD", "1");
    for (const DWORD which : {STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE}) {
      SetHandleInformation(GetStdHandle(which), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    }
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(exe, GetCommandLineA(), nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
      std::fprintf(stderr, "difffuzz: CreateProcess(suspended) failed: %lu\n", GetLastError());
      return 3;
    }
    void* const got = VirtualAllocEx(
      pi.hProcess, reinterpret_cast<void*>(static_cast<std::uintptr_t>(base)), size, MEM_RESERVE | MEM_COMMIT,
      PAGE_READWRITE
    );
    if (got == nullptr) {
      std::fprintf(stderr, "difffuzz: VirtualAllocEx(0x%08X) in the suspended child failed: %lu\n", base, GetLastError());
      TerminateProcess(pi.hProcess, 3);
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
      return 3;
    }
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 3;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return static_cast<int>(code);
  }

  bool RetailImage::IsExecutable(const std::uint32_t va) const noexcept
  {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<void*>(static_cast<std::uintptr_t>(va)), &mbi, sizeof(mbi)) == 0) {
      return false;
    }
    return (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE)) != 0;
  }

  bool RetailImage::PokeDword(const std::uint32_t va, const std::uint32_t value) noexcept
  {
    if (va < mBase || va + 4 > mBase + mSizeOfImage) {
      return false;
    }
    void* const p = reinterpret_cast<void*>(static_cast<std::uintptr_t>(va));
    DWORD oldProtect = 0;
    if (!VirtualProtect(p, 4, PAGE_READWRITE, &oldProtect)) {
      return false;
    }
    std::memcpy(p, &value, 4);
    VirtualProtect(p, 4, oldProtect, &oldProtect);
    return true;
  }
} // namespace difffuzz
