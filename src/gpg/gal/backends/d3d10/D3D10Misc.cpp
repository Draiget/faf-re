#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{
namespace
{

    // `{proxy, first, last, end}` at 0x10 is `fa::vector<EffectMacro>`
    // itself, so the lane is the container, not a view over it.
    using EffectMacroVector = fa::vector<EffectMacro>;

    static_assert(sizeof(EffectMacroVector) == 0x10, "EffectMacroVector size must be 0x10");

    void* AllocateArrayOrThrow(const std::uint32_t count, const std::uint32_t elementSize)
    {
      if ((count != 0U) && ((std::numeric_limits<std::uint32_t>::max() / count) < elementSize)) {
        throw std::bad_alloc();
      }

      return ::operator new(static_cast<std::size_t>(count) * static_cast<std::size_t>(elementSize));
    }

    /**
     * Address: 0x008F8ED0 (FUN_008F8ED0)
     *
     * uint32_t
     *
     * What it does:
     * Allocates `count * 4` bytes with overflow guard and throws
     * `std::bad_alloc` on overflow.
     */
    [[maybe_unused]] void* AllocateStride04Array(const std::uint32_t count)
    {
      return AllocateArrayOrThrow(count, 0x04U);
    }

    // Defined later in this TU; used by the vector<void*>::_Insert_n grow lane below.
    [[noreturn]] void ThrowVectorTooLongLengthErrorB();

    /**
     * Address: 0x008FAA50 (FUN_008FAA50)
     *
     * What it does:
     * Throws the legacy MSVC vector-length error used by effect-macro vector
     * growth helpers.
     */
    [[maybe_unused]] [[noreturn]] void ThrowVectorTooLongLengthErrorA()
    {
      throw std::length_error("vector<T> too long");
    }

    /**
     * Address: 0x008FAAC0 (FUN_008FAAC0)
     *
     * What it does:
     * Throws the legacy MSVC vector-length error used by effect-macro vector
     * growth helpers.
     */
    [[maybe_unused]] [[noreturn]] void ThrowVectorTooLongLengthErrorB()
    {
      throw std::length_error("vector<T> too long");
    }

    /**
     * Address: 0x008CB6B0 (FUN_008CB6B0)
     *
     * IDA signature:
     * void __noreturn sub_8CB6B0();
     *
     * What it does:
     * Throws the legacy MSVC `std::out_of_range("invalid vector<T> subscript")`
     * used by bounds-checked `operator[]` instantiations for the D3D device
     * caps / adapter-mode / antialiasing-option vectors.
     */
    [[maybe_unused]] [[noreturn]] void ThrowVectorSubscriptOutOfRange()
    {
      throw std::out_of_range("invalid vector<T> subscript");
    }

    /**
     * Address: 0x008F8CA0 (FUN_008F8CA0)
     *
     * What it does:
     * Returns one stable, process-lifetime zero-initialized wide-character
     * storage lane used by legacy helper paths.
     */
    wchar_t* GetLegacyWideZeroStorageLane() noexcept
    {
      static wchar_t sLegacyWideZeroStorage = L'\0';
      return &sLegacyWideZeroStorage;
    }

    /**
     * Address: 0x008F9920 (FUN_008F9920)
     *
     * What it does:
     * Clone entry that returns the same stable process-lifetime wide-zero
     * storage lane as `FUN_008F8CA0`.
     */
    [[maybe_unused]] wchar_t* GetLegacyWideZeroStorageLaneCloneA() noexcept
    {
      return GetLegacyWideZeroStorageLane();
    }
}

}

