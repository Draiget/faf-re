#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{
  namespace
  {

    // `{proxy, first, last, end}` at 0x10 is `fa::vector<EffectMacro>`
    // itself, so the lane is the container, not a view over it.
    using EffectMacroVector = fa::vector<EffectMacro>;

    static_assert(sizeof(EffectMacroVector) == 0x10, "EffectMacroVector size must be 0x10");

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

  } // namespace

} // namespace gpg::gal
