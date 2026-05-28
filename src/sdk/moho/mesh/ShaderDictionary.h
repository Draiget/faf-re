#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

#include "legacy/containers/String.h"

namespace moho
{
  /**
   * One entry value stored inside the shader-remap dictionary:
   *   - the modern shader/material name the legacy annotation maps to,
   *   - the dictionary generation at which the entry was last (re-)written.
   *
   * The binary keeps the same payload distributed across two intrusive
   * `std::map` containers (one mapping legacy-key -> remapped-name and one
   * tracking the "current" set of valid keys). The modern absorption fuses
   * both lanes into a single map keyed by normalized legacy name, with the
   * generation lane stored alongside the value so stale-entry detection
   * still functions for `ResolveShaderAnnotationName`.
   */
  struct ShaderDictionaryEntry
  {
    msvc8::string remappedShaderName;
    std::int32_t sourceGeneration;
  };

  /**
   * Polymorphic global shader-remap dictionary used by mesh material
   * creation. The binary instantiates exactly one of these (singleton-
   * style) through the CRT static-init lane (`register_ShaderDictionary`)
   * and registers its destructor with `atexit`. The recovered modern code
   * exposes the same object as a Meyer's singleton; the C++ runtime emits
   * the equivalent atexit destructor registration automatically.
   *
   * Binary identity:
   *   - RTTI: `??_R0?AVShaderDictionary@Moho@@@8`
   *   - vftable: `??_7ShaderDictionary@Moho@@6B@` at 0x00E3F4B4
   *   - Scalar deleting destructor (vtable slot 0): `FUN_007DBEC0`
   *     (`Moho::ShaderDictionary::dtr`)
   */
  class ShaderDictionary
  {
  public:
    /**
     * Address: 0x007DB3A0 (FUN_007DB3A0, ??0ShaderDictionary@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes the shader remap dictionary with all built-in
     * legacy-annotation -> modern-name aliases used by legacy mesh
     * assets.
     */
    ShaderDictionary();

    /**
     * Address: 0x007DBD10 (FUN_007DBD10, ??1ShaderDictionary@Moho@@QAE@@Z)
     *
     * IDA signature:
     *   void __thiscall Moho::ShaderDictionary::~ShaderDictionary(
     *     Moho::ShaderDictionary *this);
     *
     * What it does:
     * Tears down the two intrusive RB-tree containers used by the binary
     * (in reverse construction order: the value/remap container first, then
     * the generation/key container), reinstates the vtable identity (which
     * the C++ runtime does automatically for a virtual dtor), and zeros the
     * head/size lanes the binary kept inline.
     */
    virtual ~ShaderDictionary();

    ShaderDictionary(const ShaderDictionary&) = delete;
    ShaderDictionary& operator=(const ShaderDictionary&) = delete;
    ShaderDictionary(ShaderDictionary&&) = delete;
    ShaderDictionary& operator=(ShaderDictionary&&) = delete;

    /**
     * Returns the process-wide shader dictionary instance. The Meyer's
     * function-local-static lifetime mirrors the binary's CRT-static-init
     * + atexit registration lane.
     */
    [[nodiscard]] static ShaderDictionary& Instance() noexcept;

    /**
     * Returns the current dictionary generation marker. Each
     * `AssignRemap` stamps the inserted entry with this value;
     * `ResolveShaderAnnotationName` warns on lookups whose stored
     * generation no longer matches.
     */
    [[nodiscard]] std::int32_t CurrentGeneration() const noexcept;

    /**
     * Looks up one shader annotation by key. Returns nullptr if the key
     * is not present in the dictionary.
     */
    [[nodiscard]] const ShaderDictionaryEntry* Lookup(const msvc8::string& requestedShaderName) const;

    /**
     * Address: 0x007DBE90 (FUN_007DBE90, sub_7DBE90)
     *
     * What it does:
     * Writes one remap pair into the dictionary, stamping the resulting
     * entry with the current generation marker.
     */
    void AssignRemap(const msvc8::string& legacyShaderName, const msvc8::string& remappedShaderName);

  private:
    template <class TString>
    [[nodiscard]] static std::string NormalizeKey(const TString& value)
    {
      const std::string_view view = value.view();
      return std::string(view.begin(), view.end());
    }

    std::int32_t mCurrentGeneration = 0;
    std::unordered_map<std::string, ShaderDictionaryEntry> mEntries{};
  };

  /**
   * Address: 0x007DBDB0 (FUN_007DBDB0, sub_7DBDB0)
   *
   * What it does:
   * Resolves one shader annotation through the shader remap dictionary,
   * falling back to the caller-provided text (or the constant "Unit" when
   * empty). Emits a `Use of 'old' shader: %s` warning when the entry's
   * stored generation no longer matches the dictionary's current marker.
   */
  [[nodiscard]] msvc8::string ResolveShaderAnnotationName(const msvc8::string& shaderName);
} // namespace moho
