#pragma once

#include <cstdint>

#include "legacy/containers/Map.h"
#include "legacy/containers/Set.h"
#include "legacy/containers/String.h"

namespace moho
{
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
     * The modern name `requestedShaderName` remaps to, or null when the
     * dictionary does not know it.
     */
    [[nodiscard]] const msvc8::string* Lookup(const msvc8::string& requestedShaderName) const;

    /**
     * Whether `shaderName` is one of the names a lookup warns about.
     *
     * Nothing in this binary ever puts a name in that set, so the warning
     * `ResolveShaderAnnotationName` guards with this never fires. The set is
     * real - the constructor buys its header sentinel (0x004DD460) and the
     * destructor frees it - so it is kept rather than folded away.
     */
    [[nodiscard]] bool IsDeprecated(const msvc8::string& shaderName) const;

    /**
     * Address: 0x007DBE90 (FUN_007DBE90, sub_7DBE90)
     *
     * What it does:
     * Writes one remap pair into the dictionary, stamping the resulting
     * entry with the current generation marker.
     */
    void AssignRemap(const msvc8::string& legacyShaderName, const msvc8::string& remappedShaderName);

  private:
    /**
     * The names a lookup warns about. Node 0x2C -- the constructor's header
     * allocation (0x004DD460) marks nil at `+0x29`, so the value is the bare
     * 0x1C key with colour/nil at `+0x28`/`+0x29`, which is a set and not a
     * map. Never inserted into anywhere in this binary.
     */
    msvc8::set<msvc8::string> mDeprecatedNames{};                  // +0x04

    /**
     * Legacy annotation -> modern shader name. Node 0x48 -- its header
     * allocation (0x00434CF0) marks nil at `+0x45`, so the pair at `node+0x0C`
     * is 0x38, two 0x1C strings. `ResolveShaderAnnotationName` reads the
     * mapped name at `node+0x28`, which is exactly `pair::second`.
     */
    msvc8::map<msvc8::string, msvc8::string> mRemaps{};             // +0x10

    static_assert(sizeof(msvc8::set<msvc8::string>) == 0x0C, "the legacy set head is 0x0C");
    static_assert(sizeof(msvc8::map<msvc8::string, msvc8::string>) == 0x0C, "the legacy map head is 0x0C");
  };

  static_assert(sizeof(ShaderDictionary) == 0x1C, "ShaderDictionary size must be 0x1C");

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
