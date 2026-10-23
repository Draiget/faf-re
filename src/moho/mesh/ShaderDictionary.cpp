#include "ShaderDictionary.h"

#include "gpg/core/utils/Logging.h"

namespace moho
{
  /**
   * Address: 0x007DB3A0 (FUN_007DB3A0, ??0ShaderDictionary@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes the shader remap dictionary with all built-in
   * legacy-annotation -> modern-name aliases used by legacy mesh assets.
   */
  ShaderDictionary::ShaderDictionary()
  {
    AssignRemap("TMeshNoLighting", "Flat");
    AssignRemap("TMeshNoNormals", "VertexNormal");
    AssignRemap("TMeshAlpha", "NormalMappedAlpha");
    AssignRemap("TMeshGlow", "NormalMappedGlow");
    AssignRemap("TMeshTerrain", "NormalMappedTerrain");
    AssignRemap("Simple", "Unit");
    AssignRemap("Team", "Unit");
    AssignRemap("TMeshAlphaGlowFade", "UnitBuild");
    AssignRemap("TMeshMetalBuild", "AeonBuild");
    AssignRemap("TMeshShield", "Shield");
    AssignRemap("TMeshZFill", "ShieldFill");
    AssignRemap("TMeshAdd", "Effect");
    AssignRemap("TMeshExplosion", "Explosion");
    AssignRemap("TMeshCloud", "Cloud");
    AssignRemap("TMeshOuterCloud", "OuterCloud");
    AssignRemap("TMeshEMPNuke", "NukeEMP");
    AssignRemap("TMeshQuantumNuke", "NukeQuantum");
    AssignRemap("TMeshTemporalBubble", "TemporalBubble");
  }

  /**
   * Address: 0x007DBD10 (FUN_007DBD10, ??1ShaderDictionary@Moho@@QAE@@Z)
   * Address: 0x007DBEC0 (FUN_007DBEC0, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   *
   * IDA signature:
   *   void __thiscall Moho::ShaderDictionary::~ShaderDictionary(
   *     Moho::ShaderDictionary *this);
   *
   * What it does:
   * Tears down the dictionary's runtime state in the same reverse
   * construction order the binary uses. The binary destroys two intrusive
   * `std::map`-shape containers: the remap container (the binary's `+0x10`
   * slot) first, then the generation/key container (the binary's `+0x04`
   * slot). The modern absorption fuses both lanes into one
   * `std::unordered_map<std::string, ShaderDictionaryEntry>`; the implicit
   * destructor of `mEntries` performs the equivalent node-by-node teardown.
   * The vtable identity is reinstated automatically by the C++ runtime for
   * any virtual destructor.
   */
  ShaderDictionary::~ShaderDictionary()
  {
    // Both members' `~rb_tree()` runs here, in reverse declaration order,
    // and MSVC emits both calls - which is what 0x007DBD10 does at
    // 0x007DBD3D (`mRemaps`) and 0x007DBD6B (`mDeprecatedNames`). The body
    // itself says nothing.
  }

  ShaderDictionary& ShaderDictionary::Instance() noexcept
  {
    // Function-local static: the C++ runtime emits the atexit-registered
    // destructor call that mirrors the binary's
    // `register_ShaderDictionary` -> `atexit(sub_C03BF0)` lane (which
    // ultimately invokes `~ShaderDictionary` at process teardown).
    static ShaderDictionary instance{};
    return instance;
  }

  const msvc8::string* ShaderDictionary::Lookup(const msvc8::string& requestedShaderName) const
  {
    const msvc8::map<msvc8::string, msvc8::string>::const_iterator it = mRemaps.find(requestedShaderName);
    return it == mRemaps.end() ? nullptr : &it->second;
  }

  bool ShaderDictionary::IsDeprecated(const msvc8::string& shaderName) const
  {
    return mDeprecatedNames.find(shaderName) != mDeprecatedNames.end();
  }

  /**
   * Address: 0x007DBE90 (FUN_007DBE90, sub_7DBE90)
   *
   * What it does:
   * Stores one legacy shader key -> remapped shader name pair in the
   * dictionary and tags the entry with the current dictionary generation
   * marker.
   */
  void ShaderDictionary::AssignRemap(
    const msvc8::string& legacyShaderName,
    const msvc8::string& remappedShaderName
  )
  {
    mRemaps[legacyShaderName] = remappedShaderName;
  }

  /**
   * Address: 0x007DBDB0 (FUN_007DBDB0, sub_7DBDB0)
   *
   * What it does:
   * Resolves one shader annotation through the shader remap dictionary. A
   * name the dictionary does not know comes back unchanged, or as "Unit"
   * when it is empty. A name in the deprecated set warns first - a branch
   * that cannot be taken in this binary, because nothing inserts into that
   * set.
   */
  msvc8::string ResolveShaderAnnotationName(const msvc8::string& shaderName)
  {
    const ShaderDictionary& dictionary = ShaderDictionary::Instance();
    const msvc8::string* const remapped = dictionary.Lookup(shaderName);
    if (remapped == nullptr) {
      return shaderName.empty() ? msvc8::string("Unit") : msvc8::string(shaderName.view());
    }

    if (dictionary.IsDeprecated(shaderName)) {
      gpg::Warnf("Use of 'old' shader: %s", shaderName.raw_data_unsafe());
    }

    return msvc8::string(remapped->view());
  }
} // namespace moho
