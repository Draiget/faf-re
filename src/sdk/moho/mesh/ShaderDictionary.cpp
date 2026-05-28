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
    // Reverse construction order: drop the remap entries (binary
    // container at +0x10) before clearing the generation marker
    // (binary container at +0x04). std::unordered_map::clear() invokes
    // each ShaderDictionaryEntry's destructor and releases bucket
    // storage, mirroring the binary's range-erase + head-sentinel free.
    mEntries.clear();
    mCurrentGeneration = 0;
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

  std::int32_t ShaderDictionary::CurrentGeneration() const noexcept
  {
    return mCurrentGeneration;
  }

  const ShaderDictionaryEntry* ShaderDictionary::Lookup(const msvc8::string& requestedShaderName) const
  {
    const auto it = mEntries.find(NormalizeKey(requestedShaderName));
    if (it == mEntries.end()) {
      return nullptr;
    }

    return &it->second;
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
    ShaderDictionaryEntry& entry = mEntries[NormalizeKey(legacyShaderName)];
    entry.remappedShaderName = remappedShaderName;
    entry.sourceGeneration = mCurrentGeneration;
  }

  /**
   * Address: 0x007DBDB0 (FUN_007DBDB0, sub_7DBDB0)
   *
   * What it does:
   * Resolves one shader annotation through the shader remap dictionary,
   * falling back to the caller-provided text (or the constant "Unit" when
   * empty). Emits a `Use of 'old' shader: %s` warning when the entry's
   * stored generation no longer matches the dictionary's current marker.
   */
  msvc8::string ResolveShaderAnnotationName(const msvc8::string& shaderName)
  {
    const ShaderDictionary& dictionary = ShaderDictionary::Instance();
    const ShaderDictionaryEntry* const dictionaryEntry = dictionary.Lookup(shaderName);
    if (!dictionaryEntry) {
      if (shaderName.empty()) {
        return msvc8::string("Unit");
      }

      return msvc8::string(shaderName.view());
    }

    if (dictionaryEntry->sourceGeneration != dictionary.CurrentGeneration()) {
      gpg::Warnf("Use of 'old' shader: %s", shaderName.raw_data_unsafe());
    }

    return msvc8::string(dictionaryEntry->remappedShaderName.view());
  }
} // namespace moho
