#pragma once

// FAF addition, not in the shipped binary.
//
// DXC front end of the universal effect layer: compiles the HLSL that
// ModernHlsl generates to DXIL (Direct3D 12) or SPIR-V (Vulkan).
// dxcompiler.dll and dxil.dll (the DXIL signer) are loaded at run time from
// the executable's directory, or from the directory in FAF_DXC_DIR; see
// docs/RENDERER_BACKENDS.md.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "ModernHlsl.h"

namespace gpg::gal::effects
{
  enum class ShaderTarget : std::uint8_t
  {
    Dxil,
    Spirv,
  };

  struct CompiledShader
  {
    bool succeeded = false;
    std::vector<std::uint8_t> code;
    std::string messages; // errors, or warnings on success
  };

  /** One input of a vertex shader's signature. */
  struct ShaderInput
  {
    enum class Component : std::uint8_t
    {
      Float,
      Uint,
      Sint,
    };

    std::string semantic; // upper case, without the index
    std::uint32_t index = 0;
    Component component = Component::Float;
    std::uint32_t mask = 0;     // used components
    bool systemValue = false;   // SV_VertexID and friends: not fed by vertex buffers
  };

  class ShaderCompiler
  {
  public:
    /** The process-wide compiler; loads DXC on first use. */
    [[nodiscard]] static ShaderCompiler& Instance();

    ShaderCompiler(const ShaderCompiler&) = delete;
    ShaderCompiler& operator=(const ShaderCompiler&) = delete;

    [[nodiscard]] bool Available() const noexcept;

    /** Why DXC could not be loaded (empty when it was). */
    [[nodiscard]] const std::string& LoadError() const noexcept;

    /**
     * Compiles `entry` of `hlsl`. `extraArguments` go to DXC after the
     * layer's own (-HV 2018 -Zpr, the stage define, SPIR-V options).
     */
    [[nodiscard]] CompiledShader Compile(
      std::string_view hlsl, const ShaderEntry& entry, ShaderTarget target, const std::vector<std::wstring>& extraArguments = {}
    ) const;

    /** The input signature of a DXIL shader (empty when it cannot be read). */
    [[nodiscard]] std::vector<ShaderInput> ReflectInputs(const std::vector<std::uint8_t>& dxil) const;

    /** A digest of the loaded compiler, for shader cache keys. */
    [[nodiscard]] const std::string& Version() const noexcept;

  private:
    ShaderCompiler();
    ~ShaderCompiler();

    struct Library;
    Library* mLibrary = nullptr;
    std::string mLoadError;
    std::string mVersion;
  };
} // namespace gpg::gal::effects
