#pragma once

// FAF addition, not in the shipped binary.
//
// The gal Effect / EffectTechnique / EffectVariable of the backends that have
// no effect framework (Direct3D 12, Vulkan), shared by both. An
// EffectProgram is one loaded effect: its description, the generated HLSL,
// the parameter store, and the compiled shaders, built lazily per entry point
// (the first pass that uses one compiles it) and kept in a disk cache outside
// the game's own cache directory, which the engine empties at every start.
//
// The backend sees passes through a PassBinder: BeginPass hands it the
// program and the pass, and it snapshots the parameters and binds the state.

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

#include "EffectDescription.h"
#include "EffectParameters.h"
#include "ModernHlsl.h"
#include "ShaderCompiler.h"
#include "boost/shared_ptr.h"
#include "gpg/gal/Effect.hpp"
#include "gpg/gal/EffectContext.hpp"
#include "gpg/gal/EffectTechnique.hpp"
#include "gpg/gal/EffectVariable.hpp"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg::gal::effects
{
  /** One compiled entry point. */
  struct CompiledEntry
  {
    bool attempted = false;
    bool succeeded = false;
    std::vector<std::uint8_t> code;
    std::vector<ShaderInput> inputs; // vertex shaders, DXIL only
    std::uint64_t key = 0;           // identifies the code (cache key)
    std::string entryName;           // the HLSL entry point (SPIR-V keeps it as the module's entry)
    std::string messages;
  };

  /** The entry points of one pass, as indices into ModernEffect::entries (-1: none). */
  struct PassEntries
  {
    std::int32_t vertex = -1;
    std::int32_t pixel = -1;
  };

  class EffectProgram
  {
  public:
    /**
     * Parses `translatedSource` (TranslateEffectSource output) and generates
     * its HLSL. `originalSource`, the effect as the engine loaded it, supplies
     * the Direct3D 9 pass states the D3D10 dialect lost (ApplyDirect3D9PassStates).
     * Throws std::runtime_error when the source cannot be structured.
     */
    EffectProgram(std::string name, std::string translatedSource, ShaderTarget target, std::string_view originalSource = {});

    EffectProgram(const EffectProgram&) = delete;
    EffectProgram& operator=(const EffectProgram&) = delete;

    [[nodiscard]] const std::string& Name() const noexcept { return mName; }
    [[nodiscard]] const EffectDescription& Description() const noexcept { return mDescription; }
    [[nodiscard]] const ModernEffect& Modern() const noexcept { return mModern; }
    [[nodiscard]] ParameterStore& Parameters() noexcept { return mParameters; }
    [[nodiscard]] const PassEntries& Entries(std::uint32_t technique, std::uint32_t pass) const;

    /** The compiled entry, compiling (or reading the cache) on first use. Never throws. */
    [[nodiscard]] const CompiledEntry& Shader(std::uint32_t entry);

    /** Compiles every entry now (FAF_SHADER_PRECOMPILE=1). */
    void CompileAll();

    /** Index of a parameter, or -1. */
    [[nodiscard]] std::int32_t FindParameter(std::string_view name) const noexcept;

    /** The parameter each ModernEffect::textures slot reads. */
    [[nodiscard]] const std::vector<std::int32_t>& TextureSlotParameters() const noexcept { return mTextureSlotParameters; }

    /** Whatever the backend keeps per effect (its sampler table, cached bindings). */
    [[nodiscard]] std::shared_ptr<void>& BackendState() noexcept { return mBackendState; }

  private:
    std::string mName;
    ShaderTarget mTarget;
    EffectDescription mDescription;
    ModernEffect mModern;
    ParameterStore mParameters;
    std::vector<std::vector<PassEntries>> mPassEntries;
    std::vector<CompiledEntry> mCompiled;
    std::uint64_t mSourceKey = 0;
    std::vector<std::int32_t> mTextureSlotParameters;
    std::shared_ptr<void> mBackendState;
    std::mutex mCompileMutex;
  };

  /** What the backend does when a technique or pass begins and ends. */
  class PassBinder
  {
  public:
    virtual ~PassBinder() = default;

    virtual void BindPass(EffectProgram& program, std::uint32_t technique, std::uint32_t pass) = 0;
    virtual void UnbindPass() = 0;
  };

  /** Keys the shader cache: FNV-1a, 64-bit. */
  class Fnv1a64
  {
  public:
    void Add(const void* data, std::size_t bytes) noexcept;
    void Add(std::string_view text) noexcept;
    [[nodiscard]] std::uint64_t Value() const noexcept { return mHash; }

  private:
    std::uint64_t mHash = 0xCBF29CE484222325ULL;
  };

  /** The directory compiled shaders are kept in (FAF_SHADER_CACHE_DIR, else under %LOCALAPPDATA%). */
  [[nodiscard]] const std::string& ShaderCacheDirectory();
} // namespace gpg::gal::effects

namespace gpg::gal
{
  class ProgramEffect final : public Effect
  {
  public:
    ProgramEffect(const EffectContext& context, std::shared_ptr<effects::EffectProgram> program, effects::PassBinder& binder);
    ~ProgramEffect() override;

    EffectContext* GetContext() override;
    void GetTechniques(msvc8::vector<boost::shared_ptr<EffectTechnique>>& outTechniques) override;
    boost::shared_ptr<EffectVariable> GetVariable(const char* name) override;
    boost::shared_ptr<EffectTechnique> GetTechnique(const char* name) override;
    void OnReset() override;
    void OnLost() override;

  private:
    EffectContext mContext;
    std::shared_ptr<effects::EffectProgram> mProgram;
    effects::PassBinder& mBinder;
  };

  class ProgramEffectTechnique final : public EffectTechnique
  {
  public:
    ProgramEffectTechnique(std::shared_ptr<effects::EffectProgram> program, std::uint32_t technique, effects::PassBinder& binder);
    ~ProgramEffectTechnique() override;

    msvc8::string* GetName() override;
    int BeginTechnique() override;
    void EndTechnique() override;
    void BeginPass(int pass) override;
    void EndPass() override;
    bool GetAnnotationBool(bool* outValue, const msvc8::string& annotationName) override;
    bool GetAnnotationInt(int* outValue, const msvc8::string& annotationName) override;
    bool GetAnnotationFloat(float* outValue, const msvc8::string& annotationName) override;
    bool GetAnnotationString(msvc8::string* outValue, const msvc8::string& annotationName) override;

  private:
    std::shared_ptr<effects::EffectProgram> mProgram;
    std::uint32_t mTechnique = 0;
    effects::PassBinder& mBinder;
    msvc8::string mName;
    bool mBegun = false;
  };

  class ProgramEffectVariable final : public EffectVariable
  {
  public:
    /** `parameter` < 0: a name the effect knows that is not a parameter (a sampler); setters do nothing. */
    ProgramEffectVariable(std::shared_ptr<effects::EffectProgram> program, std::int32_t parameter, const char* name);
    ~ProgramEffectVariable() override;

    msvc8::string* GetName() override;
    /** No cube targets on these backends yet, as on D3D10 and D3D11. */
    void SetCubeRenderTarget(boost::shared_ptr<CubeRenderTarget> cubeTarget) override;
    void SetRenderTarget(boost::shared_ptr<RenderTarget> renderTarget) override;
    void SetTexture(boost::shared_ptr<Texture> texture) override;
    void SetMatrix4x4(const Matrix* matrix) override;
    void SetFloatArray(std::uint32_t count, const float* values) override;
    void SetVector(const float* vector4) override;
    void SetValue(const void* data, std::uint32_t byteCount) override;
    void SetFloat(float value) override;
    void SetInt(int value) override;
    void SetBool(bool value) override;
    void SetMatrixArray(std::uint32_t count, const Matrix* matrices) override;
    void SetVectorArray(std::uint32_t count, const float* vectors4) override;
    bool GetAnnotationBool(bool* outValue, const msvc8::string& annotationName) override;
    bool GetAnnotationInt(int* outValue, const msvc8::string& annotationName) override;
    bool GetAnnotationFloat(float* outValue, const msvc8::string& annotationName) override;
    bool GetAnnotationString(msvc8::string* outValue, const msvc8::string& annotationName) override;

  private:
    [[nodiscard]] const effects::Annotations* OwnAnnotations() const;

    std::shared_ptr<effects::EffectProgram> mProgram;
    std::int32_t mParameter = -1;
    msvc8::string mName;
  };
} // namespace gpg::gal
