// FAF addition, not in the shipped binary: see EffectRuntime.h.

#include "EffectRuntime.h"

#include <windows.h>
#include <shlobj.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <utility>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/Matrix.h"
#include "gpg/gal/RenderTarget.hpp"
#include "gpg/gal/Texture.hpp"

namespace gpg::gal::effects
{
  namespace
  {
    // Bump when the generated HLSL or the compile options change meaning.
    constexpr const char* kLayerVersion = "faf effect layer 1";

    struct CacheHeader
    {
      char magic[8];
      std::uint64_t key;
      std::uint64_t bytes;
    };

    constexpr char kCacheMagic[8] = {'F', 'A', 'F', 'S', 'H', 'D', 'R', '1'};

    [[nodiscard]] std::string CachePath(const std::uint64_t key, const ShaderTarget target)
    {
      const std::string& directory = ShaderCacheDirectory();
      if (directory.empty()) {
        return {};
      }
      char name[64]{};
      std::snprintf(name, sizeof(name), "%016llx.%s", static_cast<unsigned long long>(key), target == ShaderTarget::Dxil ? "dxil" : "spv");
      return directory + name;
    }

    [[nodiscard]] bool ReadCache(const std::string& path, const std::uint64_t key, std::vector<std::uint8_t>& code)
    {
      if (path.empty()) {
        return false;
      }
      HANDLE const file = ::CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0U, nullptr);
      if (file == INVALID_HANDLE_VALUE) {
        return false;
      }
      CacheHeader header{};
      DWORD read = 0U;
      bool ok = ::ReadFile(file, &header, sizeof(header), &read, nullptr) && read == sizeof(header) &&
        std::memcmp(header.magic, kCacheMagic, sizeof(kCacheMagic)) == 0 && header.key == key && header.bytes != 0U &&
        header.bytes < (16ULL << 20U);
      if (ok) {
        code.resize(static_cast<std::size_t>(header.bytes));
        ok = ::ReadFile(file, code.data(), static_cast<DWORD>(code.size()), &read, nullptr) && read == code.size();
      }
      ::CloseHandle(file);
      if (!ok) {
        code.clear();
      }
      return ok;
    }

    void WriteCache(const std::string& path, const std::uint64_t key, const std::vector<std::uint8_t>& code)
    {
      if (path.empty()) {
        return;
      }
      char suffix[32]{};
      std::snprintf(suffix, sizeof(suffix), ".%lu.tmp", static_cast<unsigned long>(::GetCurrentThreadId()));
      const std::string temporary = path + suffix;
      HANDLE const file = ::CreateFileA(temporary.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_ALWAYS, 0U, nullptr);
      if (file == INVALID_HANDLE_VALUE) {
        return;
      }
      CacheHeader header{};
      std::memcpy(header.magic, kCacheMagic, sizeof(kCacheMagic));
      header.key = key;
      header.bytes = code.size();
      DWORD written = 0U;
      const bool ok = ::WriteFile(file, &header, sizeof(header), &written, nullptr) && written == sizeof(header) &&
        ::WriteFile(file, code.data(), static_cast<DWORD>(code.size()), &written, nullptr) && written == code.size();
      ::CloseHandle(file);
      if (!ok || !::MoveFileExA(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        ::DeleteFileA(temporary.c_str());
      }
    }

  } // namespace

  void Fnv1a64::Add(const void* const data, const std::size_t bytes) noexcept
  {
    const auto* const begin = static_cast<const unsigned char*>(data);
    for (std::size_t index = 0U; index < bytes; ++index) {
      mHash ^= begin[index];
      mHash *= 0x100000001B3ULL;
    }
  }

  void Fnv1a64::Add(const std::string_view text) noexcept
  {
    Add(text.data(), text.size());
    const char terminator = '\0';
    Add(&terminator, 1U);
  }

  const std::string& ShaderCacheDirectory()
  {
    static const std::string directory = [] {
      std::string path;
      if (const char* const configured = std::getenv("FAF_SHADER_CACHE_DIR"); configured != nullptr && configured[0] != '\0') {
        path = configured;
      } else {
        char localAppData[MAX_PATH]{};
        if (SUCCEEDED(::SHGetFolderPathA(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, localAppData))) {
          path = std::string(localAppData) + "\\FAForever\\ShaderCache";
        }
      }
      if (path.empty()) {
        return std::string();
      }
      if (path.back() != '\\' && path.back() != '/') {
        path += '\\';
      }
      const int result = ::SHCreateDirectoryExA(nullptr, path.c_str(), nullptr);
      if (result != ERROR_SUCCESS && result != ERROR_ALREADY_EXISTS && result != ERROR_FILE_EXISTS) {
        gpg::Warnf("effects: cannot create the shader cache %s (error %d); compiling every run", path.c_str(), result);
        return std::string();
      }
      return path;
    }();
    return directory;
  }

  EffectProgram::EffectProgram(std::string name, std::string translatedSource, const ShaderTarget target)
    : mName(std::move(name))
    , mTarget(target)
  {
    mDescription = ParseEffect(translatedSource);
    mModern = GenerateModernHlsl(translatedSource, mDescription);
    mParameters.Initialize(mDescription, mModern.constants);
    mCompiled.resize(mModern.entries.size());

    mPassEntries.resize(mDescription.techniques.size());
    for (std::size_t technique = 0U; technique < mDescription.techniques.size(); ++technique) {
      for (const Pass& pass : mDescription.techniques[technique].passes) {
        PassEntries entries;
        for (std::size_t entry = 0U; entry < mModern.entries.size(); ++entry) {
          if (!pass.vertexShader.entry.empty() && mModern.entries[entry].name == pass.vertexShader.entry) {
            entries.vertex = static_cast<std::int32_t>(entry);
          }
          if (!pass.pixelShader.entry.empty() && mModern.entries[entry].name == pass.pixelShader.entry) {
            entries.pixel = static_cast<std::int32_t>(entry);
          }
        }
        mPassEntries[technique].push_back(entries);
      }
    }

    for (const TextureSlot& slot : mModern.textures) {
      mTextureSlotParameters.push_back(FindParameter(slot.parameter));
    }

    Fnv1a64 key;
    key.Add(kLayerVersion);
    key.Add(ShaderCompiler::Instance().Version());
    key.Add(mModern.hlsl);
    mSourceKey = key.Value();

    // Diagnostics: FAF_EFFECT_DUMP_DIR=dir writes the translated source and
    // the generated HLSL of every effect there (local files, never shipped).
    if (const char* const dumpDirectory = std::getenv("FAF_EFFECT_DUMP_DIR"); dumpDirectory != nullptr && dumpDirectory[0] != '\0') {
      const std::size_t slash = mName.find_last_of("\\/");
      const std::string base =
        std::string(dumpDirectory) + "\\" + ((slash == std::string::npos) ? mName : mName.substr(slash + 1U));
      for (const auto& [suffix, text] : {std::pair<const char*, const std::string*>{".translated.fx", &translatedSource},
                                         std::pair<const char*, const std::string*>{".hlsl", &mModern.hlsl}}) {
        if (FILE* const file = std::fopen((base + suffix).c_str(), "wb")) {
          std::fwrite(text->data(), 1U, text->size(), file);
          std::fclose(file);
        }
      }
    }

    for (const std::string& note : mDescription.notes) {
      gpg::Logf("effects: %s: %s", mName.c_str(), note.c_str());
    }
    for (const std::string& note : mModern.notes) {
      gpg::Logf("effects: %s: %s", mName.c_str(), note.c_str());
    }
  }

  const PassEntries& EffectProgram::Entries(const std::uint32_t technique, const std::uint32_t pass) const
  {
    static const PassEntries kNone{};
    if (technique >= mPassEntries.size() || pass >= mPassEntries[technique].size()) {
      return kNone;
    }
    return mPassEntries[technique][pass];
  }

  const CompiledEntry& EffectProgram::Shader(const std::uint32_t entry)
  {
    static const CompiledEntry kMissing{};
    if (entry >= mCompiled.size()) {
      return kMissing;
    }
    const std::lock_guard<std::mutex> lock(mCompileMutex);
    CompiledEntry& compiled = mCompiled[entry];
    if (compiled.attempted) {
      return compiled;
    }
    compiled.attempted = true;

    const ShaderEntry& shaderEntry = mModern.entries[entry];
    Fnv1a64 key;
    key.Add(&mSourceKey, sizeof(mSourceKey));
    key.Add(shaderEntry.name);
    key.Add(mTarget == ShaderTarget::Dxil ? "dxil" : "spirv");
    compiled.key = key.Value();
    compiled.entryName = shaderEntry.name;

    ShaderCompiler& compiler = ShaderCompiler::Instance();
    const std::string path = CachePath(compiled.key, mTarget);
    if (ReadCache(path, compiled.key, compiled.code)) {
      compiled.succeeded = true;
    } else {
      const DWORD started = ::GetTickCount();
      CompiledShader result = compiler.Compile(mModern.hlsl, shaderEntry, mTarget);
      compiled.messages = std::move(result.messages);
      if (!result.succeeded) {
        gpg::Warnf(
          "effects: %s: %s (%s %s) failed to compile:\n%s", mName.c_str(), shaderEntry.name.c_str(), shaderEntry.function.c_str(),
          shaderEntry.arguments.c_str(), compiled.messages.substr(0U, 2000U).c_str()
        );
        return compiled;
      }
      compiled.code = std::move(result.code);
      compiled.succeeded = true;
      WriteCache(path, compiled.key, compiled.code);
      static int logged = 0;
      if (logged++ < 32) {
        gpg::Logf("effects: %s: compiled %s (%s) in %lu ms", mName.c_str(), shaderEntry.name.c_str(), shaderEntry.function.c_str(),
                  ::GetTickCount() - started);
      }
    }
    if (shaderEntry.stage == ShaderStage::Vertex && mTarget == ShaderTarget::Dxil) {
      compiled.inputs = compiler.ReflectInputs(compiled.code);
    }
    return compiled;
  }

  void EffectProgram::CompileAll()
  {
    for (std::uint32_t entry = 0U; entry < mCompiled.size(); ++entry) {
      static_cast<void>(Shader(entry));
    }
  }

  std::int32_t EffectProgram::FindParameter(const std::string_view name) const noexcept
  {
    for (std::size_t index = 0U; index < mDescription.parameters.size(); ++index) {
      if (mDescription.parameters[index].name == name) {
        return static_cast<std::int32_t>(index);
      }
    }
    return -1;
  }
} // namespace gpg::gal::effects

namespace gpg::gal
{
  namespace
  {
    [[noreturn]] void Throw(const int line, const std::string& message)
    {
      throw Error(msvc8::string("EffectRuntime.cpp"), line, msvc8::string(message.c_str()));
    }

    template <class Read>
    bool ReadAnnotation(const effects::Annotations* const annotations, const msvc8::string& name, Read&& read)
    {
      if (annotations == nullptr) {
        return false;
      }
      const effects::Annotation* const annotation = effects::FindAnnotation(*annotations, name.c_str());
      return annotation != nullptr && read(*annotation);
    }

    [[nodiscard]] bool AnnotationNumber(const effects::Annotation& annotation, double& value)
    {
      if (annotation.kind == effects::Annotation::Kind::String) {
        return false;
      }
      value = annotation.number;
      return true;
    }
  } // namespace

  // ---------------------------------------------------------------------------
  // ProgramEffect

  ProgramEffect::ProgramEffect(
    const EffectContext& context, std::shared_ptr<effects::EffectProgram> program, effects::PassBinder& binder
  )
    : mContext(context)
    , mProgram(std::move(program))
    , mBinder(binder)
  {
    // No source is kept once the effect exists (as DeviceD3D10's SetEffect).
    mContext.mSourceBuffer.Reset();
  }

  ProgramEffect::~ProgramEffect() = default;

  EffectContext* ProgramEffect::GetContext()
  {
    return &mContext;
  }

  void ProgramEffect::GetTechniques(msvc8::vector<boost::shared_ptr<EffectTechnique>>& outTechniques)
  {
    const auto count = static_cast<std::uint32_t>(mProgram->Description().techniques.size());
    for (std::uint32_t technique = 0U; technique < count; ++technique) {
      outTechniques.push_back(boost::shared_ptr<EffectTechnique>(new ProgramEffectTechnique(mProgram, technique, mBinder)));
    }
  }

  boost::shared_ptr<EffectVariable> ProgramEffect::GetVariable(const char* const name)
  {
    const std::string_view wanted = (name != nullptr) ? name : "";
    const std::int32_t parameter = mProgram->FindParameter(wanted);
    if (parameter < 0) {
      bool sampler = false;
      for (const effects::SamplerDesc& candidate : mProgram->Description().samplers) {
        sampler = sampler || candidate.name == wanted;
      }
      if (!sampler) {
        Throw(__LINE__, "invalid effect variable requested: " + std::string(wanted));
      }
    }
    return boost::shared_ptr<EffectVariable>(new ProgramEffectVariable(mProgram, parameter, name));
  }

  boost::shared_ptr<EffectTechnique> ProgramEffect::GetTechnique(const char* const name)
  {
    const auto& techniques = mProgram->Description().techniques;
    for (std::size_t technique = 0U; technique < techniques.size(); ++technique) {
      if (name != nullptr && techniques[technique].name == name) {
        return boost::shared_ptr<EffectTechnique>(
          new ProgramEffectTechnique(mProgram, static_cast<std::uint32_t>(technique), mBinder)
        );
      }
    }
    Throw(__LINE__, std::string("invalid effect technique requested: ") + ((name != nullptr) ? name : ""));
  }

  void ProgramEffect::OnReset() {}

  void ProgramEffect::OnLost() {}

  // ---------------------------------------------------------------------------
  // ProgramEffectTechnique

  ProgramEffectTechnique::ProgramEffectTechnique(
    std::shared_ptr<effects::EffectProgram> program, const std::uint32_t technique, effects::PassBinder& binder
  )
    : mProgram(std::move(program))
    , mTechnique(technique)
    , mBinder(binder)
    , mName(mProgram->Description().techniques[technique].name.c_str())
  {}

  ProgramEffectTechnique::~ProgramEffectTechnique() = default;

  msvc8::string* ProgramEffectTechnique::GetName()
  {
    return &mName;
  }

  int ProgramEffectTechnique::BeginTechnique()
  {
    Device::GetInstance()->BeginTechnique();
    mBegun = true;
    // Diagnostics: FAF_GAL_SKIP_TECHNIQUES=";A;B;" draws techniques A and B with no passes.
    static const char* const skipped = std::getenv("FAF_GAL_SKIP_TECHNIQUES");
    if (skipped != nullptr && std::strstr(skipped, (";" + std::string(mName.c_str()) + ";").c_str()) != nullptr) {
      return 0;
    }
    return static_cast<int>(mProgram->Description().techniques[mTechnique].passes.size());
  }

  void ProgramEffectTechnique::EndTechnique()
  {
    if (!mBegun) {
      Throw(__LINE__, "effect technique begin/end mismatch");
    }
    Device::GetInstance()->EndTechnique();
    mBegun = false;
  }

  void ProgramEffectTechnique::BeginPass(const int pass)
  {
    if (!mBegun) {
      Throw(__LINE__, "effect technique begin/end mismatch");
    }
    if (pass < 0 || static_cast<std::size_t>(pass) >= mProgram->Description().techniques[mTechnique].passes.size()) {
      Throw(__LINE__, "invalid effect pass requested");
    }
    mBinder.BindPass(*mProgram, mTechnique, static_cast<std::uint32_t>(pass));
  }

  void ProgramEffectTechnique::EndPass()
  {
    if (!mBegun) {
      Throw(__LINE__, "effect technique begin/end mismatch");
    }
    mBinder.UnbindPass();
  }

  bool ProgramEffectTechnique::GetAnnotationBool(bool* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(&mProgram->Description().techniques[mTechnique].annotations, annotationName, [&](const effects::Annotation& a) {
      double value = 0.0;
      if (!AnnotationNumber(a, value)) {
        return false;
      }
      *outValue = value != 0.0;
      return true;
    });
  }

  bool ProgramEffectTechnique::GetAnnotationInt(int* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(&mProgram->Description().techniques[mTechnique].annotations, annotationName, [&](const effects::Annotation& a) {
      double value = 0.0;
      if (!AnnotationNumber(a, value)) {
        return false;
      }
      *outValue = static_cast<int>(value);
      return true;
    });
  }

  bool ProgramEffectTechnique::GetAnnotationFloat(float* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(&mProgram->Description().techniques[mTechnique].annotations, annotationName, [&](const effects::Annotation& a) {
      double value = 0.0;
      if (!AnnotationNumber(a, value)) {
        return false;
      }
      *outValue = static_cast<float>(value);
      return true;
    });
  }

  bool ProgramEffectTechnique::GetAnnotationString(msvc8::string* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(&mProgram->Description().techniques[mTechnique].annotations, annotationName, [&](const effects::Annotation& a) {
      if (a.kind != effects::Annotation::Kind::String) {
        return false;
      }
      outValue->assign_owned(a.text.c_str());
      return true;
    });
  }

  // ---------------------------------------------------------------------------
  // ProgramEffectVariable

  ProgramEffectVariable::ProgramEffectVariable(
    std::shared_ptr<effects::EffectProgram> program, const std::int32_t parameter, const char* const name
  )
    : mProgram(std::move(program))
    , mParameter(parameter)
    , mName((name != nullptr) ? name : "")
  {}

  ProgramEffectVariable::~ProgramEffectVariable() = default;

  msvc8::string* ProgramEffectVariable::GetName()
  {
    return &mName;
  }

  void ProgramEffectVariable::SetCubeRenderTarget(const boost::shared_ptr<CubeRenderTarget> cubeTarget)
  {
    static_cast<void>(cubeTarget);
  }

  void ProgramEffectVariable::SetRenderTarget(const boost::shared_ptr<RenderTarget> renderTarget)
  {
    if (mParameter >= 0) {
      mProgram->Parameters().SetRenderTarget(static_cast<std::uint32_t>(mParameter), renderTarget);
    }
  }

  void ProgramEffectVariable::SetTexture(const boost::shared_ptr<Texture> texture)
  {
    if (mParameter >= 0) {
      mProgram->Parameters().SetTexture(static_cast<std::uint32_t>(mParameter), texture);
    }
  }

  void ProgramEffectVariable::SetMatrix4x4(const Matrix* const matrix)
  {
    if (mParameter >= 0 && matrix != nullptr) {
      mProgram->Parameters().SetMatrix(static_cast<std::uint32_t>(mParameter), &matrix->r[0].x);
    }
  }

  void ProgramEffectVariable::SetFloatArray(const std::uint32_t count, const float* const values)
  {
    if (mParameter >= 0) {
      mProgram->Parameters().SetFloats(static_cast<std::uint32_t>(mParameter), values, count);
    }
  }

  void ProgramEffectVariable::SetVector(const float* const vector4)
  {
    if (mParameter >= 0) {
      mProgram->Parameters().SetVector(static_cast<std::uint32_t>(mParameter), vector4);
    }
  }

  void ProgramEffectVariable::SetValue(const void* const data, const std::uint32_t byteCount)
  {
    if (mParameter < 0) {
      return;
    }
    const effects::Parameter& parameter = mProgram->Description().parameters[static_cast<std::size_t>(mParameter)];
    // D3D9's SetValue on float data converts like SetFloatArray; anything
    // else is packed 4-byte components.
    if (parameter.scalarType == effects::ScalarType::Float && parameter.parameterClass != effects::ParameterClass::Struct &&
        (byteCount % 4U) == 0U) {
      mProgram->Parameters().SetFloats(static_cast<std::uint32_t>(mParameter), static_cast<const float*>(data), byteCount / 4U);
      return;
    }
    mProgram->Parameters().SetPacked(static_cast<std::uint32_t>(mParameter), data, byteCount);
  }

  void ProgramEffectVariable::SetFloat(const float value)
  {
    if (mParameter >= 0) {
      mProgram->Parameters().SetScalar(static_cast<std::uint32_t>(mParameter), value);
    }
  }

  void ProgramEffectVariable::SetInt(const int value)
  {
    if (mParameter >= 0) {
      mProgram->Parameters().SetScalar(static_cast<std::uint32_t>(mParameter), value);
    }
  }

  void ProgramEffectVariable::SetBool(const bool value)
  {
    if (mParameter >= 0) {
      mProgram->Parameters().SetScalar(static_cast<std::uint32_t>(mParameter), value ? 1.0 : 0.0);
    }
  }

  void ProgramEffectVariable::SetMatrixArray(const std::uint32_t count, const Matrix* const matrices)
  {
    if (mParameter >= 0 && matrices != nullptr) {
      mProgram->Parameters().SetMatrixArray(static_cast<std::uint32_t>(mParameter), &matrices->r[0].x, count);
    }
  }

  void ProgramEffectVariable::SetVectorArray(const std::uint32_t count, const float* const vectors4)
  {
    if (mParameter >= 0) {
      mProgram->Parameters().SetVectorArray(static_cast<std::uint32_t>(mParameter), vectors4, count);
    }
  }

  const effects::Annotations* ProgramEffectVariable::OwnAnnotations() const
  {
    if (mParameter < 0) {
      return nullptr;
    }
    return &mProgram->Description().parameters[static_cast<std::size_t>(mParameter)].annotations;
  }

  bool ProgramEffectVariable::GetAnnotationBool(bool* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(OwnAnnotations(), annotationName, [&](const effects::Annotation& a) {
      double value = 0.0;
      if (!AnnotationNumber(a, value)) {
        return false;
      }
      *outValue = value != 0.0;
      return true;
    });
  }

  bool ProgramEffectVariable::GetAnnotationInt(int* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(OwnAnnotations(), annotationName, [&](const effects::Annotation& a) {
      double value = 0.0;
      if (!AnnotationNumber(a, value)) {
        return false;
      }
      *outValue = static_cast<int>(value);
      return true;
    });
  }

  bool ProgramEffectVariable::GetAnnotationFloat(float* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(OwnAnnotations(), annotationName, [&](const effects::Annotation& a) {
      double value = 0.0;
      if (!AnnotationNumber(a, value)) {
        return false;
      }
      *outValue = static_cast<float>(value);
      return true;
    });
  }

  bool ProgramEffectVariable::GetAnnotationString(msvc8::string* const outValue, const msvc8::string& annotationName)
  {
    return ReadAnnotation(OwnAnnotations(), annotationName, [&](const effects::Annotation& a) {
      if (a.kind != effects::Annotation::Kind::String) {
        return false;
      }
      outValue->assign_owned(a.text.c_str());
      return true;
    });
  }
} // namespace gpg::gal
