// FAF addition, not in the shipped binary: see ShaderCompiler.h.

#include "ShaderCompiler.h"

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <wrl/client.h>

#include <algorithm>
#include <cctype>
#include <d3d12shader.h>

#include "dxcapi.h"

namespace gpg::gal::effects
{
  using Microsoft::WRL::ComPtr;

  struct ShaderCompiler::Library
  {
    HMODULE signer = nullptr;   // dxil.dll
    HMODULE compiler = nullptr; // dxcompiler.dll
    ComPtr<IDxcUtils> utils;
    ComPtr<IDxcCompiler3> dxc;
    std::mutex mutex; // one compiler object: not for concurrent use
  };

  namespace
  {
    [[nodiscard]] std::wstring ExecutableDirectory()
    {
      wchar_t path[MAX_PATH]{};
      const DWORD length = ::GetModuleFileNameW(nullptr, path, MAX_PATH);
      std::wstring directory(path, length);
      const std::size_t slash = directory.find_last_of(L"\\/");
      return (slash == std::wstring::npos) ? std::wstring() : directory.substr(0U, slash + 1U);
    }

    [[nodiscard]] std::wstring Widen(const std::string_view text)
    {
      if (text.empty()) {
        return {};
      }
      const int length = ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
      std::wstring wide(static_cast<std::size_t>(length), L'\0');
      ::MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()), wide.data(), length);
      return wide;
    }
  } // namespace

  ShaderCompiler& ShaderCompiler::Instance()
  {
    static ShaderCompiler compiler;
    return compiler;
  }

  ShaderCompiler::ShaderCompiler()
  {
    std::vector<std::wstring> directories{ExecutableDirectory()};
    if (const char* const configured = std::getenv("FAF_DXC_DIR"); configured != nullptr && configured[0] != '\0') {
      std::wstring directory = Widen(configured);
      if (directory.back() != L'\\' && directory.back() != L'/') {
        directory += L'\\';
      }
      directories.push_back(directory);
    }

    auto library = new Library();
    for (const std::wstring& directory : directories) {
      // Loading the signer first by path lets dxcompiler's own
      // LoadLibrary("dxil.dll") find it.
      library->signer = ::LoadLibraryW((directory + L"dxil.dll").c_str());
      library->compiler = ::LoadLibraryW((directory + L"dxcompiler.dll").c_str());
      if (library->compiler != nullptr) {
        break;
      }
      if (library->signer != nullptr) {
        ::FreeLibrary(library->signer);
        library->signer = nullptr;
      }
    }
    if (library->compiler == nullptr) {
      mLoadError = "dxcompiler.dll not found next to the executable or in FAF_DXC_DIR";
      delete library;
      return;
    }

    const auto create = reinterpret_cast<DxcCreateInstanceProc>(::GetProcAddress(library->compiler, "DxcCreateInstance"));
    if (create == nullptr || FAILED(create(CLSID_DxcUtils, IID_PPV_ARGS(&library->utils))) ||
        FAILED(create(CLSID_DxcCompiler, IID_PPV_ARGS(&library->dxc)))) {
      mLoadError = "dxcompiler.dll does not provide IDxcCompiler3";
      library->utils.Reset();
      library->dxc.Reset();
      ::FreeLibrary(library->compiler);
      if (library->signer != nullptr) {
        ::FreeLibrary(library->signer);
      }
      delete library;
      return;
    }

    ComPtr<IDxcVersionInfo> versionInfo;
    UINT32 major = 0U;
    UINT32 minor = 0U;
    if (SUCCEEDED(library->dxc.As(&versionInfo)) && SUCCEEDED(versionInfo->GetVersion(&major, &minor))) {
      char version[64]{};
      std::snprintf(version, sizeof(version), "dxc %u.%u%s", major, minor, library->signer != nullptr ? " signed" : " unsigned");
      mVersion = version;
    } else {
      mVersion = "dxc";
    }
    mLibrary = library;
  }

  ShaderCompiler::~ShaderCompiler()
  {
    // Process-lifetime singleton: the modules stay loaded until exit.
    if (mLibrary != nullptr) {
      mLibrary->utils.Reset();
      mLibrary->dxc.Reset();
    }
  }

  bool ShaderCompiler::Available() const noexcept
  {
    return mLibrary != nullptr;
  }

  const std::string& ShaderCompiler::LoadError() const noexcept
  {
    return mLoadError;
  }

  const std::string& ShaderCompiler::Version() const noexcept
  {
    return mVersion;
  }

  CompiledShader ShaderCompiler::Compile(
    const std::string_view hlsl, const ShaderEntry& entry, const ShaderTarget target, const std::vector<std::wstring>& extraArguments
  ) const
  {
    CompiledShader result;
    if (mLibrary == nullptr) {
      result.messages = mLoadError;
      return result;
    }

    const std::wstring entryName = Widen(entry.name);
    std::vector<std::wstring> arguments{
      L"-E", entryName,
      L"-T", entry.stage == ShaderStage::Vertex ? L"vs_6_0" : L"ps_6_0",
      // HLSL 2018: the effects predate 2021's stricter vector logic.
      L"-HV", L"2018",
      // Row-major matrices: the parameter store keeps the engine's layout.
      L"-Zpr",
      L"-O3",
      L"-D", entry.stage == ShaderStage::Vertex ? L"FAF_VERTEX_STAGE=1" : L"FAF_PIXEL_STAGE=1",
      // FXC accepted these silently.
      L"-Wno-conversion",
    };
    if (target == ShaderTarget::Spirv) {
      // The Vulkan backend's descriptor model: textures t<n> and samplers
      // s<n> in set 0 at bindings n and 64+n, $Globals alone in set 1.
      // D3D's clip-space y points the other way.
      arguments.insert(arguments.end(), {L"-spirv", L"-fvk-use-dx-layout", L"-fspv-reflect", L"-fspv-target-env=vulkan1.1",
                                         L"-fvk-t-shift", L"0", L"0", L"-fvk-s-shift", L"64", L"0", L"-fvk-b-shift", L"0", L"0",
                                         L"-fvk-bind-globals", L"0", L"1"});
      if (entry.stage == ShaderStage::Vertex) {
        arguments.push_back(L"-fvk-invert-y");
      }
    }
    arguments.insert(arguments.end(), extraArguments.begin(), extraArguments.end());

    std::vector<LPCWSTR> argumentPointers;
    argumentPointers.reserve(arguments.size());
    for (const std::wstring& argument : arguments) {
      argumentPointers.push_back(argument.c_str());
    }

    DxcBuffer source{};
    source.Ptr = hlsl.data();
    source.Size = hlsl.size();
    source.Encoding = DXC_CP_UTF8;

    const std::lock_guard<std::mutex> lock(mLibrary->mutex);
    ComPtr<IDxcResult> compiled;
    const HRESULT hr = mLibrary->dxc->Compile(
      &source, argumentPointers.data(), static_cast<UINT32>(argumentPointers.size()), nullptr, IID_PPV_ARGS(&compiled)
    );
    if (FAILED(hr) || compiled == nullptr) {
      char message[64]{};
      std::snprintf(message, sizeof(message), "IDxcCompiler3::Compile failed (0x%08lX)", static_cast<unsigned long>(hr));
      result.messages = message;
      return result;
    }

    ComPtr<IDxcBlobUtf8> errors;
    if (SUCCEEDED(compiled->GetOutput(DXC_OUT_ERRORS, IID_PPV_ARGS(&errors), nullptr)) && errors != nullptr &&
        errors->GetStringLength() != 0U) {
      result.messages.assign(errors->GetStringPointer(), errors->GetStringLength());
    }
    HRESULT status = E_FAIL;
    compiled->GetStatus(&status);
    if (FAILED(status)) {
      return result;
    }
    ComPtr<IDxcBlob> object;
    if (FAILED(compiled->GetOutput(DXC_OUT_OBJECT, IID_PPV_ARGS(&object), nullptr)) || object == nullptr) {
      result.messages += "\nno object produced";
      return result;
    }
    const auto* const bytes = static_cast<const std::uint8_t*>(object->GetBufferPointer());
    result.code.assign(bytes, bytes + object->GetBufferSize());
    result.succeeded = true;
    return result;
  }

  std::vector<ShaderInput> ShaderCompiler::ReflectInputs(const std::vector<std::uint8_t>& dxil) const
  {
    std::vector<ShaderInput> inputs;
    if (mLibrary == nullptr || dxil.empty()) {
      return inputs;
    }
    DxcBuffer buffer{};
    buffer.Ptr = dxil.data();
    buffer.Size = dxil.size();
    const std::lock_guard<std::mutex> lock(mLibrary->mutex);
    ComPtr<ID3D12ShaderReflection> reflection;
    if (FAILED(mLibrary->utils->CreateReflection(&buffer, IID_PPV_ARGS(&reflection)))) {
      return inputs;
    }
    D3D12_SHADER_DESC desc{};
    if (FAILED(reflection->GetDesc(&desc))) {
      return inputs;
    }
    for (UINT index = 0U; index < desc.InputParameters; ++index) {
      D3D12_SIGNATURE_PARAMETER_DESC parameter{};
      if (FAILED(reflection->GetInputParameterDesc(index, &parameter))) {
        continue;
      }
      ShaderInput input;
      input.semantic = (parameter.SemanticName != nullptr) ? parameter.SemanticName : "";
      std::transform(input.semantic.begin(), input.semantic.end(), input.semantic.begin(), [](const unsigned char c) {
        return static_cast<char>(std::toupper(c));
      });
      input.index = parameter.SemanticIndex;
      input.component = (parameter.ComponentType == D3D_REGISTER_COMPONENT_UINT32) ? ShaderInput::Component::Uint
        : (parameter.ComponentType == D3D_REGISTER_COMPONENT_SINT32)                ? ShaderInput::Component::Sint
                                                                                    : ShaderInput::Component::Float;
      input.mask = parameter.Mask;
      input.systemValue = parameter.SystemValueType != D3D_NAME_UNDEFINED;
      inputs.push_back(std::move(input));
    }
    return inputs;
  }
} // namespace gpg::gal::effects
