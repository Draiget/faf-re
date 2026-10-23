// FAF addition, not in the shipped binary: the Direct3D 11 gal device.

#include "DeviceD3D11.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>
#include <vector>

#include <d3d11.h>
#include <d3d11_4.h> // ID3D11Multithread
#include <d3dcompiler.h>
#include <d3d11shader.h>
#include <d3dx11effect.h>
// D3DX11 (DirectX SDK, June 2010) loads and saves texture files, as D3DX10
// does for the D3D10 backend. Its exports are linked at run time from
// d3dx11_43.dll; only the declarations come from the header.
#include <d3dx11tex.h>

#include "BufferD3D11.h"
#include "D3D11Common.h"
#include "D3D11VertexLayouts.h"
#include "EffectD3D11.h"
#include "EffectSourceD3D11.h"
#include "RenderTargetD3D11.h"
#include "TextureD3D11.h"

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/CubeRenderTargetContext.hpp"
#include "gpg/gal/CursorContext.hpp"
#include "gpg/gal/DepthStencilTargetContext.hpp"
#include "gpg/gal/DrawContext.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/DrawStatistics.h"
#include "gpg/gal/DxgiAdapterInfo.h"
#include "gpg/gal/EffectContext.hpp"
#include "gpg/gal/EffectMacro.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/IndexBufferContext.hpp"
#include "gpg/gal/RenderTargetContext.hpp"
#include "gpg/gal/TextureContext.h"
#include "gpg/gal/VertexBufferContext.hpp"

namespace gpg::gal
{
  using Microsoft::WRL::ComPtr;
  using d3d11::CheckHresult;
  using d3d11::ThrowError;

  // ---------------------------------------------------------------------------
  // D3DX11, linked at run time

  class D3DX11Library
  {
  public:
    D3DX11Library()
    {
      mModule = ::LoadLibraryA("d3dx11_43.dll");
      if (mModule == nullptr) {
        ThrowError("DeviceD3D11.cpp", __LINE__, "unable to explicitly link to d3dx11_43.dll");
      }
      createTextureFromMemory =
        reinterpret_cast<decltype(&::D3DX11CreateTextureFromMemory)>(::GetProcAddress(mModule, "D3DX11CreateTextureFromMemory"));
      saveTextureToFile =
        reinterpret_cast<decltype(&::D3DX11SaveTextureToFileA)>(::GetProcAddress(mModule, "D3DX11SaveTextureToFileA"));
      saveTextureToMemory =
        reinterpret_cast<decltype(&::D3DX11SaveTextureToMemory)>(::GetProcAddress(mModule, "D3DX11SaveTextureToMemory"));
      if (createTextureFromMemory == nullptr || saveTextureToFile == nullptr || saveTextureToMemory == nullptr) {
        ThrowError("DeviceD3D11.cpp", __LINE__, "d3dx11_43.dll lacks the texture exports");
      }
    }

    D3DX11Library(const D3DX11Library&) = delete;
    D3DX11Library& operator=(const D3DX11Library&) = delete;

    ~D3DX11Library()
    {
      if (mModule != nullptr) {
        ::FreeLibrary(mModule);
      }
    }

    decltype(&::D3DX11CreateTextureFromMemory) createTextureFromMemory = nullptr;
    decltype(&::D3DX11SaveTextureToFileA) saveTextureToFile = nullptr;
    decltype(&::D3DX11SaveTextureToMemory) saveTextureToMemory = nullptr;

  private:
    HMODULE mModule = nullptr;
  };

  namespace
  {
    constexpr char kSignatureEffectSource[] =
#include "gpg/gal/backends/d3d10/D3D10SignatureEffectSource.inl"
      ;
    constexpr char kRttEffectSource[] =
#include "gpg/gal/backends/d3d10/D3D10RTTEffectSource.inl"
      ;

    struct MacroPair
    {
      const char* name;
      const char* value;
    };

    // DeviceD3D10::CreateEffect's twenty macros (0x008FEA00), plus one naming
    // this backend for effect sources that want to tell the two apart.
    constexpr MacroPair kInjectedMacros[] = {
      {"technique", "technique10"},
      {"VERSION", "DIRECT3D10"},
      {"vs_1_1", "vs_4_0"},
      {"vs_1_3", "vs_4_0"},
      {"vs_1_4", "vs_4_0"},
      {"vs_2_0", "vs_4_0"},
      {"vs_3_0", "vs_4_0"},
      {"ps_1_1", "ps_4_0"},
      {"ps_1_3", "ps_4_0"},
      {"ps_1_4", "ps_4_0"},
      {"ps_2_0", "ps_4_0"},
      {"ps_2_a", "ps_4_0"},
      {"ps_2_b", "ps_4_0"},
      {"ps_3_0", "ps_4_0"},
      {"MipFilter", "Filter"},
      {"MinFilter", "Filter"},
      {"MagFilter", "Filter"},
      {"NONE", "MIN_MAG_MIP_POINT"},
      {"LINEAR", "MIN_MAG_MIP_LINEAR"},
      {"POINT", "MIN_MAG_MIP_POINT"},
      {"DIRECT3D11", "1"},
    };

    // The effect dialect is D3D10's (vs_4_0/ps_4_0 shaders), but the effect
    // container is fx_5_0: d3dcompiler_47 wraps fx_4_0 output in a DXBC
    // container that Effects 11 refuses ("Effect version is unrecognized").
    // HLSL flags as DeviceD3D10::CreateEffect.
    constexpr const char* kEffectProfile = "fx_5_0";
    // Bump when EffectSourceD3D11's output changes, to retire cached blobs.
    constexpr const char* kTranslatorVersion = "translator 7";
    // Added to every viewport origin: D3D9 pixel centres in D3D11 (see SetViewport).
    constexpr float kD3D9PixelCentreOffset = 0.5f;
    constexpr UINT kEffectCompileFlags = D3DCOMPILE_ENABLE_BACKWARDS_COMPATIBILITY;
    constexpr UINT kHelperCompileFlags = D3DCOMPILE_ENABLE_STRICTNESS;

    // D3D10's primitive topology per gal token (0x00D43078).
    constexpr D3D11_PRIMITIVE_TOPOLOGY kTopologyByToken[15] = {
      D3D11_PRIMITIVE_TOPOLOGY_UNDEFINED,
      D3D11_PRIMITIVE_TOPOLOGY_POINTLIST,
      D3D11_PRIMITIVE_TOPOLOGY_LINELIST,
      D3D11_PRIMITIVE_TOPOLOGY_LINESTRIP,
      D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST,
      D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP,
      D3D11_PRIMITIVE_TOPOLOGY_LINELIST_ADJ,
      D3D11_PRIMITIVE_TOPOLOGY_LINESTRIP_ADJ,
      D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST_ADJ,
      D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP_ADJ,
      D3D11_PRIMITIVE_TOPOLOGY_UNDEFINED,
      D3D11_PRIMITIVE_TOPOLOGY_POINTLIST,
      D3D11_PRIMITIVE_TOPOLOGY_LINESTRIP,
      D3D11_PRIMITIVE_TOPOLOGY_LINESTRIP,
      D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST,
    };

    // gal image file format -> D3DX11_IMAGE_FILE_FORMAT (D3D10's 0x00D430A0).
    constexpr D3DX11_IMAGE_FILE_FORMAT kImageFileFormats[5] = {
      D3DX11_IFF_BMP, D3DX11_IFF_JPG, D3DX11_IFF_PNG, D3DX11_IFF_PNG, D3DX11_IFF_DDS,
    };

    struct RttVertex
    {
      float x, y, z, u, v;
    };

    constexpr RttVertex kRttFullscreenVertices[4] = {
      {-1.0f, -1.0f, 0.0f, 0.0f, 1.0f},
      {1.0f, -1.0f, 0.0f, 1.0f, 1.0f},
      {-1.0f, 1.0f, 0.0f, 0.0f, 0.0f},
      {1.0f, 1.0f, 0.0f, 1.0f, 0.0f},
    };

    [[nodiscard]] D3DX11_IMAGE_FILE_FORMAT ImageFileFormat(const int galFormat) noexcept
    {
      return (galFormat >= 0 && galFormat < 5) ? kImageFileFormats[galFormat] : D3DX11_IFF_BMP;
    }

    [[nodiscard]] const char* FeatureLevelName(const D3D_FEATURE_LEVEL level) noexcept
    {
      switch (level) {
      case D3D_FEATURE_LEVEL_11_1:
        return "11_1";
      case D3D_FEATURE_LEVEL_11_0:
        return "11_0";
      case D3D_FEATURE_LEVEL_10_1:
        return "10_1";
      case D3D_FEATURE_LEVEL_10_0:
        return "10_0";
      default:
        return "unknown";
      }
    }

    /** Case-insensitive search of the process command line for `option`. */
    [[nodiscard]] bool CommandLineHas(const char* const option)
    {
      std::string commandLine = ::GetCommandLineA();
      std::string needle = option;
      const auto lower = [](std::string& text) {
        std::transform(text.begin(), text.end(), text.begin(), [](const unsigned char c) {
          return static_cast<char>(std::tolower(c));
        });
      };
      lower(commandLine);
      lower(needle);
      return commandLine.find(needle) != std::string::npos;
    }

    // FNV-1a, 64-bit: keys the compiled-effect cache.
    class Fnv1a64
    {
    public:
      void Add(const void* const data, const std::size_t bytes) noexcept
      {
        const auto* const begin = static_cast<const unsigned char*>(data);
        for (std::size_t index = 0U; index < bytes; ++index) {
          mHash ^= begin[index];
          mHash *= 0x100000001B3ULL;
        }
      }
      void AddString(const char* const text) noexcept
      {
        if (text != nullptr) {
          Add(text, std::strlen(text) + 1U);
        } else {
          Add("", 1U);
        }
      }
      [[nodiscard]] std::uint64_t Value() const noexcept { return mHash; }

    private:
      std::uint64_t mHash = 0xCBF29CE484222325ULL;
    };

    struct EffectCacheHeader
    {
      char magic[8];
      std::uint64_t key;
      std::uint64_t blobBytes;
    };

    constexpr char kEffectCacheMagic[8] = {'F', 'A', 'F', 'F', 'X', '1', '1', '1'};

    [[nodiscard]] std::vector<char> ReadEffectCache(const std::string& path, const std::uint64_t key, bool& stale)
    {
      std::vector<char> blob;
      stale = false;
      HANDLE const file = ::CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0U, nullptr);
      if (file == INVALID_HANDLE_VALUE) {
        const DWORD error = ::GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
          gpg::Warnf("D3D11: cannot open %s (error %lu)", path.c_str(), static_cast<unsigned long>(error));
        }
        return blob;
      }
      EffectCacheHeader header{};
      DWORD read = 0U;
      if (::ReadFile(file, &header, sizeof(header), &read, nullptr) && read == sizeof(header) &&
          std::memcmp(header.magic, kEffectCacheMagic, sizeof(kEffectCacheMagic)) == 0 && header.key == key &&
          header.blobBytes != 0U && header.blobBytes < (64ULL << 20U)) {
        blob.resize(static_cast<std::size_t>(header.blobBytes));
        if (!::ReadFile(file, blob.data(), static_cast<DWORD>(blob.size()), &read, nullptr) || read != blob.size()) {
          blob.clear();
        }
      } else {
        stale = true;
      }
      ::CloseHandle(file);
      return blob;
    }

    void WriteEffectCache(const std::string& path, const std::uint64_t key, const void* const blob, const std::size_t bytes)
    {
      const std::string temporary = path + ".tmp";
      HANDLE const file = ::CreateFileA(temporary.c_str(), GENERIC_WRITE, 0U, nullptr, CREATE_ALWAYS, 0U, nullptr);
      if (file == INVALID_HANDLE_VALUE) {
        return;
      }
      EffectCacheHeader header{};
      std::memcpy(header.magic, kEffectCacheMagic, sizeof(kEffectCacheMagic));
      header.key = key;
      header.blobBytes = bytes;
      DWORD written = 0U;
      const bool ok = ::WriteFile(file, &header, sizeof(header), &written, nullptr) && written == sizeof(header) &&
        ::WriteFile(file, blob, static_cast<DWORD>(bytes), &written, nullptr) && written == bytes;
      ::CloseHandle(file);
      if (!ok || !::MoveFileExA(temporary.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        ::DeleteFileA(temporary.c_str());
      }
    }

    /** The first lines of a compiler message, short enough for a dialog. */
    [[nodiscard]] std::string TrimCompilerMessage(ID3DBlob* const errors)
    {
      if (errors == nullptr) {
        return "unknown error";
      }
      std::string text(static_cast<const char*>(errors->GetBufferPointer()), errors->GetBufferSize());
      while (!text.empty() && (text.back() == '\0' || text.back() == '\n' || text.back() == '\r')) {
        text.pop_back();
      }
      if (text.size() > 1500U) {
        text.resize(1500U);
        text += "...";
      }
      return text;
    }
  } // namespace

  // ---------------------------------------------------------------------------
  // Construction and setup

  DeviceD3D11::DeviceD3D11() = default;

  DeviceD3D11::~DeviceD3D11()
  {
    Shutdown();
  }

  void DeviceD3D11::Shutdown() noexcept
  {
    if (mImmediate != nullptr) {
      mImmediate->ClearState();
      mImmediate->Flush();
    }
    outputContext_ = OutputContext();
    mHeadOutputContexts.clear();
    mGpuDriven.reset();
    mSwapChains.clear(); // leaves exclusive full screen first
    mShaderInputLayouts.clear();
    for (ComPtr<ID3D11InputLayout>& layout : mInputLayouts) {
      layout.Reset();
    }
    mRttInputLayout.Reset();
    mClearVertexShader.Reset();
    mClearPixelShader.Reset();
    mClearConstants.Reset();
    mClearRasterizer.Reset();
    for (ComPtr<ID3D11BlendState>& state : mClearBlend) {
      state.Reset();
    }
    for (ComPtr<ID3D11DepthStencilState>& state : mClearDepthStencil) {
      state.Reset();
    }
    mRttQuadVertexBuffer.Reset();
    mRttTechnique = nullptr;
    mRttEffect.Reset();
    mSignatureEffect.Reset();
    mPipelineState.reset();
    mCursor.Destroy();
    mInfoQueue.Reset();
    mDecodeContext.Reset();
    mDecodeDevice.Reset();
    mImmediate.Reset();
    mDevice.Reset();
    mD3DX11.reset();
    mFactory.Release();
    mDeviceContext = DeviceContext(DeviceApi::Unset);
  }

  void DeviceD3D11::CreateDevice()
  {
    const dxgi::AdapterInfo& adapter = mFactory.Adapters()[mAdapterIndex];

    UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
    const bool debugLayer = CommandLineHas("/d3d11debug");
    if (debugLayer) {
      flags |= D3D11_CREATE_DEVICE_DEBUG;
    }

    const D3D_FEATURE_LEVEL levels[] = {
      D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0,
    };
    // An adapter is given, so the driver type must be UNKNOWN.
    HRESULT result = ::D3D11CreateDevice(
      adapter.adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, flags, levels, static_cast<UINT>(std::size(levels)),
      D3D11_SDK_VERSION, &mDevice, &mFeatureLevel, &mImmediate
    );
    if (result == E_INVALIDARG) {
      // A pre-11.1 runtime rejects the 11_1 entry.
      result = ::D3D11CreateDevice(
        adapter.adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, flags, levels + 1, static_cast<UINT>(std::size(levels) - 1U),
        D3D11_SDK_VERSION, &mDevice, &mFeatureLevel, &mImmediate
      );
    }
    if (FAILED(result) && debugLayer) {
      gpg::Warnf("D3D11: the debug layer is not installed; creating the device without it");
      flags &= ~static_cast<UINT>(D3D11_CREATE_DEVICE_DEBUG);
      result = ::D3D11CreateDevice(
        adapter.adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr, flags, levels + 1, static_cast<UINT>(std::size(levels) - 1U),
        D3D11_SDK_VERSION, &mDevice, &mFeatureLevel, &mImmediate
      );
    }
    CheckHresult("DeviceD3D11.cpp", __LINE__, result);

    if ((flags & D3D11_CREATE_DEVICE_DEBUG) != 0U) {
      static_cast<void>(mDevice.As(&mInfoQueue));
    }

    // The D3D9 device is created D3DCREATE_MULTITHREADED (0x44 at 0x008F1752);
    // keep the same guarantee for the immediate context.
    ComPtr<ID3D11Multithread> multithread;
    if (SUCCEEDED(mImmediate.As(&multithread))) {
      static_cast<void>(multithread->SetMultithreadProtected(TRUE));
    }

    gpg::Logf(
      "D3D11: device created on adapter %u '%s' (vendor 0x%04X device 0x%04X, %u MB VRAM), feature level %s%s",
      mAdapterIndex,
      adapter.Name().c_str(),
      adapter.desc.VendorId,
      adapter.desc.DeviceId,
      static_cast<unsigned>(adapter.desc.DedicatedVideoMemory >> 20U),
      FeatureLevelName(mFeatureLevel),
      ((flags & D3D11_CREATE_DEVICE_DEBUG) != 0U) ? ", debug layer" : ""
    );
  }

  void DeviceD3D11::CreateSwapChains(const DeviceContext& context)
  {
    mSwapChains.clear();
    const bool allowFlip = !CommandLineHas("/d3d11blt");
    for (int headIndex = 0; headIndex < context.GetHeadCount(); ++headIndex) {
      const Head& head = context.GetHead(static_cast<std::uint32_t>(headIndex));

      dxgi::SwapChainDesc desc{};
      desc.window = static_cast<HWND>(head.mWindow);
      desc.width = head.mWidth;
      desc.height = head.mHeight;
      desc.format = DXGI_FORMAT_B8G8R8A8_UNORM;
      // `Head::mWindowed` is a full-screen flag: the D3D10 backend writes
      // DXGI's Windowed as its negation (`BuildSwapChainDescFromHead`).
      desc.fullscreen = head.mWindowed;
      desc.refreshHz = head.framesPerSecond;
      desc.usage = DXGI_USAGE_RENDER_TARGET_OUTPUT | DXGI_USAGE_SHADER_INPUT;
      desc.allowFlipModel = allowFlip;
      if (desc.width == 0U || desc.height == 0U) {
        RECT client{};
        ::GetClientRect(desc.window, &client);
        desc.width = static_cast<std::uint32_t>(std::max<LONG>(client.right - client.left, 1));
        desc.height = static_cast<std::uint32_t>(std::max<LONG>(client.bottom - client.top, 1));
      }

      auto swapChain = std::make_unique<dxgi::SwapChain>();
      CheckHresult("DeviceD3D11.cpp", __LINE__, swapChain->Create(mFactory, mDevice.Get(), desc));
      gpg::Logf(
        "D3D11: head %d swap chain %ux%u %s, %s%s",
        headIndex,
        desc.width,
        desc.height,
        desc.fullscreen ? "full screen" : "windowed",
        dxgi::SwapModelName(swapChain->Model()),
        swapChain->AllowsTearing() ? ", tearing allowed" : ""
      );
      mSwapChains.push_back(std::move(swapChain));
    }
  }

  ComPtr<ID3DX11Effect> DeviceD3D11::CompileEffect(
    const char* const source,
    const std::size_t sourceBytes,
    const char* const sourceName,
    const D3D_SHADER_MACRO* const defines,
    const char* const cachePath
  )
  {
    const UINT flags = (sourceName != nullptr) ? kEffectCompileFlags : kHelperCompileFlags;

    Fnv1a64 key;
    key.AddString("FAF D3D11 effect cache 1");
    key.AddString(kEffectProfile);
    key.AddString(kTranslatorVersion);
    key.Add(&mFeatureLevel, sizeof(mFeatureLevel));
    key.Add(&flags, sizeof(flags));
    key.Add(source, sourceBytes);
    for (const D3D_SHADER_MACRO* macro = defines; macro != nullptr && macro->Name != nullptr; ++macro) {
      key.AddString(macro->Name);
      key.AddString(macro->Definition);
    }

    const std::string cacheFile = (cachePath != nullptr && cachePath[0] != '\0') ? std::string(cachePath) + ".d3d11fx" : std::string();
    if (!cacheFile.empty()) {
      bool stale = false;
      const std::vector<char> cached = ReadEffectCache(cacheFile, key.Value(), stale);
      if (stale) {
        gpg::Logf("D3D11: cached %s is stale; recompiling", cacheFile.c_str());
      }
      if (!cached.empty()) {
        ComPtr<ID3DX11Effect> effect;
        const HRESULT result = ::D3DX11CreateEffectFromMemory(cached.data(), cached.size(), 0U, mDevice.Get(), &effect, sourceName);
        if (SUCCEEDED(result)) {
          return effect;
        }
        gpg::Logf("D3D11: cached %s did not load (HRESULT 0x%08lX); recompiling", cacheFile.c_str(), static_cast<unsigned long>(result));
      }
    }

    const DWORD started = ::GetTickCount();

    // Game effects go through the override layer: preprocess with the macros,
    // rewrite the D3D9-isms (EffectSourceD3D11.h), compile the result.
    std::string translated;
    const char* compileSource = source;
    std::size_t compileBytes = sourceBytes;
    const D3D_SHADER_MACRO* compileDefines = defines;
    if (sourceName != nullptr) {
      ComPtr<ID3DBlob> preprocessed;
      ComPtr<ID3DBlob> errors;
      if (FAILED(::D3DPreprocess(source, sourceBytes, sourceName, defines, nullptr, &preprocessed, &errors))) {
        const std::string message = std::string("unable to preprocess effect: ") + sourceName + " reason: " + TrimCompilerMessage(errors.Get());
        ThrowError("DeviceD3D11.cpp", __LINE__, message.c_str());
      }
      d3d11::TranslatedEffectSource result = d3d11::TranslateEffectSource(
        std::string_view(static_cast<const char*>(preprocessed->GetBufferPointer()), preprocessed->GetBufferSize() - 1U),
        mFeatureLevel >= D3D_FEATURE_LEVEL_10_1,
        std::string_view(source, sourceBytes)
      );
      for (const std::string& note : result.notes) {
        gpg::Logf("D3D11: %s: %s", sourceName, note.c_str());
      }
      translated = std::move(result.source);
      compileSource = translated.data();
      compileBytes = translated.size();
      compileDefines = nullptr;
    }

    ComPtr<ID3DBlob> compiled;
    ComPtr<ID3DBlob> errors;
    const HRESULT compileResult = ::D3DCompile(
      compileSource, compileBytes, sourceName, compileDefines, nullptr, nullptr, kEffectProfile, flags, 0U, &compiled, &errors
    );
    if (FAILED(compileResult)) {
      if (!translated.empty() && !cacheFile.empty()) {
        // Keep what was compiled, for whoever fixes the override layer.
        const std::string dump = cacheFile + ".failed.fx";
        if (FILE* const file = std::fopen(dump.c_str(), "wb")) {
          std::fwrite(translated.data(), 1U, translated.size(), file);
          std::fclose(file);
        }
      }
      const std::string message = std::string("unable to create effect: ") + ((sourceName != nullptr) ? sourceName : "(built-in)") +
        " reason: " + TrimCompilerMessage(errors.Get());
      ThrowError("DeviceD3D11.cpp", __LINE__, message.c_str());
    }

    ComPtr<ID3DX11Effect> effect;
    const HRESULT createResult =
      ::D3DX11CreateEffectFromMemory(compiled->GetBufferPointer(), compiled->GetBufferSize(), 0U, mDevice.Get(), &effect, sourceName);
    if (FAILED(createResult)) {
      char message[512]{};
      std::snprintf(
        message, sizeof(message), "unable to load effect %s into Effects 11: HRESULT 0x%08lX",
        (sourceName != nullptr) ? sourceName : "(built-in)", static_cast<unsigned long>(createResult)
      );
      ThrowError("DeviceD3D11.cpp", __LINE__, message);
    }

    if (sourceName != nullptr) {
      gpg::Logf("D3D11: compiled effect %s as %s in %lu ms", sourceName, kEffectProfile, ::GetTickCount() - started);
    }
    if (!cacheFile.empty()) {
      WriteEffectCache(cacheFile, key.Value(), compiled->GetBufferPointer(), compiled->GetBufferSize());
    }
    return effect;
  }

  void DeviceD3D11::CreateHelperEffects()
  {
    mSignatureEffect = CompileEffect(kSignatureEffectSource, sizeof(kSignatureEffectSource) - 1U, nullptr, nullptr, nullptr);
    mRttEffect = CompileEffect(kRttEffectSource, sizeof(kRttEffectSource) - 1U, nullptr, nullptr, nullptr);
    mRttTechnique = mRttEffect->GetTechniqueByName("RTT");
    if (mRttTechnique == nullptr || !mRttTechnique->IsValid()) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "internal D3D11 RTT effect error");
    }

    D3D11_BUFFER_DESC bufferDesc{};
    bufferDesc.ByteWidth = sizeof(kRttFullscreenVertices);
    bufferDesc.Usage = D3D11_USAGE_IMMUTABLE;
    bufferDesc.BindFlags = D3D11_BIND_VERTEX_BUFFER;
    D3D11_SUBRESOURCE_DATA initialData{};
    initialData.pSysMem = kRttFullscreenVertices;
    CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateBuffer(&bufferDesc, &initialData, &mRttQuadVertexBuffer));

    const D3D11_INPUT_ELEMENT_DESC elements[2] = {
      {"POSITION", 0U, DXGI_FORMAT_R32G32B32_FLOAT, 0U, 0U, D3D11_INPUT_PER_VERTEX_DATA, 0U},
      {"TEXCOORD", 0U, DXGI_FORMAT_R32G32_FLOAT, 0U, 12U, D3D11_INPUT_PER_VERTEX_DATA, 0U},
    };
    D3DX11_PASS_DESC passDesc{};
    CheckHresult("DeviceD3D11.cpp", __LINE__, mRttTechnique->GetPassByIndex(0U)->GetDesc(&passDesc));
    CheckHresult(
      "DeviceD3D11.cpp", __LINE__,
      mDevice->CreateInputLayout(elements, 2U, passDesc.pIAInputSignature, passDesc.IAInputSignatureSize, &mRttInputLayout)
    );
  }

  void DeviceD3D11::CheckAvailableFormats(DeviceContext* const context)
  {
    const DeviceApi api = context->mDeviceType;
    mDeviceContext = *context;
    mDeviceContext.mDeviceType = api;

    // The D3D10 backend's capabilities (`CheckAvailableFormats`, 0x008FF5B0).
    mDeviceContext.mMaxPrimitiveCount = 0x10000U;
    mDeviceContext.mMaxVertexCount = 0xFFFFU;
    mDeviceContext.mHWBasedInstancing = true;
    mDeviceContext.mVertexShaderProfile = 4;
    mDeviceContext.mPixelShaderProfile = 8;

    const dxgi::AdapterInfo& adapter = mFactory.Adapters()[mAdapterIndex];
    for (int headIndex = 0; headIndex < mDeviceContext.GetHeadCount(); ++headIndex) {
      Head& head = mDeviceContext.GetHead(static_cast<std::uint32_t>(headIndex));

      head.adapterModes.clear();
      for (const dxgi::OutputInfo& output : adapter.outputs) {
        for (const DXGI_MODE_DESC& mode : output.modes) {
          head.adapterModes.push_back(HeadAdapterMode{mode.Width, mode.Height, dxgi::AdapterInfo::RefreshHz(mode)});
        }
      }

      head.validFormats1.clear();
      for (std::int32_t format = 1; format < 8; ++format) {
        UINT support = 0U;
        const DXGI_FORMAT dxgiFormat = d3d11::RenderTargetFormatToDxgi(static_cast<std::uint32_t>(format));
        if (dxgiFormat != DXGI_FORMAT_UNKNOWN && SUCCEEDED(mDevice->CheckFormatSupport(dxgiFormat, &support)) &&
            (support & D3D11_FORMAT_SUPPORT_RENDER_TARGET) != 0U) {
          head.validFormats1.push_back(format);
        }
      }

      head.validFormats2.clear();
      for (std::int32_t format = 1; format < 20; ++format) {
        UINT support = 0U;
        const DXGI_FORMAT dxgiFormat = d3d11::TextureFormatToDxgi(static_cast<std::uint32_t>(format));
        if (dxgiFormat != DXGI_FORMAT_UNKNOWN && SUCCEEDED(mDevice->CheckFormatSupport(dxgiFormat, &support)) &&
            (support & D3D11_FORMAT_SUPPORT_TEXTURE2D) != 0U) {
          head.validFormats2.push_back(format);
        }
      }

      // No multisampled back buffer on this backend yet (a flip-model swap
      // chain cannot have one; it needs an MSAA target and a resolve), so no
      // antialiasing options are offered.
      head.mStrs.clear();
    }
  }

  void DeviceD3D11::CreateRenderTargets()
  {
    mHeadOutputContexts.clear();
    mHeadOutputContexts.resize(mSwapChains.size());

    for (std::size_t headIndex = 0U; headIndex < mSwapChains.size(); ++headIndex) {
      ComPtr<ID3D11Texture2D> backBuffer;
      CheckHresult("DeviceD3D11.cpp", __LINE__, mSwapChains[headIndex]->GetBuffer(backBuffer.GetAddressOf()));

      ComPtr<ID3D11RenderTargetView> renderTargetView;
      CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateRenderTargetView(backBuffer.Get(), nullptr, &renderTargetView));

      ComPtr<ID3D11ShaderResourceView> shaderResourceView;
      CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateShaderResourceView(backBuffer.Get(), nullptr, &shaderResourceView));

      D3D11_TEXTURE2D_DESC desc{};
      backBuffer->GetDesc(&desc);

      OutputContext& output = mHeadOutputContexts[headIndex];
      output.surface.reset(new RenderTargetD3D11(backBuffer.Get(), renderTargetView.Get(), shaderResourceView.Get()));
      gpg::Logf("D3D11: head %u back buffer target %p (%ux%u)", static_cast<unsigned>(headIndex), output.surface.get(), desc.Width, desc.Height);
      const DepthStencilTargetContext depthContext(desc.Width, desc.Height, 3U, false);
      output.depthStencil = CreateDepthStencilTarget(&depthContext);
    }

    if (!mHeadOutputContexts.empty()) {
      ClearTarget(&mHeadOutputContexts.front());
      D3DVIEWPORT9 viewport{};
      const RenderTargetContext* const context = mHeadOutputContexts.front().surface->GetContext();
      viewport.Width = context->width_;
      viewport.Height = context->height_;
      viewport.MaxZ = 1.0f;
      SetViewport(&viewport);
    }
  }

  void DeviceD3D11::ReleaseRenderTargets() noexcept
  {
    outputContext_ = OutputContext();
    mHeadOutputContexts.clear();
    if (mImmediate != nullptr) {
      mImmediate->OMSetRenderTargets(0U, nullptr, nullptr);
      mImmediate->ClearState();
      mImmediate->Flush();
    }
  }

  void DeviceD3D11::Setup(DeviceContext* const context)
  {
    mCurThreadId = static_cast<int>(::GetCurrentThreadId());
    mLog.clear();

    // Diagnostics: FAF_GAL_FAIL_SETUP=1 makes device creation fail, to exercise
    // the fallback to Direct3D 9 in CScApp::CreateDevice.
    if (const char* const fail = std::getenv("FAF_GAL_FAIL_SETUP"); fail != nullptr && fail[0] == '1') {
      ThrowError("DeviceD3D11.cpp", __LINE__, "device creation failed on request (FAF_GAL_FAIL_SETUP)");
    }

    CheckHresult("DeviceD3D11.cpp", __LINE__, mFactory.Create());
    mFactory.EnumerateAdapters(DXGI_FORMAT_B8G8R8A8_UNORM);
    if (mFactory.Adapters().empty()) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "unable to enumerate adapters");
    }
    const auto adapterCount = static_cast<std::int32_t>(mFactory.Adapters().size());
    mAdapterIndex = (context->mAdapter >= 0 && context->mAdapter < adapterCount) ? static_cast<std::uint32_t>(context->mAdapter) : 0U;

    CreateDevice();
    mD3DX11 = std::make_unique<D3DX11Library>();
    CreateSwapChains(*context);
    CreateHelperEffects();
    CreateInputLayouts();
    CreateClearResources();

    std::fill(std::begin(mStreamFrequencies), std::end(mStreamFrequencies), 0);
    mPipelineState.reset(new PipelineStateD3D11(mDevice.Get(), mImmediate.Get()));
    mPipelineState->SetDeviceState();

    CheckAvailableFormats(context);
    CreateRenderTargets();
    mGpuDriven = std::make_unique<GpuDrivenD3D11>(mDevice.Get(), mImmediate.Get(), mFeatureLevel);

    gpg::Logf(
      "D3D11: ready (%d head(s), effects fx_5_0 via Effects 11, vsync %s, GPU-driven features 0x%X)",
      mDeviceContext.GetHeadCount(),
      mDeviceContext.mVSync ? "on" : "off",
      mGpuDriven->Features()
    );
  }

  // ---------------------------------------------------------------------------
  // Device slots

  void* DeviceD3D11::GetLog()
  {
    return &mLog;
  }

  DeviceContext* DeviceD3D11::GetDeviceContext()
  {
    return &mDeviceContext;
  }

  int DeviceD3D11::GetCurThreadId()
  {
    return mCurThreadId;
  }

  void DeviceD3D11::Func1() const {}

  void DeviceD3D11::GetModesForAdapter(msvc8::vector<HeadAdapterMode>& outModes, const int adapterIndex)
  {
    outModes.clear();
    const auto& adapters = mFactory.Adapters();
    if (adapterIndex < 0 || adapterIndex >= static_cast<int>(adapters.size())) {
      return;
    }
    for (const dxgi::OutputInfo& output : adapters[static_cast<std::size_t>(adapterIndex)].outputs) {
      for (const DXGI_MODE_DESC& mode : output.modes) {
        outModes.push_back(HeadAdapterMode{mode.Width, mode.Height, dxgi::AdapterInfo::RefreshHz(mode)});
      }
    }
  }

  OutputContext* DeviceD3D11::GetHeadOutputContext(const unsigned int headIndex)
  {
    if (headIndex >= mHeadOutputContexts.size()) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "invalid head index specified");
    }
    return &mHeadOutputContexts[headIndex];
  }

  const OutputContext* DeviceD3D11::GetHeadOutputContext(const unsigned int headIndex) const
  {
    if (headIndex >= mHeadOutputContexts.size()) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "invalid head index specified");
    }
    return &mHeadOutputContexts[headIndex];
  }

  boost::shared_ptr<PipelineState> DeviceD3D11::GetPipelineState()
  {
    return mPipelineState;
  }

  boost::shared_ptr<Effect> DeviceD3D11::CreateEffect(const EffectContext& context)
  {
    if (context.mSourceType != 2U) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "invalid source defined for effect");
    }

    EffectContext localContext(context);
    for (const MacroPair& macro : kInjectedMacros) {
      localContext.DefineMacro(macro.name, macro.value);
    }

    std::vector<D3D_SHADER_MACRO> defines;
    defines.reserve(localContext.mMacros.size() + 1U);
    for (const EffectMacro& macro : localContext.mMacros) {
      defines.push_back(D3D_SHADER_MACRO{macro.keyText_.c_str(), macro.valueText_.c_str()});
    }
    defines.push_back(D3D_SHADER_MACRO{nullptr, nullptr});

    const char* const sourceData = context.mSourceBuffer.mBegin;
    const std::size_t sourceBytes = static_cast<std::size_t>(context.mSourceBuffer.mEnd - context.mSourceBuffer.mBegin);
    ComPtr<ID3DX11Effect> effect =
      CompileEffect(sourceData, sourceBytes, context.mSourcePath.c_str(), defines.data(), context.mCachePath.c_str());
    return boost::shared_ptr<Effect>(new EffectD3D11(context, effect.Get()));
  }

  boost::shared_ptr<Texture> DeviceD3D11::CreateTexture(const TextureContext* const context)
  {
    ComPtr<ID3D11Resource> resource;
    bool contentsFromEngine = false;

    if (context->source_ == 2U) {
      D3D11_TEXTURE2D_DESC desc{};
      desc.Width = std::max(context->width_, 1U);
      desc.Height = std::max(context->height_, 1U);
      // Mip level 0 asks D3D9 for an auto-generated chain; one level here.
      desc.MipLevels = (context->mipmapLevels_ != 0U) ? context->mipmapLevels_ : 1U;
      desc.ArraySize = 1U;
      desc.Format = d3d11::TextureFormatToDxgi(context->format_);
      if (desc.Format == DXGI_FORMAT_UNKNOWN) {
        char message[128]{};
        std::snprintf(message, sizeof(message), "unsupported texture format %u", context->format_);
        ThrowError("DeviceD3D11.cpp", __LINE__, message);
      }
      desc.SampleDesc.Count = 1U;
      desc.Usage = D3D11_USAGE_DEFAULT;
      desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

      // Zeroed levels, matching the CPU copy `TextureD3D11` starts from.
      std::vector<D3D11_SUBRESOURCE_DATA> levels(desc.MipLevels);
      const d3d11::LevelLayout top = d3d11::ComputeLevelLayout(desc.Format, desc.Width, desc.Height);
      std::vector<std::uint8_t> zeros(top.ByteSize(), 0U);
      for (UINT level = 0U; level < desc.MipLevels; ++level) {
        const d3d11::LevelLayout layout =
          d3d11::ComputeLevelLayout(desc.Format, std::max(1U, desc.Width >> level), std::max(1U, desc.Height >> level));
        levels[level].pSysMem = zeros.data();
        levels[level].SysMemPitch = layout.rowPitch;
      }

      ComPtr<ID3D11Texture2D> texture;
      CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateTexture2D(&desc, levels.data(), &texture));
      resource = texture;
      contentsFromEngine = true;
    } else if (context->source_ == 1U) {
      if (context->dataBuffer_.mEnd == context->dataBuffer_.mBegin) {
        ThrowError("DeviceD3D11.cpp", __LINE__, "attempt to create texture from uninitialized memory");
      }

      const char* const data = context->dataBuffer_.mBegin;
      const SIZE_T bytes = context->DataSizeBytes();

      // The texture-quality option skips top mip levels (D3D9 passes it as
      // D3DX_SKIP_DDS_MIP_LEVELS, `reserved0x44_`); a file with too few
      // levels for that loads whole.
      const UINT skipLevels = context->reserved0x44_ & 0x1FU;
      HRESULT result = E_FAIL;
      if (skipLevels != 0U) {
        D3DX11_IMAGE_LOAD_INFO loadInfo;
        loadInfo.FirstMipLevel = skipLevels;
        result = mD3DX11->createTextureFromMemory(mDevice.Get(), data, bytes, &loadInfo, nullptr, &resource, nullptr);
      }
      if (FAILED(result)) {
        resource.Reset();
        result = mD3DX11->createTextureFromMemory(mDevice.Get(), data, bytes, nullptr, nullptr, &resource, nullptr);
      }
      if (FAILED(result)) {
        char message[640]{};
        std::snprintf(
          message, sizeof(message), "unable to load texture %s: HRESULT 0x%08lX", context->location_.c_str(),
          static_cast<unsigned long>(result)
        );
        ThrowError("DeviceD3D11.cpp", __LINE__, message);
      }
    } else {
      ThrowError("DeviceD3D11.cpp", __LINE__, "invalid source specified for texture data");
    }

    ComPtr<ID3D11ShaderResourceView> view;
    ComPtr<ID3D11Texture2D> texture2D;
    if (SUCCEEDED(resource.As(&texture2D))) {
      D3D11_TEXTURE2D_DESC desc{};
      texture2D->GetDesc(&desc);
      if ((desc.MiscFlags & D3D11_RESOURCE_MISC_TEXTURECUBE) != 0U) {
        D3D11_SHADER_RESOURCE_VIEW_DESC viewDesc{};
        viewDesc.Format = desc.Format;
        viewDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURECUBE;
        viewDesc.TextureCube.MostDetailedMip = 0U;
        viewDesc.TextureCube.MipLevels = desc.MipLevels;
        CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateShaderResourceView(resource.Get(), &viewDesc, &view));
      } else {
        CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateShaderResourceView(resource.Get(), nullptr, &view));
      }
    } else {
      CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateShaderResourceView(resource.Get(), nullptr, &view));
    }

    return boost::shared_ptr<Texture>(
      new TextureD3D11(*context, mDevice.Get(), mImmediate.Get(), resource.Get(), view.Get(), contentsFromEngine)
    );
  }

  boost::shared_ptr<RenderTarget> DeviceD3D11::CreateRenderTarget(const RenderTargetContext* const context)
  {
    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = std::max(context->width_, 1U);
    desc.Height = std::max(context->height_, 1U);
    desc.MipLevels = 1U;
    desc.ArraySize = 1U;
    desc.Format = d3d11::RenderTargetFormatToDxgi(context->format_);
    if (desc.Format == DXGI_FORMAT_UNKNOWN) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "unsupported render target format");
    }
    desc.SampleDesc.Count = 1U;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;

    ComPtr<ID3D11Texture2D> texture;
    CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateTexture2D(&desc, nullptr, &texture));
    ComPtr<ID3D11RenderTargetView> renderTargetView;
    CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateRenderTargetView(texture.Get(), nullptr, &renderTargetView));
    ComPtr<ID3D11ShaderResourceView> shaderResourceView;
    CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateShaderResourceView(texture.Get(), nullptr, &shaderResourceView));

    // As DeviceD3D10::CreateRenderTarget (0x008FB1D0): a viewport covering
    // the new target.
    D3DVIEWPORT9 viewport{};
    viewport.Width = desc.Width;
    viewport.Height = desc.Height;
    viewport.MaxZ = 1.0f;
    SetViewport(&viewport);

    return boost::shared_ptr<RenderTarget>(
      new RenderTargetD3D11(texture.Get(), renderTargetView.Get(), shaderResourceView.Get())
    );
  }

  boost::shared_ptr<CubeRenderTarget> DeviceD3D11::CreateCubeRenderTarget(const CubeRenderTargetContext* const context)
  {
    return boost::shared_ptr<CubeRenderTarget>(new CubeRenderTargetD3D11(*context));
  }

  boost::shared_ptr<DepthStencilTarget> DeviceD3D11::CreateDepthStencilTarget(const DepthStencilTargetContext* const context)
  {
    const bool sampled = context->field0x10_;
    const d3d11::DepthFormats formats = d3d11::DepthStencilFormatToDxgi(context->format_, sampled);

    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = std::max(context->width_, 1U);
    desc.Height = std::max(context->height_, 1U);
    desc.MipLevels = 1U;
    desc.ArraySize = 1U;
    desc.Format = formats.texture;
    desc.SampleDesc.Count = 1U;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_DEPTH_STENCIL | (sampled ? static_cast<UINT>(D3D11_BIND_SHADER_RESOURCE) : 0U);

    ComPtr<ID3D11Texture2D> texture;
    CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateTexture2D(&desc, nullptr, &texture));

    D3D11_DEPTH_STENCIL_VIEW_DESC depthDesc{};
    depthDesc.Format = formats.depthView;
    depthDesc.ViewDimension = D3D11_DSV_DIMENSION_TEXTURE2D;
    ComPtr<ID3D11DepthStencilView> depthView;
    CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateDepthStencilView(texture.Get(), &depthDesc, &depthView));

    ComPtr<ID3D11ShaderResourceView> shaderView;
    if (sampled) {
      D3D11_SHADER_RESOURCE_VIEW_DESC viewDesc{};
      viewDesc.Format = formats.shaderView;
      viewDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
      viewDesc.Texture2D.MipLevels = 1U;
      CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateShaderResourceView(texture.Get(), &viewDesc, &shaderView));
    }

    return boost::shared_ptr<DepthStencilTarget>(
      new DepthStencilTargetD3D11(*context, texture.Get(), depthView.Get(), shaderView.Get())
    );
  }

  namespace
  {
    /** HLSL type of one input element: float/uint/int and its component count. */
    [[nodiscard]] std::string ElementType(const DXGI_FORMAT format)
    {
      unsigned components = 4U;
      const char* base = "float";
      switch (format) {
      case DXGI_FORMAT_R32_FLOAT:
      case DXGI_FORMAT_R16_FLOAT:
      case DXGI_FORMAT_R8_UNORM:
        components = 1U;
        break;
      case DXGI_FORMAT_R32G32_FLOAT:
      case DXGI_FORMAT_R16G16_FLOAT:
        components = 2U;
        break;
      case DXGI_FORMAT_R32G32B32_FLOAT:
        components = 3U;
        break;
      case DXGI_FORMAT_R8_SINT:
        components = 1U;
        base = "int";
        break;
      case DXGI_FORMAT_R8G8B8A8_UINT:
      case DXGI_FORMAT_R16G16B16A16_UINT:
        base = "uint";
        break;
      default:
        break;
      }
      return std::string(base) + ((components > 1U) ? std::to_string(components) : std::string());
    }
  } // namespace

  ComPtr<ID3D10Blob> DeviceD3D11::BuildInputSignature(const std::uint32_t formatCode)
  {
    // A vertex shader that declares exactly the layout's elements, so its
    // input signature always matches the layout.
    std::string source = "struct FafInput\n{\n";
    std::size_t index = 0U;
    for (const D3D11_INPUT_ELEMENT_DESC& element : d3d11::VertexLayoutElements(formatCode)) {
      source += "  " + ElementType(element.Format) + " e" + std::to_string(index++) + " : " + element.SemanticName +
        std::to_string(element.SemanticIndex) + ";\n";
    }
    source += "};\nfloat4 main(FafInput input) : SV_Position { return float4(0, 0, 0, 1); }\n";

    const char* const profile = (mFeatureLevel >= D3D_FEATURE_LEVEL_11_0) ? "vs_5_0"
      : (mFeatureLevel >= D3D_FEATURE_LEVEL_10_1)                         ? "vs_4_1"
                                                                          : "vs_4_0";
    ComPtr<ID3DBlob> code;
    ComPtr<ID3DBlob> errors;
    if (FAILED(::D3DCompile(source.data(), source.size(), "FafInputSignature", nullptr, nullptr, "main", profile, 0U, 0U, &code, &errors))) {
      const std::string message = "unable to build an input signature for vertex format " + std::to_string(formatCode) + ": " +
        TrimCompilerMessage(errors.Get());
      ThrowError("DeviceD3D11.cpp", __LINE__, message.c_str());
    }
    return code;
  }

  void DeviceD3D11::CreateInputLayouts()
  {
    // Built once, up front: a layout that cannot be created fails Setup, so
    // the fallback to Direct3D 9 happens before the engine holds any
    // Direct3D 11 resource. D3D10 built one per CreateVertexFormat call.
    std::uint32_t generated = 0U;
    for (std::uint32_t format = 0U; format < d3d11::kVertexFormatCount; ++format) {
      const std::span<const D3D11_INPUT_ELEMENT_DESC> elements = d3d11::VertexLayoutElements(format);
      if (elements.empty()) {
        continue;
      }

      // The D3D10 backend's way: the signature effect's technique for the
      // format (its techniques follow D3D10's numbering, so only up to 16).
      ID3DX11EffectTechnique* const technique = (format <= 16U) ? mSignatureEffect->GetTechniqueByIndex(format) : nullptr;
      if (technique != nullptr && technique->IsValid()) {
        D3DX11_PASS_DESC passDesc{};
        if (SUCCEEDED(technique->GetPassByIndex(0U)->GetDesc(&passDesc)) &&
            SUCCEEDED(mDevice->CreateInputLayout(
              elements.data(), static_cast<UINT>(elements.size()), passDesc.pIAInputSignature, passDesc.IAInputSignatureSize,
              &mInputLayouts[format]
            ))) {
          continue;
        }
      }

      // Its signature does not fit every layout (vertex format 16 has more
      // inputs than vs_4_0 takes); fall back to a signature built from the layout.
      const ComPtr<ID3D10Blob> signature = BuildInputSignature(format);
      CheckHresult(
        "DeviceD3D11.cpp", __LINE__,
        mDevice->CreateInputLayout(
          elements.data(), static_cast<UINT>(elements.size()), signature->GetBufferPointer(), signature->GetBufferSize(),
          &mInputLayouts[format]
        )
      );
      ++generated;
    }
    if (generated != 0U) {
      gpg::Logf("D3D11: %u vertex format(s) use an input signature built from the layout", generated);
    }
  }

  boost::shared_ptr<VertexFormat> DeviceD3D11::CreateVertexFormat(const std::uint32_t formatCode)
  {
    if (formatCode >= d3d11::kVertexFormatCount || mInputLayouts[formatCode] == nullptr) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "invalid vertex format specified");
    }
    return boost::shared_ptr<VertexFormat>(new VertexFormatD3D11(formatCode, mInputLayouts[formatCode].Get()));
  }

  boost::shared_ptr<VertexBuffer> DeviceD3D11::CreateVertexBuffer(const VertexBufferContext* const context)
  {
    return boost::shared_ptr<VertexBuffer>(new VertexBufferD3D11(*context, mDevice.Get(), mImmediate.Get()));
  }

  boost::shared_ptr<IndexBuffer> DeviceD3D11::CreateIndexBuffer(const IndexBufferContext* const context)
  {
    return boost::shared_ptr<IndexBuffer>(new IndexBufferD3D11(*context, mDevice.Get(), mImmediate.Get()));
  }

  void DeviceD3D11::GetRenderTargetData(const boost::shared_ptr<RenderTarget>& source, const boost::shared_ptr<Texture>& destination)
  {
    if (source == nullptr) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "Missing source texture");
    }
    if (destination == nullptr) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "Missing dest   texture");
    }
    auto* const target = static_cast<TextureD3D11*>(destination.get());
    if (mTracing) {
      Trace("GetRenderTargetData rt %p -> tex fmt %d", source.get(), static_cast<int>(target->GetFormat()));
    }
    mImmediate->CopyResource(target->GetTexture2D(), static_cast<RenderTargetD3D11*>(source.get())->GetTexture());
    target->DiscardCpuCopy();
  }

  void DeviceD3D11::StretchRect(
    const boost::shared_ptr<RenderTarget>& source,
    const boost::shared_ptr<RenderTarget>& destination,
    const RECT* const sourceRect,
    const RECT* const destinationRect
  )
  {
    if (source == nullptr) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "Missing source texture");
    }
    if (destination == nullptr) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "Missing dest   texture");
    }

    auto* const sourceTarget = static_cast<RenderTargetD3D11*>(source.get());
    auto* const destinationTarget = static_cast<RenderTargetD3D11*>(destination.get());
    const RenderTargetContext* const sourceContext = sourceTarget->GetContext();
    const RenderTargetContext* const destinationContext = destinationTarget->GetContext();
    if (mTracing) {
      Trace("StretchRect %p %ux%u fmt %u -> %p %ux%u fmt %u", sourceTarget, sourceContext->width_, sourceContext->height_,
            sourceContext->format_, destinationTarget, destinationContext->width_, destinationContext->height_, destinationContext->format_);
    }

    D3D11_TEXTURE2D_DESC sourceDesc{};
    D3D11_TEXTURE2D_DESC destinationDesc{};
    sourceTarget->GetTexture()->GetDesc(&sourceDesc);
    destinationTarget->GetTexture()->GetDesc(&destinationDesc);

    if (sourceContext->width_ == destinationContext->width_ && sourceContext->height_ == destinationContext->height_ &&
        sourceDesc.Format == destinationDesc.Format) {
      // As D3D10: a direct copy; only the destination rect's corner is used.
      UINT destinationX = 0U;
      UINT destinationY = 0U;
      if (destinationRect != nullptr) {
        destinationX = static_cast<UINT>(destinationRect->left);
        destinationY = static_cast<UINT>(destinationRect->top);
      }
      D3D11_BOX box{};
      const D3D11_BOX* boxPointer = nullptr;
      if (sourceRect != nullptr) {
        box.left = static_cast<UINT>(sourceRect->left);
        box.top = static_cast<UINT>(sourceRect->top);
        box.right = static_cast<UINT>(sourceRect->right);
        box.bottom = static_cast<UINT>(sourceRect->bottom);
        box.front = 0U;
        box.back = 1U;
        boxPointer = &box;
      }
      mImmediate->CopySubresourceRegion(
        destinationTarget->GetTexture(), 0U, destinationX, destinationY, 0U, sourceTarget->GetTexture(), 0U, boxPointer
      );
      return;
    }

    StretchRectBlit(
      destinationContext->width_,
      destinationContext->height_,
      destinationTarget->GetRenderTargetView(),
      sourceTarget->GetShaderResourceView()
    );
  }

  void DeviceD3D11::StretchRectBlit(
    const UINT width, const UINT height, ID3D11RenderTargetView* const destination, ID3D11ShaderResourceView* const source
  )
  {
    D3D11_VIEWPORT savedViewport{};
    UINT viewportCount = 1U;
    mImmediate->RSGetViewports(&viewportCount, &savedViewport);

    ComPtr<ID3D11RenderTargetView> savedTarget;
    ComPtr<ID3D11DepthStencilView> savedDepth;
    mImmediate->OMGetRenderTargets(1U, &savedTarget, &savedDepth);

    D3D11_VIEWPORT viewport{};
    viewport.Width = static_cast<float>(width);
    viewport.Height = static_cast<float>(height);
    viewport.MaxDepth = 1.0f;
    mImmediate->RSSetViewports(1U, &viewport);

    mImmediate->IASetInputLayout(mRttInputLayout.Get());
    mInputLayoutDirty = true; // the next engine draw binds its own again
    const UINT stride = sizeof(RttVertex);
    const UINT offset = 0U;
    ID3D11Buffer* const quad = mRttQuadVertexBuffer.Get();
    mImmediate->IASetVertexBuffers(0U, 1U, &quad, &stride, &offset);
    mImmediate->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);
    mImmediate->OMSetRenderTargets(1U, &destination, nullptr);

    D3DX11_TECHNIQUE_DESC techniqueDesc{};
    mRttTechnique->GetDesc(&techniqueDesc);
    ID3DX11EffectShaderResourceVariable* const sourceVariable = mRttEffect->GetVariableByName("g_txSource")->AsShaderResource();
    for (UINT pass = 0U; pass < techniqueDesc.Passes; ++pass) {
      sourceVariable->SetResource(source);
      mRttTechnique->GetPassByIndex(pass)->Apply(0U, mImmediate.Get());
      mImmediate->Draw(4U, 0U);
    }
    // Leave no view of `source` bound, so it can be a target again.
    sourceVariable->SetResource(nullptr);
    ID3D11ShaderResourceView* const noView = nullptr;
    mImmediate->PSSetShaderResources(0U, 1U, &noView);

    mImmediate->RSSetViewports(1U, &savedViewport);
    ID3D11RenderTargetView* const restoredTarget = savedTarget.Get();
    mImmediate->OMSetRenderTargets(1U, &restoredTarget, savedDepth.Get());
  }

  void DeviceD3D11::UpdateSurface(
    const boost::shared_ptr<Texture>& source,
    const boost::shared_ptr<Texture>& destination,
    const RECT* const sourceRect,
    const RECT* const destinationRect
  )
  {
    if (source == nullptr) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "Missing source texture");
    }
    if (destination == nullptr) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "Missing dest   texture");
    }

    auto* const sourceTexture = static_cast<TextureD3D11*>(source.get());
    auto* const destinationTexture = static_cast<TextureD3D11*>(destination.get());
    const TextureContext* const sourceContext = sourceTexture->GetContext();
    const TextureContext* const destinationContext = destinationTexture->GetContext();

    if (sourceContext->width_ == destinationContext->width_ && sourceContext->height_ == destinationContext->height_ &&
        sourceTexture->GetFormat() == destinationTexture->GetFormat()) {
      UINT destinationX = 0U;
      UINT destinationY = 0U;
      if (destinationRect != nullptr) {
        destinationX = static_cast<UINT>(destinationRect->left);
        destinationY = static_cast<UINT>(destinationRect->top);
      }
      D3D11_BOX box{};
      const D3D11_BOX* boxPointer = nullptr;
      if (sourceRect != nullptr) {
        box.left = static_cast<UINT>(sourceRect->left);
        box.top = static_cast<UINT>(sourceRect->top);
        box.right = static_cast<UINT>(sourceRect->right);
        box.bottom = static_cast<UINT>(sourceRect->bottom);
        box.front = 0U;
        box.back = 1U;
        boxPointer = &box;
      }
      mImmediate->CopySubresourceRegion(
        destinationTexture->GetTexture2D(), 0U, destinationX, destinationY, 0U, sourceTexture->GetTexture2D(), 0U, boxPointer
      );
      destinationTexture->DiscardCpuCopy();
      return;
    }

    {
      static int logged = 0;
      if (logged++ < 8) {
        D3D11_TEXTURE2D_DESC sourceDesc{};
        D3D11_TEXTURE2D_DESC destinationDesc{};
        sourceTexture->GetTexture2D()->GetDesc(&sourceDesc);
        destinationTexture->GetTexture2D()->GetDesc(&destinationDesc);
        gpg::Logf(
          "D3D11: UpdateSurface fallback %ux%u fmt %d mips %u -> %ux%u fmt %d mips %u (gal %u -> %u)", sourceDesc.Width,
          sourceDesc.Height, static_cast<int>(sourceDesc.Format), sourceDesc.MipLevels, destinationDesc.Width, destinationDesc.Height,
          static_cast<int>(destinationDesc.Format), destinationDesc.MipLevels, sourceContext->format_, destinationContext->format_
        );
      }
    }
    // D3D10's fallback (0x008FBDF0): encode the source, reload it as one
    // level of BC3, and copy that into the destination.
    ComPtr<ID3D10Blob> encoded;
    CheckHresult(
      "DeviceD3D11.cpp", __LINE__,
      mD3DX11->saveTextureToMemory(mImmediate.Get(), sourceTexture->GetResource(), D3DX11_IFF_DDS, &encoded, 0U)
    );
    // D3D10 reloads as one level of BC3, which only fits a BC3 destination.
    // Reload in the destination's own size, format and level count, so the
    // copy below always matches (a file texture D3DX loaded as R8G8B8A8 into
    // an engine B8G8R8A8 texture is the common case: the stratum masks).
    D3D11_TEXTURE2D_DESC destinationDesc{};
    destinationTexture->GetTexture2D()->GetDesc(&destinationDesc);
    D3DX11_IMAGE_LOAD_INFO loadInfo;
    loadInfo.Width = destinationDesc.Width;
    loadInfo.Height = destinationDesc.Height;
    loadInfo.MipLevels = destinationDesc.MipLevels;
    loadInfo.Format = destinationDesc.Format;
    loadInfo.Usage = D3D11_USAGE_DEFAULT;
    loadInfo.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    loadInfo.CpuAccessFlags = 0U;
    loadInfo.MiscFlags = 0U;
    ComPtr<ID3D11Resource> recreated;
    CheckHresult(
      "DeviceD3D11.cpp", __LINE__,
      mD3DX11->createTextureFromMemory(
        mDevice.Get(), encoded->GetBufferPointer(), encoded->GetBufferSize(), &loadInfo, nullptr, &recreated, nullptr
      )
    );
    mImmediate->CopyResource(destinationTexture->GetTexture2D(), recreated.Get());
    destinationTexture->DiscardCpuCopy();
  }

  void DeviceD3D11::SaveCubeRenderTarget(const boost::shared_ptr<CubeRenderTarget>& cubeTarget, const msvc8::string& filePath)
  {
    static_cast<void>(cubeTarget);
    static_cast<void>(filePath);
  }

  void DeviceD3D11::SaveRenderTarget(
    const boost::shared_ptr<RenderTarget>& renderTarget, const msvc8::string& filePath, const int fileFormat
  )
  {
    auto* const target = static_cast<RenderTargetD3D11*>(renderTarget.get());
    CheckHresult(
      "DeviceD3D11.cpp", __LINE__,
      mD3DX11->saveTextureToFile(mImmediate.Get(), target->GetTexture(), ImageFileFormat(fileFormat), filePath.c_str())
    );
  }

  void DeviceD3D11::SaveTexture(
    const boost::shared_ptr<Texture>& texture,
    const msvc8::string& filePath,
    const int fileFormat,
    gpg::MemBuffer<char>* const outBuffer
  )
  {
    auto* const sourceTexture = static_cast<TextureD3D11*>(texture.get());
    if (outBuffer == nullptr) {
      CheckHresult(
        "DeviceD3D11.cpp", __LINE__,
        mD3DX11->saveTextureToFile(mImmediate.Get(), sourceTexture->GetResource(), ImageFileFormat(fileFormat), filePath.c_str())
      );
      return;
    }

    ComPtr<ID3D10Blob> encoded;
    CheckHresult("DeviceD3D11.cpp", __LINE__, EncodeTexture(sourceTexture->GetResource(), ImageFileFormat(fileFormat), &encoded));
    const std::size_t bytes = encoded->GetBufferSize();
    if (outBuffer->Size() != bytes) {
      *outBuffer = gpg::AllocMemBuffer(bytes);
    }
    std::copy_n(static_cast<const char*>(encoded->GetBufferPointer()), bytes, outBuffer->GetPtr(0U, 0U));
  }

  HRESULT DeviceD3D11::EncodeTexture(ID3D11Resource* const resource, const int d3dxFormat, ID3D10Blob** const outBlob)
  {
    return mD3DX11->saveTextureToMemory(
      mImmediate.Get(), resource, static_cast<D3DX11_IMAGE_FILE_FORMAT>(d3dxFormat), outBlob, 0U
    );
  }

  void DeviceD3D11::GetTexture2D(
    const void* const sourceData,
    const std::uint32_t sourceBytes,
    gpg::MemBuffer<char>* const outTextureData,
    std::uint32_t* const outWidth,
    int* const outHeight
  )
  {
    if (sourceData == nullptr) {
      return;
    }

    // As D3D10 (0x008FCAC0): one level of BC3, read back to the CPU. D3DX11
    // decodes straight into a staging texture.
    //
    // The resource prefetch thread calls this while the render thread draws.
    // Decoding on the render device mapped a staging texture on the shared
    // immediate context: the map holds the context's multithread lock while
    // the driver waits for the GPU, and the render thread's next call blocked
    // on that lock (the stress map hung on load). The decode is a CPU job, so
    // it runs on a private WARP device with its own context and lock.
    const std::lock_guard<std::mutex> decodeLock(mDecodeMutex);
    if (mDecodeDevice == nullptr) {
      CheckHresult(
        "DeviceD3D11.cpp", __LINE__,
        ::D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0U, nullptr, 0U, D3D11_SDK_VERSION, &mDecodeDevice, nullptr, &mDecodeContext)
      );
    }
    D3DX11_IMAGE_LOAD_INFO loadInfo;
    loadInfo.MipLevels = 1U;
    loadInfo.Format = DXGI_FORMAT_BC3_UNORM;
    loadInfo.Usage = D3D11_USAGE_STAGING;
    loadInfo.BindFlags = 0U;
    loadInfo.CpuAccessFlags = D3D11_CPU_ACCESS_READ;

    ComPtr<ID3D11Resource> decoded;
    CheckHresult(
      "DeviceD3D11.cpp", __LINE__,
      mD3DX11->createTextureFromMemory(mDecodeDevice.Get(), sourceData, sourceBytes, &loadInfo, nullptr, &decoded, nullptr)
    );
    ComPtr<ID3D11Texture2D> staging;
    CheckHresult("DeviceD3D11.cpp", __LINE__, decoded.As(&staging));

    D3D11_TEXTURE2D_DESC desc{};
    staging->GetDesc(&desc);
    *outWidth = desc.Width;
    *outHeight = static_cast<int>(desc.Height);

    D3D11_MAPPED_SUBRESOURCE mapped{};
    CheckHresult("DeviceD3D11.cpp", __LINE__, mDecodeContext->Map(staging.Get(), 0U, D3D11_MAP_READ, 0U, &mapped));

    const std::uint32_t rowBytes = 16U * ((desc.Width + 3U) / 4U);
    const std::uint32_t rowCount = (desc.Height + 3U) / 4U;
    const std::size_t requiredBytes = static_cast<std::size_t>(rowBytes) * rowCount;
    if (outTextureData->Size() != requiredBytes) {
      *outTextureData = gpg::AllocMemBuffer(requiredBytes);
    }
    char* const destinationBytes = outTextureData->GetPtr(0U, 0U);
    const auto* const sourceRows = static_cast<const char*>(mapped.pData);
    for (std::uint32_t row = 0U; row < rowCount; ++row) {
      std::memcpy(destinationBytes + static_cast<std::size_t>(row) * rowBytes,
                  sourceRows + static_cast<std::size_t>(row) * mapped.RowPitch,
                  rowBytes);
    }
    mDecodeContext->Unmap(staging.Get(), 0U);
  }

  boost::weak_ptr<void>* DeviceD3D11::Func7(boost::weak_ptr<void>* const outWeakHandle, boost::shared_ptr<void> temporarySharedHandle)
  {
    static_cast<void>(temporarySharedHandle);
    outWeakHandle->reset();
    return outWeakHandle;
  }

  void DeviceD3D11::Reset(DeviceContext* const context)
  {
    if (mDevice == nullptr) {
      return;
    }
    gpg::Logf("D3D11: Reset requested");

    if (context != nullptr && context != &mDeviceContext) {
      mDeviceContext.mVSync = context->mVSync;
      const int heads = std::min(context->GetHeadCount(), mDeviceContext.GetHeadCount());
      for (int headIndex = 0; headIndex < heads; ++headIndex) {
        const Head& requested = context->GetHead(static_cast<std::uint32_t>(headIndex));
        Head& head = mDeviceContext.GetHead(static_cast<std::uint32_t>(headIndex));
        head.mWidth = requested.mWidth;
        head.mHeight = requested.mHeight;
      }
    }

    // `CD3DDevice::InitContext` drops its references to the back-buffer
    // targets before it calls Reset and asks for them again after.
    ReleaseRenderTargets();
    for (std::size_t headIndex = 0U; headIndex < mSwapChains.size(); ++headIndex) {
      Head& head = mDeviceContext.GetHead(static_cast<std::uint32_t>(headIndex));
      std::uint32_t width = head.mWidth;
      std::uint32_t height = head.mHeight;
      if (width == 0U || height == 0U) {
        RECT client{};
        ::GetClientRect(static_cast<HWND>(head.mWindow), &client);
        width = static_cast<std::uint32_t>(std::max<LONG>(client.right - client.left, 1));
        height = static_cast<std::uint32_t>(std::max<LONG>(client.bottom - client.top, 1));
      }
      const HRESULT result = mSwapChains[headIndex]->Resize(width, height);
      if (FAILED(result)) {
        gpg::Warnf("D3D11: resizing head %u to %ux%u failed (HRESULT 0x%08lX)", static_cast<unsigned>(headIndex), width, height,
                   static_cast<unsigned long>(result));
      }
    }
    mPipelineState->SetDeviceState();
    CreateRenderTargets();
  }

  void DeviceD3D11::Reset()
  {
    Reset(&mDeviceContext);
  }

  int DeviceD3D11::TestCooperativeLevel()
  {
    return 0;
  }

  void DeviceD3D11::BeginScene() {}

  void DeviceD3D11::EndScene() {}

  void DeviceD3D11::BindOutputContext()
  {
    ID3D11RenderTargetView* renderTargetView = nullptr;
    ID3D11DepthStencilView* depthStencilView = nullptr;
    if (outputContext_.surface != nullptr) {
      renderTargetView = static_cast<RenderTargetD3D11*>(outputContext_.surface.get())->GetRenderTargetView();
    }
    if (outputContext_.depthStencil != nullptr) {
      depthStencilView = static_cast<DepthStencilTargetD3D11*>(outputContext_.depthStencil.get())->GetDepthStencilView();
    }
    mImmediate->OMSetRenderTargets(1U, &renderTargetView, depthStencilView);
  }

  void DeviceD3D11::DumpBackBufferIfDue()
  {
    // Diagnostics: with FAF_GAL_DUMP_DIR set, head 0's back buffer is written
    // there as a PNG every FAF_GAL_DUMP_SECONDS (default 10) seconds. It shows
    // what the device drew, independent of how the window is composited.
    static const char* const directory = std::getenv("FAF_GAL_DUMP_DIR");
    if (directory == nullptr || directory[0] == 0 || mHeadOutputContexts.empty()) {
      return;
    }
    static const DWORD interval = [] {
      const char* const seconds = std::getenv("FAF_GAL_DUMP_SECONDS");
      const long value = (seconds != nullptr) ? std::strtol(seconds, nullptr, 10) : 10L;
      return static_cast<DWORD>((value > 0L) ? value * 1000L : 10000L);
    }();
    const DWORD now = ::GetTickCount();
    if (mLastDumpTick != 0U && now - mLastDumpTick < interval) {
      return;
    }
    if (mLastDumpTick == 0U) {
      mFirstDumpTick = now;
    }
    mLastDumpTick = now;

    char path[MAX_PATH]{};
    std::snprintf(path, sizeof(path), "%s/d3d11_%06lu.bmp", directory, static_cast<unsigned long>((now - mFirstDumpTick) / 1000U));
    auto* const target = static_cast<RenderTargetD3D11*>(mHeadOutputContexts.front().surface.get());
    DumpTexture(target->GetTexture(), path);
  }

  void DeviceD3D11::DumpBoundTarget(const char* const label)
  {
    static const char* const directory = std::getenv("FAF_GAL_DUMP_DIR");
    if (directory == nullptr || directory[0] == 0 || outputContext_.surface == nullptr) {
      return;
    }
    char path[MAX_PATH]{};
    std::snprintf(path, sizeof(path), "%s/f%u_%03u_%s.bmp", directory, mFrameIndex, mDumpSequence++, label);
    DumpTexture(static_cast<RenderTargetD3D11*>(outputContext_.surface.get())->GetTexture(), path);
  }

  void DeviceD3D11::DumpTexture(ID3D11Texture2D* const texture, const char* const path)
  {
    D3D11_TEXTURE2D_DESC desc{};
    texture->GetDesc(&desc);
    if (d3d11::FormatElementBytes(desc.Format) != 4U || d3d11::IsBlockCompressed(desc.Format)) {
      return;
    }
    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = 0U;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    desc.MiscFlags = 0U;
    ComPtr<ID3D11Texture2D> staging;
    if (FAILED(mDevice->CreateTexture2D(&desc, nullptr, &staging))) {
      return;
    }
    mImmediate->CopyResource(staging.Get(), texture);
    D3D11_MAPPED_SUBRESOURCE mapped{};
    if (FAILED(mImmediate->Map(staging.Get(), 0U, D3D11_MAP_READ, 0U, &mapped))) {
      return;
    }

    // A top-down 32-bit BMP; the back buffer is B8G8R8A8, BMP's own order.
    BITMAPFILEHEADER fileHeader{};
    BITMAPINFOHEADER infoHeader{};
    infoHeader.biSize = sizeof(infoHeader);
    infoHeader.biWidth = static_cast<LONG>(desc.Width);
    infoHeader.biHeight = -static_cast<LONG>(desc.Height);
    infoHeader.biPlanes = 1;
    infoHeader.biBitCount = 32;
    infoHeader.biCompression = BI_RGB;
    const DWORD imageBytes = desc.Width * desc.Height * 4U;
    fileHeader.bfType = 0x4D42;
    fileHeader.bfOffBits = sizeof(fileHeader) + sizeof(infoHeader);
    fileHeader.bfSize = fileHeader.bfOffBits + imageBytes;
    if (FILE* const file = std::fopen(path, "wb")) {
      std::fwrite(&fileHeader, sizeof(fileHeader), 1U, file);
      std::fwrite(&infoHeader, sizeof(infoHeader), 1U, file);
      const auto* const rows = static_cast<const std::uint8_t*>(mapped.pData);
      for (UINT row = 0U; row < desc.Height; ++row) {
        std::fwrite(rows + static_cast<std::size_t>(row) * mapped.RowPitch, 4U, desc.Width, file);
      }
      std::fclose(file);
      gpg::Logf("D3D11: dump %s", path);
    }
    mImmediate->Unmap(staging.Get(), 0U);
  }

  void DeviceD3D11::LogDebugLayerMessages()
  {
    // With /d3d11debug the debug layer's warnings and errors go to the game
    // log, each distinct message once.
    if (mInfoQueue == nullptr) {
      return;
    }
    const UINT64 count = mInfoQueue->GetNumStoredMessages();
    for (UINT64 index = 0U; index < count; ++index) {
      SIZE_T length = 0U;
      if (FAILED(mInfoQueue->GetMessage(index, nullptr, &length)) || length == 0U) {
        continue;
      }
      std::vector<char> storage(length);
      auto* const message = reinterpret_cast<D3D11_MESSAGE*>(storage.data());
      if (FAILED(mInfoQueue->GetMessage(index, message, &length))) {
        continue;
      }
      if (message->Severity > D3D11_MESSAGE_SEVERITY_WARNING) {
        continue;
      }
      if (mLoggedDebugMessages.insert(static_cast<int>(message->ID)).second && mLoggedDebugMessages.size() < 200U) {
        gpg::Warnf("D3D11 debug layer: %.*s", static_cast<int>(message->DescriptionByteLength), message->pDescription);
      }
    }
    mInfoQueue->ClearStoredMessages();
  }

  void DeviceD3D11::Trace(const char* const format, ...)
  {
    char line[512];
    va_list arguments;
    va_start(arguments, format);
    std::vsnprintf(line, sizeof(line), format, arguments);
    va_end(arguments);
    gpg::Logf("D3D11 trace f%u: %s", mFrameIndex, line);
  }

  void DeviceD3D11::Present()
  {
    if (mTracing) {
      Trace("Present");
    }
    ++mFrameIndex;
    {
      static const long start = [] {
        const char* const value = std::getenv("FAF_GAL_TRACE_START");
        return (value != nullptr) ? std::strtol(value, nullptr, 10) : -1L;
      }();
      static const long frames = [] {
        const char* const value = std::getenv("FAF_GAL_TRACE_FRAMES");
        return (value != nullptr) ? std::strtol(value, nullptr, 10) : 1L;
      }();
      mTracing = start >= 0L && static_cast<long>(mFrameIndex) >= start && static_cast<long>(mFrameIndex) < start + frames;
    }
    DumpBackBufferIfDue();
    LogDebugLayerMessages();
    if (mGpuDriven != nullptr) {
      mGpuDriven->EndProfileFrame();
    }
    const bool vsync = mDeviceContext.mVSync;
    bool flipModel = false;
    for (const std::unique_ptr<dxgi::SwapChain>& swapChain : mSwapChains) {
      const HRESULT result = swapChain->Present(vsync);
      if (FAILED(result)) {
        if (result == DXGI_ERROR_DEVICE_REMOVED || result == DXGI_ERROR_DEVICE_RESET) {
          // Nothing drawn after this reaches the screen, and every later call
          // fails too: throwing here flooded the log with the same warning
          // until the session aborted behind a crash dialog. Say why once and
          // leave with the reason as the exit code, without the dialog or the
          // exit-time destructors that would touch the dead device.
          const HRESULT reason = mDevice->GetDeviceRemovedReason();
          gpg::Warnf(
            "D3D11: device removed (reason 0x%08lX); exiting. Run with /d3d11debug for the cause, or without /d3d11 for Direct3D 9.",
            static_cast<unsigned long>(reason)
          );
          LogDebugLayerMessages();
          ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(reason != S_OK ? reason : result));
        }
        d3d11::ThrowHresult("DeviceD3D11.cpp", __LINE__, result);
      }
      flipModel = flipModel || swapChain->IsFlipModel();
    }

    // A flip-model present unbinds the back buffer from the output merger;
    // D3D9 and D3D10 keep it bound, and the engine does not rebind it.
    if (flipModel) {
      BindOutputContext();
    }
  }

  void DeviceD3D11::SetCursor(const CursorContext* const context)
  {
    static_cast<void>(mCursor.SetCursor(*context));
  }

  void DeviceD3D11::InitCursor()
  {
    static_cast<void>(mCursor.InitCursor());
  }

  int DeviceD3D11::ShowCursor(const bool show)
  {
    return mCursor.ShowCursor(show);
  }

  void DeviceD3D11::SetViewport(const D3DVIEWPORT9* const viewport)
  {
    if (mTracing) {
      Trace("SetViewport %lu,%lu %lux%lu z %f..%f", viewport->X, viewport->Y, viewport->Width, viewport->Height, viewport->MinZ, viewport->MaxZ);
    }
    // D3D9 puts pixel centres on integer coordinates, D3D10 and later on
    // halves. The engine's 2D paths are written for D3D9: the UI projection
    // (CD3DPrimBatcher) shifts everything by -0.5 pixel so that texels land on
    // pixel centres. Moving the whole viewport by +0.5 pixel restores D3D9's
    // rasterisation for every draw; without it every glyph and UI texel is
    // sampled half-way between texels (dim, doubled text, neighbouring glyphs
    // bleeding in).
    D3D11_VIEWPORT native{};
    native.TopLeftX = static_cast<float>(viewport->X) + kD3D9PixelCentreOffset;
    native.TopLeftY = static_cast<float>(viewport->Y) + kD3D9PixelCentreOffset;
    native.Width = static_cast<float>(viewport->Width);
    native.Height = static_cast<float>(viewport->Height);
    native.MinDepth = viewport->MinZ;
    native.MaxDepth = viewport->MaxZ;
    mImmediate->RSSetViewports(1U, &native);
  }

  void DeviceD3D11::GetViewport(D3DVIEWPORT9* const outViewport)
  {
    UINT count = 1U;
    D3D11_VIEWPORT native{};
    mImmediate->RSGetViewports(&count, &native);
    outViewport->X = static_cast<DWORD>(native.TopLeftX - kD3D9PixelCentreOffset);
    outViewport->Y = static_cast<DWORD>(native.TopLeftY - kD3D9PixelCentreOffset);
    outViewport->Width = static_cast<DWORD>(native.Width);
    outViewport->Height = static_cast<DWORD>(native.Height);
    outViewport->MinZ = native.MinDepth;
    outViewport->MaxZ = native.MaxDepth;
  }

  void DeviceD3D11::ClearTarget(const OutputContext* const context)
  {
    if (mTracing) {
      const RenderTargetContext* const surface = (context != nullptr && context->surface != nullptr) ? context->surface->GetContext() : nullptr;
      const DepthStencilTargetContext* const depth =
        (context != nullptr && context->depthStencil != nullptr) ? context->depthStencil->GetContext() : nullptr;
      Trace("ClearTarget rt=%p %ux%u fmt %u, ds=%p %ux%u", (context != nullptr) ? context->surface.get() : nullptr,
            surface ? surface->width_ : 0U, surface ? surface->height_ : 0U, surface ? surface->format_ : 0U,
            (context != nullptr) ? context->depthStencil.get() : nullptr, depth ? depth->width_ : 0U, depth ? depth->height_ : 0U);
    }
    const RenderTarget* const previousSurface = outputContext_.surface.get();
    Device::ClearTarget(context);
    BindOutputContext();

    // DeviceD3D9::ClearTarget calls SetRenderTarget when the colour surface
    // changes, and D3D9 then resets the viewport to the whole new target; the
    // engine relies on it: it binds the 1024x1024 shadow target and clears it
    // while the 1280x720 screen viewport is still set, and only then sets its
    // own viewport. Without the reset the clear covered 1280x720 of it and the
    // rest kept stale depth (a dark shadow band that moved with the camera, a
    // darkened build glow). Rebinding the same surface, or changing only the
    // depth target, keeps the viewport, as in D3D9.
    if (outputContext_.surface != nullptr && outputContext_.surface.get() != previousSurface) {
      const RenderTargetContext* const surface = outputContext_.surface->GetContext();
      D3DVIEWPORT9 viewport{};
      viewport.X = 0U;
      viewport.Y = 0U;
      viewport.Width = surface->width_;
      viewport.Height = surface->height_;
      viewport.MinZ = 0.0f;
      viewport.MaxZ = 1.0f;
      SetViewport(&viewport);
    }
  }

  void DeviceD3D11::Clear(
    const bool clearColor,
    const bool clearDepth,
    const bool clearStencil,
    const std::uint32_t packedColor,
    const float depth,
    const int stencil
  )
  {
    if (mTracing) {
      Trace("Clear color=%d depth=%d stencil=%d 0x%08X z=%f s=%d", clearColor, clearDepth, clearStencil, packedColor, depth, stencil);
    }
    constexpr float kScale = 1.0f / 255.0f;
    const float rgba[4] = {
      static_cast<float>((packedColor >> 16U) & 0xFFU) * kScale,
      static_cast<float>((packedColor >> 8U) & 0xFFU) * kScale,
      static_cast<float>(packedColor & 0xFFU) * kScale,
      static_cast<float>((packedColor >> 24U) & 0xFFU) * kScale,
    };

    // D3D9's Clear covers the viewport, not the whole target (the minimap
    // clears its own corner of the screen); D3D11's clears ignore it. A
    // viewport smaller than the bound targets is cleared with a draw.
    if (!ViewportCoversTargets()) {
      ClearViewportWithDraw(clearColor && outputContext_.surface != nullptr, clearDepth, clearStencil, rgba, depth, stencil);
      return;
    }

    if (clearColor && outputContext_.surface != nullptr) {
      mImmediate->ClearRenderTargetView(
        static_cast<RenderTargetD3D11*>(outputContext_.surface.get())->GetRenderTargetView(), rgba
      );
    }

    UINT mask = 0U;
    if (clearDepth) {
      mask |= D3D11_CLEAR_DEPTH;
    }
    if (clearStencil) {
      mask |= D3D11_CLEAR_STENCIL;
    }
    if (mask != 0U && outputContext_.depthStencil != nullptr) {
      mImmediate->ClearDepthStencilView(
        static_cast<DepthStencilTargetD3D11*>(outputContext_.depthStencil.get())->GetDepthStencilView(),
        mask,
        depth,
        static_cast<UINT8>(stencil)
      );
    }
  }

  bool DeviceD3D11::ViewportCoversTargets() const
  {
    D3D11_VIEWPORT viewport{};
    UINT count = 1U;
    mImmediate->RSGetViewports(&count, &viewport);
    if (count == 0U) {
      return true;
    }
    std::uint32_t width = 0U;
    std::uint32_t height = 0U;
    if (outputContext_.surface != nullptr) {
      const RenderTargetContext* const context = outputContext_.surface->GetContext();
      width = context->width_;
      height = context->height_;
    } else if (outputContext_.depthStencil != nullptr) {
      const DepthStencilTargetContext* const context = outputContext_.depthStencil->GetContext();
      width = context->width_;
      height = context->height_;
    }
    return viewport.TopLeftX <= kD3D9PixelCentreOffset && viewport.TopLeftY <= kD3D9PixelCentreOffset &&
      viewport.Width >= static_cast<float>(width) &&
      viewport.Height >= static_cast<float>(height);
  }

  void DeviceD3D11::CreateClearResources()
  {
    static constexpr char kSource[] =
      "cbuffer FafClear : register(b0) { float4 faf_color; float4 faf_depth; };\n"
      "float4 VSMain(uint id : SV_VertexID) : SV_Position\n"
      "{\n"
      "    float2 p = float2((id << 1) & 2, id & 2);\n"
      "    return float4(p * float2(2, -2) + float2(-1, 1), faf_depth.x, 1);\n"
      "}\n"
      "float4 PSMain() : SV_Target { return faf_color; }\n";

    ComPtr<ID3DBlob> code;
    ComPtr<ID3DBlob> errors;
    CheckHresult("DeviceD3D11.cpp", __LINE__,
                 ::D3DCompile(kSource, sizeof(kSource) - 1U, "FafClear", nullptr, nullptr, "VSMain", "vs_4_0", 0U, 0U, &code, &errors));
    CheckHresult("DeviceD3D11.cpp", __LINE__,
                 mDevice->CreateVertexShader(code->GetBufferPointer(), code->GetBufferSize(), nullptr, &mClearVertexShader));
    code.Reset();
    CheckHresult("DeviceD3D11.cpp", __LINE__,
                 ::D3DCompile(kSource, sizeof(kSource) - 1U, "FafClear", nullptr, nullptr, "PSMain", "ps_4_0", 0U, 0U, &code, &errors));
    CheckHresult("DeviceD3D11.cpp", __LINE__,
                 mDevice->CreatePixelShader(code->GetBufferPointer(), code->GetBufferSize(), nullptr, &mClearPixelShader));

    D3D11_BUFFER_DESC bufferDesc{};
    bufferDesc.ByteWidth = 32U;
    bufferDesc.Usage = D3D11_USAGE_DEFAULT;
    bufferDesc.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
    CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateBuffer(&bufferDesc, nullptr, &mClearConstants));

    D3D11_RASTERIZER_DESC rasterizer{};
    rasterizer.FillMode = D3D11_FILL_SOLID;
    rasterizer.CullMode = D3D11_CULL_NONE;
    rasterizer.DepthClipEnable = FALSE;
    CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateRasterizerState(&rasterizer, &mClearRasterizer));

    for (int writeColor = 0; writeColor < 2; ++writeColor) {
      D3D11_BLEND_DESC blend{};
      blend.RenderTarget[0].SrcBlend = D3D11_BLEND_ONE;
      blend.RenderTarget[0].DestBlend = D3D11_BLEND_ZERO;
      blend.RenderTarget[0].BlendOp = D3D11_BLEND_OP_ADD;
      blend.RenderTarget[0].SrcBlendAlpha = D3D11_BLEND_ONE;
      blend.RenderTarget[0].DestBlendAlpha = D3D11_BLEND_ZERO;
      blend.RenderTarget[0].BlendOpAlpha = D3D11_BLEND_OP_ADD;
      blend.RenderTarget[0].RenderTargetWriteMask = writeColor != 0 ? D3D11_COLOR_WRITE_ENABLE_ALL : 0U;
      CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateBlendState(&blend, &mClearBlend[writeColor]));
    }
    for (int variant = 0; variant < 4; ++variant) {
      const bool writeDepth = (variant & 1) != 0;
      const bool writeStencil = (variant & 2) != 0;
      D3D11_DEPTH_STENCIL_DESC depthStencil{};
      depthStencil.DepthEnable = writeDepth ? TRUE : FALSE;
      depthStencil.DepthWriteMask = writeDepth ? D3D11_DEPTH_WRITE_MASK_ALL : D3D11_DEPTH_WRITE_MASK_ZERO;
      depthStencil.DepthFunc = D3D11_COMPARISON_ALWAYS;
      depthStencil.StencilEnable = writeStencil ? TRUE : FALSE;
      depthStencil.StencilReadMask = 0xFFU;
      depthStencil.StencilWriteMask = 0xFFU;
      depthStencil.FrontFace.StencilFunc = D3D11_COMPARISON_ALWAYS;
      depthStencil.FrontFace.StencilPassOp = D3D11_STENCIL_OP_REPLACE;
      depthStencil.FrontFace.StencilFailOp = D3D11_STENCIL_OP_REPLACE;
      depthStencil.FrontFace.StencilDepthFailOp = D3D11_STENCIL_OP_REPLACE;
      depthStencil.BackFace = depthStencil.FrontFace;
      CheckHresult("DeviceD3D11.cpp", __LINE__, mDevice->CreateDepthStencilState(&depthStencil, &mClearDepthStencil[variant]));
    }
  }

  void DeviceD3D11::ClearViewportWithDraw(
    const bool clearColor, const bool clearDepth, const bool clearStencil, const float* const rgba, const float depth, const int stencil
  )
  {
    const bool hasDepth = outputContext_.depthStencil != nullptr;
    if (!clearColor && !(hasDepth && (clearDepth || clearStencil))) {
      return;
    }

    // What the draw changes, so it can be put back: the effect state the
    // engine's next draw may rely on without another BeginPass.
    D3D11_PRIMITIVE_TOPOLOGY topology{};
    mImmediate->IAGetPrimitiveTopology(&topology);
    ComPtr<ID3D11InputLayout> layout;
    mImmediate->IAGetInputLayout(&layout);
    ComPtr<ID3D11VertexShader> vertexShader;
    mImmediate->VSGetShader(&vertexShader, nullptr, nullptr);
    ComPtr<ID3D11PixelShader> pixelShader;
    mImmediate->PSGetShader(&pixelShader, nullptr, nullptr);
    ComPtr<ID3D11GeometryShader> geometryShader;
    mImmediate->GSGetShader(&geometryShader, nullptr, nullptr);
    ComPtr<ID3D11Buffer> vertexConstants;
    mImmediate->VSGetConstantBuffers(0U, 1U, &vertexConstants);
    ComPtr<ID3D11Buffer> pixelConstants;
    mImmediate->PSGetConstantBuffers(0U, 1U, &pixelConstants);
    ComPtr<ID3D11BlendState> blend;
    FLOAT blendFactor[4]{};
    UINT sampleMask = 0U;
    mImmediate->OMGetBlendState(&blend, blendFactor, &sampleMask);
    ComPtr<ID3D11DepthStencilState> depthStencil;
    UINT stencilRef = 0U;
    mImmediate->OMGetDepthStencilState(&depthStencil, &stencilRef);
    ComPtr<ID3D11RasterizerState> rasterizer;
    mImmediate->RSGetState(&rasterizer);
    D3D11_VIEWPORT viewport{};
    UINT viewportCount = 1U;
    mImmediate->RSGetViewports(&viewportCount, &viewport);

    const float constants[8] = {rgba[0], rgba[1], rgba[2], rgba[3], depth, 0.0f, 0.0f, 0.0f};
    mImmediate->UpdateSubresource(mClearConstants.Get(), 0U, nullptr, constants, 0U, 0U);

    D3D11_VIEWPORT clearViewport = viewport;
    clearViewport.MinDepth = 0.0f;
    clearViewport.MaxDepth = 1.0f;
    mImmediate->RSSetViewports(1U, &clearViewport);
    mImmediate->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    mImmediate->IASetInputLayout(nullptr);
    mImmediate->VSSetShader(mClearVertexShader.Get(), nullptr, 0U);
    mImmediate->GSSetShader(nullptr, nullptr, 0U);
    mImmediate->PSSetShader(mClearPixelShader.Get(), nullptr, 0U);
    ID3D11Buffer* const clearBuffer = mClearConstants.Get();
    mImmediate->VSSetConstantBuffers(0U, 1U, &clearBuffer);
    mImmediate->PSSetConstantBuffers(0U, 1U, &clearBuffer);
    mImmediate->OMSetBlendState(mClearBlend[clearColor ? 1 : 0].Get(), nullptr, 0xFFFFFFFFU);
    const int variant = ((hasDepth && clearDepth) ? 1 : 0) | ((hasDepth && clearStencil) ? 2 : 0);
    mImmediate->OMSetDepthStencilState(mClearDepthStencil[variant].Get(), static_cast<UINT>(stencil & 0xFF));
    mImmediate->RSSetState(mClearRasterizer.Get());
    mImmediate->Draw(3U, 0U);

    mImmediate->IASetPrimitiveTopology(topology);
    mImmediate->IASetInputLayout(layout.Get());
    mImmediate->VSSetShader(vertexShader.Get(), nullptr, 0U);
    mImmediate->GSSetShader(geometryShader.Get(), nullptr, 0U);
    mImmediate->PSSetShader(pixelShader.Get(), nullptr, 0U);
    ID3D11Buffer* const restoredVertexConstants = vertexConstants.Get();
    mImmediate->VSSetConstantBuffers(0U, 1U, &restoredVertexConstants);
    ID3D11Buffer* const restoredPixelConstants = pixelConstants.Get();
    mImmediate->PSSetConstantBuffers(0U, 1U, &restoredPixelConstants);
    mImmediate->OMSetBlendState(blend.Get(), blendFactor, sampleMask);
    mImmediate->OMSetDepthStencilState(depthStencil.Get(), stencilRef);
    mImmediate->RSSetState(rasterizer.Get());
    mImmediate->RSSetViewports(1U, &viewport);
  }

  void DeviceD3D11::ClearTextures()
  {
    mPipelineState->ClearTextures();
  }

  void DeviceD3D11::SetVertexDeclaration(const boost::shared_ptr<VertexFormat> vertexFormat)
  {
    auto* const format = static_cast<VertexFormatD3D11*>(vertexFormat.get());
    mImmediate->IASetInputLayout(format->GetInputLayout());
    mBoundFormat = format->formatCode_;
    mInputLayoutDirty = true;
    RecordStateChange();
  }

  void DeviceD3D11::SetPassVertexShader(const void* const bytecode, const SIZE_T length)
  {
    if (bytecode != mPassVertexShader || length != mPassVertexShaderLength) {
      mPassVertexShader = bytecode;
      mPassVertexShaderLength = length;
      mInputLayoutDirty = true;
    }
  }

  void DeviceD3D11::PrepareInputLayout()
  {
    // D3D9 fed a vertex shader input the declaration lacks with (0,0,0,1);
    // Direct3D 11 refuses such a draw outright. So the layout is built for
    // the pair (vertex format, vertex shader): the format's elements, plus
    // one element on an unbound slot (which reads as zero) for every input
    // the shader takes that the format does not provide. Keyed by the
    // shader's DXBC checksum, so a reloaded effect never reuses a stale entry.
    if (!mInputLayoutDirty) {
      return;
    }
    mInputLayoutDirty = false;
    if (mPassVertexShader == nullptr || mPassVertexShaderLength < 20U || mBoundFormat >= d3d11::kVertexFormatCount) {
      return;
    }

    ShaderLayoutKey key{};
    key.format = mBoundFormat;
    std::memcpy(key.checksum, static_cast<const std::uint8_t*>(mPassVertexShader) + 4U, sizeof(key.checksum));
    auto found = mShaderInputLayouts.find(key);
    if (found == mShaderInputLayouts.end()) {
      found = mShaderInputLayouts.emplace(key, CreateShaderInputLayout(mBoundFormat, mPassVertexShader, mPassVertexShaderLength)).first;
    }
    if (found->second != nullptr) {
      mImmediate->IASetInputLayout(found->second.Get());
    }
  }

  ComPtr<ID3D11InputLayout> DeviceD3D11::CreateShaderInputLayout(
    const std::uint32_t format, const void* const bytecode, const SIZE_T length
  )
  {
    constexpr UINT kUnboundSlot = D3D11_IA_VERTEX_INPUT_RESOURCE_SLOT_COUNT - 1U;
    const std::span<const D3D11_INPUT_ELEMENT_DESC> formatElements = d3d11::VertexLayoutElements(format);
    std::vector<D3D11_INPUT_ELEMENT_DESC> elements(formatElements.begin(), formatElements.end());

    ComPtr<ID3D11ShaderReflection> reflection;
    if (FAILED(::D3DReflect(bytecode, length, IID_PPV_ARGS(&reflection)))) {
      return nullptr;
    }
    D3D11_SHADER_DESC shaderDesc{};
    reflection->GetDesc(&shaderDesc);

    std::vector<std::string> names; // keeps the semantic strings alive for CreateInputLayout
    names.reserve(shaderDesc.InputParameters);
    for (UINT index = 0U; index < shaderDesc.InputParameters; ++index) {
      D3D11_SIGNATURE_PARAMETER_DESC parameter{};
      reflection->GetInputParameterDesc(index, &parameter);
      if (parameter.SystemValueType != D3D_NAME_UNDEFINED) {
        continue;
      }
      const bool provided = std::any_of(formatElements.begin(), formatElements.end(), [&](const D3D11_INPUT_ELEMENT_DESC& element) {
        return element.SemanticIndex == parameter.SemanticIndex && ::_stricmp(element.SemanticName, parameter.SemanticName) == 0;
      });
      if (provided) {
        continue;
      }
      names.emplace_back(parameter.SemanticName);
      D3D11_INPUT_ELEMENT_DESC missing{};
      missing.SemanticIndex = parameter.SemanticIndex;
      missing.Format = (parameter.ComponentType == D3D_REGISTER_COMPONENT_UINT32) ? DXGI_FORMAT_R32G32B32A32_UINT
        : (parameter.ComponentType == D3D_REGISTER_COMPONENT_SINT32)                ? DXGI_FORMAT_R32G32B32A32_SINT
                                                                                    : DXGI_FORMAT_R32G32B32A32_FLOAT;
      missing.InputSlot = kUnboundSlot;
      missing.AlignedByteOffset = 0U;
      missing.InputSlotClass = D3D11_INPUT_PER_VERTEX_DATA;
      elements.push_back(missing);
    }
    for (std::size_t index = formatElements.size(), name = 0U; index < elements.size(); ++index, ++name) {
      elements[index].SemanticName = names[name].c_str();
    }

    ComPtr<ID3D11InputLayout> layout;
    if (FAILED(mDevice->CreateInputLayout(elements.data(), static_cast<UINT>(elements.size()), bytecode, length, &layout))) {
      gpg::Warnf("D3D11: no input layout for vertex format %u with this vertex shader; using the format's own", format);
      return nullptr;
    }
    return layout;
  }

  void DeviceD3D11::SetVertexBuffer(
    const std::uint32_t streamSlot,
    const boost::shared_ptr<VertexBuffer> vertexBuffer,
    const int streamFrequencyToken,
    const int startVertex
  )
  {
    if (streamSlot >= std::size(mStreamFrequencies)) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "invalid vertex stream");
    }
    const VertexBufferContext* const context = vertexBuffer->GetContext();
    ID3D11Buffer* const buffer = static_cast<VertexBufferD3D11*>(vertexBuffer.get())->GetBuffer();
    const UINT stride = context->stride_;
    const UINT offset = static_cast<UINT>(startVertex) * stride;
    mImmediate->IASetVertexBuffers(streamSlot, 1U, &buffer, &stride, &offset);
    RecordStateChange();

    // Slot 0's frequency is the instance count the draws use, read the way
    // DeviceD3D9::SetVertexBuffer reads the token: only a geometry stream
    // (type 2) repeats per instance, and the D3D9 stream-source flag bits are
    // not part of the count. RangeRenderer passes
    // `D3DSTREAMSOURCE_INDEXEDDATA | count`; taken raw, that drew about 2^30
    // instances and hung the GPU (TDR) as soon as a range ring was on screen.
    constexpr std::uint32_t kStreamSourceFlagMask = 0xC0000000U; // D3DSTREAMSOURCE_INDEXEDDATA | INSTANCEDATA
    constexpr std::uint32_t kGeometryStreamType = 2U;
    const std::uint32_t count = static_cast<std::uint32_t>(streamFrequencyToken) & ~kStreamSourceFlagMask;
    mStreamFrequencies[streamSlot] = (context->type_ == kGeometryStreamType) ? static_cast<std::int32_t>(count) : 1;
  }

  void DeviceD3D11::SetBufferIndices(const boost::shared_ptr<IndexBuffer> indexBuffer)
  {
    auto* const buffer = static_cast<IndexBufferD3D11*>(indexBuffer.get());
    mImmediate->IASetIndexBuffer(buffer->GetBuffer(), buffer->GetIndexFormat(), 0U);
    RecordStateChange();
  }

  void DeviceD3D11::SetFogState(const bool, const Matrix* const, const float, const float, const int) {}

  void DeviceD3D11::SetWireframeState(const bool enabled)
  {
    mPipelineState->SetWireframe(enabled);
  }

  void DeviceD3D11::SetColorWriteState(const bool writeColor, const bool writeAlpha)
  {
    mPipelineState->SetColorWriteMask(writeColor, writeAlpha);
  }

  void DeviceD3D11::DrawIndexedPrimitive(const DrawIndexedContext* const context)
  {
    PrepareInputLayout();
    if (mTracing) {
      Trace("DrawIndexed topo %d idx %u start %u base %d inst %d fmt %u", static_cast<int>(context->topology_), context->indexCount_,
            context->startIndex_, context->baseVertexIndex_, mStreamFrequencies[0], mBoundFormat);
    }
    const auto token = static_cast<std::uint32_t>(context->topology_);
    if (token == 0U || token >= std::size(kTopologyByToken)) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "invalid topology specified");
    }
    mImmediate->IASetPrimitiveTopology(kTopologyByToken[token]);

    // D3D10 passes base vertex 0 (0x008FD16E); D3D9 passes the context's
    // BaseVertexIndex, which is what the engine means.
    const auto instanceCount = static_cast<UINT>(mStreamFrequencies[0]);
    if (instanceCount > 1U) {
      mImmediate->DrawIndexedInstanced(context->indexCount_, instanceCount, context->startIndex_, context->baseVertexIndex_, 0U);
    } else {
      mImmediate->DrawIndexed(context->indexCount_, context->startIndex_, context->baseVertexIndex_);
    }
    RecordDraw(context->GetPrimitiveCount(), context->vertexCount_);
  }

  void DeviceD3D11::DrawPrimitive(const DrawContext* const context)
  {
    PrepareInputLayout();
    if (mTracing) {
      Trace("Draw topo %d count %u start %u inst %d fmt %u", static_cast<int>(context->topology_), context->vertexCount_,
            context->startVertex_, mStreamFrequencies[0], mBoundFormat);
    }
    const auto token = static_cast<std::uint32_t>(context->topology_);
    if (token == 0U || token >= std::size(kTopologyByToken)) {
      ThrowError("DeviceD3D11.cpp", __LINE__, "invalid topology specified");
    }
    mImmediate->IASetPrimitiveTopology(kTopologyByToken[token]);

    const auto instanceCount = static_cast<UINT>(mStreamFrequencies[0]);
    if (instanceCount > 1U) {
      mImmediate->DrawInstanced(context->vertexCount_, instanceCount, context->startVertex_, 0U);
    } else {
      mImmediate->Draw(context->vertexCount_, context->startVertex_);
    }
    RecordDraw(context->GetPrimitiveCount(), context->vertexCount_);
  }

  void DeviceD3D11::BeginTechnique()
  {
    mPipelineState->BeginTechnique();
  }

  void DeviceD3D11::EndTechnique()
  {
    mPipelineState->EndTechnique();
  }

  bool DeviceD3D11::SupportsVertexTextureFormat(const std::uint32_t textureFormat)
  {
    const DXGI_FORMAT format = d3d11::TextureFormatToDxgi(textureFormat);
    if (mDevice == nullptr || format == DXGI_FORMAT_UNKNOWN) {
      return false;
    }
    UINT support = 0U;
    return SUCCEEDED(mDevice->CheckFormatSupport(format, &support)) && (support & D3D11_FORMAT_SUPPORT_TEXTURE2D) != 0U &&
      (support & D3D11_FORMAT_SUPPORT_SHADER_SAMPLE) != 0U;
  }

  // ---------------------------------------------------------------------------
  // GPU-driven additions (GpuDrivenD3D11)

  std::uint32_t DeviceD3D11::GetGpuDrivenFeatures() const
  {
    // CopyVertexBufferRegion is CopySubresourceRegion, on every feature level.
    return (mGpuDriven != nullptr ? mGpuDriven->Features() : 0U) | kGpuFeatureBufferCopy;
  }

  std::uint32_t DeviceD3D11::GetGpuDrivenVerified() const
  {
    // Each passed its parity checks on Direct3D 11 (docs/RENDERER_BACKENDS.md, GPU-driven paths).
    // Not kGpuPathParticleBatch: a paused A/B still shows extra particle specks with it on.
    return kGpuPathStrategicIcons | kGpuPathIconClassify | kGpuPathFogOfWar | kGpuPathSelectBrackets |
      kGpuPathProjectileIcons;
  }

  boost::shared_ptr<GpuBuffer> DeviceD3D11::CreateGpuBuffer(const GpuBufferDesc& desc)
  {
    return mGpuDriven != nullptr ? mGpuDriven->CreateBuffer(desc) : boost::shared_ptr<GpuBuffer>();
  }

  void DeviceD3D11::UpdateGpuBuffer(GpuBuffer& buffer, const std::uint32_t firstElement, const std::uint32_t count, const void* const data)
  {
    if (mGpuDriven != nullptr) {
      mGpuDriven->UpdateBuffer(buffer, firstElement, count, data);
    }
  }

  boost::shared_ptr<GpuProgram> DeviceD3D11::CreateGpuProgram(const GpuProgramDesc& desc)
  {
    return mGpuDriven != nullptr ? mGpuDriven->CreateProgram(desc) : boost::shared_ptr<GpuProgram>();
  }

  void DeviceD3D11::DrawGpuProgram(const GpuDrawCall& call)
  {
    if (mGpuDriven != nullptr) {
      mGpuDriven->Draw(call);
      // The draw replaced the input layout; the next engine draw rebuilds it.
      mInputLayoutDirty = true;
    }
  }

  void DeviceD3D11::DispatchGpuProgram(const GpuDispatch& dispatch)
  {
    if (mGpuDriven != nullptr) {
      mGpuDriven->Dispatch(dispatch);
    }
  }

  void DeviceD3D11::BeginProfileRegion(const std::uint32_t region)
  {
    if (mGpuDriven != nullptr) {
      mGpuDriven->BeginProfileRegion(region);
    }
  }

  void DeviceD3D11::EndProfileRegion(const std::uint32_t region)
  {
    if (mGpuDriven != nullptr) {
      mGpuDriven->EndProfileRegion(region);
    }
  }

  bool DeviceD3D11::CopyVertexBufferRegion(
    VertexBuffer& destination,
    const std::uint32_t destinationOffset,
    VertexBuffer& source,
    const std::uint32_t sourceOffset,
    const std::uint32_t byteCount
  )
  {
    auto& to = static_cast<VertexBufferD3D11&>(destination);
    auto& from = static_cast<VertexBufferD3D11&>(source);
    if (&to == &from || byteCount == 0U) {
      return false;
    }
    D3D11_BOX box{};
    box.left = sourceOffset;
    box.right = sourceOffset + byteCount;
    box.top = 0U;
    box.bottom = 1U;
    box.front = 0U;
    box.back = 1U;
    mImmediate->CopySubresourceRegion(to.GetBuffer(), 0U, destinationOffset, 0U, 0U, from.GetBuffer(), 0U, &box);
    return true;
  }

  bool DeviceD3D11::ReadGpuBuffer(GpuBuffer& buffer, const std::uint32_t firstElement, const std::uint32_t count, void* const out)
  {
    return mGpuDriven != nullptr && mGpuDriven->ReadBuffer(buffer, firstElement, count, out);
  }

  bool DeviceD3D11::GetRuntimeInfo(DeviceRuntimeInfo& out)
  {
    if (mDevice == nullptr) {
      return false;
    }
    out.api = "D3D11";
    out.featureLevel = FeatureLevelName(mFeatureLevel);
    if (mAdapterIndex < mFactory.Adapters().size()) {
      (void)FillDxgiAdapterInfo(mFactory.Adapters()[mAdapterIndex].adapter.Get(), out);
    }

    std::string chains;
    for (const std::unique_ptr<dxgi::SwapChain>& chain : mSwapChains) {
      if (chain == nullptr || chain->Get() == nullptr) {
        continue;
      }
      DXGI_SWAP_CHAIN_DESC desc{};
      (void)chain->Get()->GetDesc(&desc);
      char text[128] = {};
      std::snprintf(
        text, sizeof(text), "%s%ux%u %s %u buffers%s%s", chains.empty() ? "" : "; ", desc.BufferDesc.Width,
        desc.BufferDesc.Height, dxgi::SwapModelName(chain->Model()), chain->BufferCount(),
        chain->AllowsTearing() ? ", tearing" : "", desc.Windowed ? ", windowed" : ", full screen"
      );
      chains += text;
    }
    out.swapChain = chains.c_str();
    out.vsync = mDeviceContext.mVSync;
    out.gpuDrivenFeatures = GetGpuDrivenFeatures();
    return true;
  }
} // namespace gpg::gal
