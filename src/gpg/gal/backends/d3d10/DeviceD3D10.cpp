#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{
namespace
{

    // Address: 0x00D43078 (DAT_00D43078)
    constexpr std::uint32_t kPrimitiveTopologyByToken[15] = {
      0U,
      1U,
      2U,
      3U,
      4U,
      5U,
      10U,
      11U,
      12U,
      13U,
      0U,
      1U,
      3U,
      3U,
      4U,
    };

    // Address: 0x00D430A0 (DAT_00D430A0)
    constexpr std::int32_t kImageFileFormatByToken[5] = {0, 1, 3, 3, 4};

    // Address: 0x00D487AC (DAT_00D487AC)
    constexpr std::uint32_t kDepthStencilDxgiByToken[8] = {
      0U,
      40U,
      0U,
      45U,
      46U,
      0U,
      55U,
      0U,
    };

    constexpr std::uint32_t kVendorIdNvidia = 4318U;
    constexpr UINT kD3D10FormatSupportRenderTarget = 0x4000U;
    constexpr UINT kD3D10FormatSupportTexture2D = 0x20U;

    struct RttVertex final
    {
      float x = 0.0f;
      float y = 0.0f;
      float z = 0.0f;
      float u = 0.0f;
      float v = 0.0f;
    };

    static_assert(sizeof(RttVertex) == 0x14, "RttVertex size must be 0x14");

    constexpr RttVertex kRttFullscreenVertices[4] = {
      {-1.0f, -1.0f, 0.0f, 0.0f, 1.0f},
      {1.0f, -1.0f, 0.0f, 1.0f, 1.0f},
      {-1.0f, 1.0f, 0.0f, 0.0f, 0.0f},
      {1.0f, 1.0f, 0.0f, 1.0f, 0.0f},
    };

    struct NvidiaSampleCandidate final
    {
      unsigned int sampleType = 0U;
      unsigned int sampleQuality = 0U;
      const char* label = nullptr;
    };

    constexpr NvidiaSampleCandidate kNvidiaSampleCandidates[] = {
      {2U, 0U, "2"},
      {4U, 0U, "4"},
      {4U, 2U, "8"},
      {8U, 0U, "8Q"},
      {4U, 4U, "16"},
      {8U, 2U, "16Q"},
    };

    constexpr char kSignaturePreambleEffectSource[] =
#include "D3D10SignatureEffectSource.inl"
      ;
    constexpr char kRttEffectSource[] =
#include "D3D10RTTEffectSource.inl"
      ;

    static_assert(
      sizeof(kSignaturePreambleEffectSource) == 7789,
      "kSignaturePreambleEffectSource size must be 7789 (source + NUL)"
    );
    static_assert(sizeof(kRttEffectSource) == 1041, "kRttEffectSource size must be 1041 (source + NUL)");

    struct ShaderMacroPair final
    {
      const char* key = nullptr;
      const char* value = nullptr;
    };

    constexpr ShaderMacroPair kDeviceCreateEffectInjectedMacros[] = {
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
    };
    constexpr std::size_t kDeviceCreateEffectInjectedMacroCount =
      sizeof(kDeviceCreateEffectInjectedMacros) / sizeof(kDeviceCreateEffectInjectedMacros[0]);

    [[noreturn]] void ThrowDeviceD3D10Hresult(const int line, const HRESULT code)
    {
      throw Error(MakeShortString("DeviceD3D10.cpp"), line, MakeD3DErrorString(code));
    }

    /**
     * Address: 0x008EA950 (FUN_008EA950)
     *
     * What it does:
     * Appends one validated multisample option (`type/quality/label`) into one
     * head capability list.
     */
    void AppendHeadSampleOption(
      Head& head, const unsigned int sampleType, const unsigned int sampleQuality, const char* const label
    )
    {
      HeadSampleOption option{};
      option.sampleType = sampleType;
      option.sampleQuality = sampleQuality;
      option.label.assign_owned((label != nullptr) ? label : "");
      head.mStrs.push_back(option);
    }

    [[noreturn]] void ThrowInvalidTopologyError(const int line)
    {
      ThrowGalError("DeviceD3D10.cpp", line, "invalid topology specified");
    }

    std::uint32_t ResolvePrimitiveTopology(const std::uint32_t topologyToken) noexcept
    {
      return kPrimitiveTopologyByToken[topologyToken];
    }

    int ResolveImageFileFormatToken(const int token) noexcept
    {
      if ((token < 0) || (token >= 5)) {
        return 0;
      }

      return kImageFileFormatByToken[token];
    }

    /**
     * Address: 0x008F8890 (FUN_008F8890)
     *
     * DXGI_SWAP_CHAIN_DESC *,Head const *
     *
     * What it does:
     * Clears one swap-chain descriptor and populates presentation lanes from
     * one `Head` runtime view when a native window handle is present.
     */
    DXGI_SWAP_CHAIN_DESC*
    BuildSwapChainDescFromHead(DXGI_SWAP_CHAIN_DESC* const outDesc, const Head* const head)
    {
      std::memset(outDesc, 0, sizeof(DXGI_SWAP_CHAIN_DESC));
      if (head->mWindow == nullptr) {
        return outDesc;
      }

      outDesc->BufferDesc.Width = head->mWidth;
      outDesc->BufferDesc.Height = head->mHeight;
      outDesc->BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
      outDesc->BufferDesc.RefreshRate.Numerator = head->mWindowed ? head->framesPerSecond : 0U;
      outDesc->BufferDesc.RefreshRate.Denominator = 1U;
      outDesc->BufferDesc.Scaling = DXGI_MODE_SCALING_UNSPECIFIED;
      outDesc->BufferDesc.ScanlineOrdering = DXGI_MODE_SCANLINE_ORDER_UNSPECIFIED;
      outDesc->SampleDesc.Count = 1U;
      outDesc->SampleDesc.Quality = 0U;
      outDesc->BufferUsage = 48U;
      outDesc->BufferCount = 2U;
      outDesc->OutputWindow = static_cast<HWND>(head->mWindow);
      // Inverted on purpose: the binary writes DXGI's `Windowed` as
      // `mWindowed == 0`, and only takes the refresh rate above when
      // `mWindowed` is set -- a rate that matters only full-screen. So this
      // lane behaves as a full-screen flag whatever `Head` calls it.
      outDesc->Windowed = head->mWindowed ? FALSE : TRUE;
      outDesc->SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
      outDesc->Flags = 0U;
      return outDesc;
    }

    /**
     * Address: 0x00902D90 (FUN_00902D90, func_Fmt_Gal_to_DXGI)
     *
     * What it does:
     * Converts GAL render-target format token to DXGI format token through the
     * recovered 10-entry render-target mapping table.
     */
    int MapGalRenderTargetFormatToDxgi(const int galFormat)
    {
      for (const DXGIFormatPair& pair : kRenderTargetDxgiGalPairs) {
        if (pair.gal == galFormat) {
          return pair.dxgi;
        }
      }

      return 0;
    }

    /**
     * Address: 0x0094B170 (FUN_0094B170)
     *
     * What it does:
     * Maps depth-stencil format token to DXGI format through the recovered
     * `DAT_00D487AC` lookup lane.
     */
    int ResolveDepthStencilFormatToDxgi(const int formatToken) noexcept
    {
      return static_cast<int>(kDepthStencilDxgiByToken[formatToken]);
    }

    /**
     * Address: 0x008FDA10 (FUN_008FDA10)
     *
     * What it does:
     * Resolves the retained signature-effect pass for one vertex format token and
     * writes pass-desc IA signature lanes for input-layout creation.
     */
    void GetVertexInputSignatureOrThrow(
      DeviceD3D10* const device, const int formatToken, D3D10_PASS_DESC* const outPassDesc
    )
    {
      ID3D10Effect* const signatureEffect = device->mSignatureEffect;
      if (signatureEffect == nullptr) {
        ThrowGalError("DeviceD3D10.cpp", 1910, "internal D3D10 SignatureEffect error");
      }

      ID3D10EffectTechnique* const technique = signatureEffect->GetTechniqueByIndex(static_cast<UINT>(formatToken));
      if (technique == nullptr) {
        ThrowGalError("DeviceD3D10.cpp", 1913, "invalid format/technique combination");
      }

      static_cast<void>(technique->GetPassByIndex(0U)->GetDesc(outPassDesc));
    }
}


    // FAF addition, not in the shipped binary. GPG's D3D10 SetColorWriteState
    // and SetWireframeState (0x008FE6F0, 0x008FE6E0) are empty, so the engine's
    // colour-write masks (13 call sites) and wireframe toggle did nothing under
    // /D3D10. These hold what the engine last asked for; one device exists at a
    // time, and the binary-sized PipelineStateD3D10 has no room for them.
    UINT8 sColorWriteMask = D3D10_COLOR_WRITE_ENABLE_ALL;
    bool sWireframe = false;
namespace
{

    /**
     * FAF addition. The D3D9 backend's mask for the two flags
     * (`PipelineStateD3D9::SetColorWriteState`, 0x009461F0): both or neither
     * write everything, colour alone RGB, alpha alone A. D3D10's write-enable
     * bits are D3D9's.
     */
    [[nodiscard]] UINT8 ColorWriteMask(const bool writeColor, const bool writeAlpha) noexcept
    {
      constexpr UINT8 kRgb =
        D3D10_COLOR_WRITE_ENABLE_RED | D3D10_COLOR_WRITE_ENABLE_GREEN | D3D10_COLOR_WRITE_ENABLE_BLUE;
      if (writeColor) {
        return writeAlpha ? static_cast<UINT8>(D3D10_COLOR_WRITE_ENABLE_ALL) : kRgb;
      }
      return writeAlpha ? static_cast<UINT8>(D3D10_COLOR_WRITE_ENABLE_ALPHA)
                        : static_cast<UINT8>(D3D10_COLOR_WRITE_ENABLE_ALL);
    }
}


  /**
   * Address: 0x00900450 (FUN_00900450)
   * Address: 0x009005E0 (FUN_009005E0, slot 0: the scalar deleting destructor)
   *
   * What it does:
   * Releases the device objects and unloads the D3D10 modules; the member
   * destructors then run in reverse declaration order (cursor, pipeline
   * state, swap chains, adapters, device context, log, output context).
   */
  DeviceD3D10::~DeviceD3D10()
  {
    Shutdown();
  }

  /**
   * Address: 0x009001B0 (FUN_009001B0)
   *
   * What it does:
   * Releases the head targets, every swap chain and adapter in place (the
   * vectors keep their slots; the member destructors free them), the pipeline
   * state, the factory, the device, both helper effects and the RTT quad and
   * layout (not the RTT technique, which the effect owns), puts the cursor
   * back, resets the context, and unloads the three libraries. The exports
   * resolved from them are left as they were.
   */
  void DeviceD3D10::Shutdown()
  {
    DeleteOutputContexts(mHeadOutputContexts, static_cast<std::uint32_t>(mDeviceContext.GetHeadCount()));
    mHeadOutputContexts = nullptr;

    for (IDXGISwapChain*& swapChain : mSwapChains) {
      SafeRelease(swapChain);
    }

    for (AdapterD3D10& adapter : mAdapters) {
      ReleaseAdapterOutputAndDeviceRefs(&adapter);
    }

    mPipelineState.reset();

    SafeRelease(mDXGIFactory);
    SafeRelease(mDevice);
    SafeRelease(mSignatureEffect);
    SafeRelease(mRttEffect);
    SafeRelease(mRttQuadVertexBuffer);
    SafeRelease(mRttInputLayout);

    mCursor.Destroy();
    mDeviceContext = DeviceContext(DeviceApi::Unset);

    ::FreeLibrary(mDXGIModule);
    mDXGIModule = nullptr;
    ::FreeLibrary(mD3DX10Module);
    mD3DX10Module = nullptr;
    ::FreeLibrary(mD3D10Module);
    mD3D10Module = nullptr;
  }

  /**
   * Address: 0x008F8860 (FUN_008F8860)
   *
   * What it does:
   * Forwards to the linked `D3D10CreateBlob`.
   */
  HRESULT DeviceD3D10::CreateBlob(const SIZE_T size, ID3D10Blob** const outBlob)
  {
    return mD3D10CreateBlob(size, outBlob);
  }

  /**
   * Address: 0x008F8880 (FUN_008F8880)
   *
   * What it does:
   * Forwards to the linked `D3DX10SaveTextureToMemory`.
   */
  HRESULT DeviceD3D10::SaveTextureToMemory(
    ID3D10Resource* const texture, const D3DX10_IMAGE_FILE_FORMAT format, ID3D10Blob** const outBlob
  )
  {
    return mD3DX10SaveTextureToMemory(texture, format, outBlob);
  }

  /**
   * Address: 0x008FE5D0 (FUN_008FE5D0)
   *
   * What it does:
   * Installs the vtable, builds the output context at +0x04, zeroes the
   * module, export and COM lanes, builds the embedded `DeviceContext(Unset)` at
   * +0x60 and the cursor at +0x11C. Every one of those is a member
   * initializer on the class, so the body is empty: this used to be a free
   * factory that `new`ed an overlay and then reset each member by hand.
   */
  DeviceD3D10::DeviceD3D10() = default;

  /**
   * Address: 0x008F86B0 (FUN_008F86B0)
   *
   * What it does:
   * Returns the address of the retained device log-storage lane at `this+0x50`.
   */
  void* DeviceD3D10::GetLog()
  {
    return &mLog;
  }

  /**
   * Address: 0x008F86C0 (FUN_008F86C0)
   *
   * What it does:
   * `lea eax, [ecx+0x60]`: the address of the embedded context. (An earlier
   * recovery read the dword at +0x60 instead - the context's vptr.)
   */
  DeviceContext* DeviceD3D10::GetDeviceContext()
  {
    return &mDeviceContext;
  }

  /**
   * Address: 0x008F86D0 (FUN_008F86D0)
   *
   * What it does:
   * Returns the current thread-id snapshot lane from `this+0x4C`.
   */
  int DeviceD3D10::GetCurThreadId()
  {
    return mCurThreadId;
  }

  /**
   * Address: 0x008F86E0 (FUN_008F86E0)
   *
   * What it does:
   * Preserves the binary no-op virtual slot.
   */
  void DeviceD3D10::Func1() const {}

  /**
   * Address: 0x008F86F0 (FUN_008F86F0)
   *
   * What it does:
   * The shipped body is a bare `ret 8`, which left the options screen with no
   * resolutions under /D3D10.
   *
   * FAF addition: fills `outModes` the way the D3D9 backend does (0x008F0170),
   * from the modes `SetupDXGIDevice` already enumerated for the adapter's
   * outputs. Only the swap chain's format is listed (`BuildSwapChainDescFromHead`
   * asks for R8G8B8A8_UNORM); the enumeration covers eight formats, so taking
   * them all would repeat each resolution. An index past the adapter list
   * leaves the list empty, as on D3D9.
   */
  void DeviceD3D10::GetModesForAdapter(fa::vector<HeadAdapterMode>& outModes, const int adapterIndex)
  {
    outModes.clear();
    if (adapterIndex < 0 || adapterIndex >= static_cast<int>(mAdapters.size())) {
      return;
    }

    for (const AdapterModeD3D10& output : mAdapters[static_cast<std::size_t>(adapterIndex)].modes_) {
      for (const DXGI_MODE_DESC& mode : output.modes_) {
        if (mode.Format != DXGI_FORMAT_R8G8B8A8_UNORM) {
          continue;
        }

        const UINT refreshRate = (mode.RefreshRate.Denominator != 0U)
          ? (mode.RefreshRate.Numerator / mode.RefreshRate.Denominator)
          : mode.RefreshRate.Numerator;
        outModes.push_back(HeadAdapterMode{mode.Width, mode.Height, refreshRate});
      }
    }
  }

  /**
   * Address: 0x008FD2E0 (FUN_008FD2E0)
   *
   * What it does:
   * Dynamically resolves required D3D10/D3DX10/DXGI module exports used by
   * backend startup.
   */
  void DeviceD3D10::DynamicLink()
  {

    mD3D10Module = ::LoadLibraryA("d3d10.dll");
    if (mD3D10Module == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1645, "unable to explicitly link to d3d10.dll");
    }

    mD3D10CreateDevice = reinterpret_cast<D3D10CreateDeviceFn>(::GetProcAddress(mD3D10Module, "D3D10CreateDevice"));
    mD3D10CreateBlob = reinterpret_cast<D3D10CreateBlobFn>(
      ::GetProcAddress(mD3D10Module, "D3D10CreateBlob")
    );

    mD3DX10Module = ::LoadLibraryA("d3dx10.dll");
    if (mD3DX10Module == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1650, "unable to explicitly link to d3dx10.dll");
    }

    mD3DX10CreateEffectFromMemory = reinterpret_cast<D3DX10CreateEffectFromMemoryFn>(
      ::GetProcAddress(mD3DX10Module, "D3DX10CreateEffectFromMemory")
    );
    mD3DX10CreateTextureFromMemory = reinterpret_cast<D3DX10CreateTextureFromMemoryFn>(
      ::GetProcAddress(mD3DX10Module, "D3DX10CreateTextureFromMemory")
    );
    mD3DX10SaveTextureToFileA = reinterpret_cast<D3DX10SaveTextureToFileFn>(
      ::GetProcAddress(mD3DX10Module, "D3DX10SaveTextureToFileA")
    );
    mD3DX10SaveTextureToMemory = reinterpret_cast<D3DX10SaveTextureToMemoryFn>(
      ::GetProcAddress(mD3DX10Module, "D3DX10SaveTextureToMemory")
    );

    mDXGIModule = ::LoadLibraryA("dxgi.dll");
    if (mDXGIModule == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1657, "unable to explicitly link to dxgi.dll");
    }

    mCreateDXGIFactory = reinterpret_cast<CreateDXGIFactoryFn>(::GetProcAddress(mDXGIModule, "CreateDXGIFactory"));
  }

  /**
   * Address: 0x00900A70 (FUN_00900A70)
   *
   * What it does:
   * Enumerates DXGI adapters, probes adapter output mode caches, and stores
   * valid adapters into the backend adapter list.
   */
  int DeviceD3D10::SetupDXGIDevice()
  {
    mAdapters.clear();

    auto* const dxgiFactory = mDXGIFactory;
    if (dxgiFactory == nullptr) {
      return E_POINTER;
    }

    IDXGIAdapter* adapter = nullptr;
    HRESULT result = dxgiFactory->EnumAdapters(0U, &adapter);
    for (unsigned int adapterIndex = 0U; result >= 0; ++adapterIndex) {
      AdapterD3D10 adapterEntry(adapter);
      if (adapterEntry.ProbeOutputsAndModes() >= 0) {
        mAdapters.push_back(adapterEntry);
      }

      adapter = nullptr;
      result = dxgiFactory->EnumAdapters(adapterIndex + 1U, &adapter);
    }

    return (result == DXGI_ERROR_NOT_FOUND) ? 0 : result;
  }

  /**
   * Address: 0x008FDB80 (FUN_008FDB80)
   *
   * What it does:
   * Builds RTT helper effect/state resources (effect, technique, quad VB,
   * and input layout) used by stretch-rect paths.
   */
  void DeviceD3D10::SetUpRTT()
  {
    auto* const device = mDevice;

    const HRESULT createEffectResult = mD3DX10CreateEffectFromMemory(
      kRttEffectSource,
      sizeof(kRttEffectSource),
      nullptr,
      nullptr,
      nullptr,
      D3D10_SHADER_ENABLE_STRICTNESS,
      0U,
      device,
      nullptr,
      nullptr,
      &mRttEffect,
      nullptr
    );
    if (createEffectResult < 0) {
      ThrowDeviceD3D10Hresult(1925, createEffectResult);
    }

    auto* const shaderEffect = mRttEffect;
    mRttTechnique = shaderEffect->GetTechniqueByName("RTT");

    D3D10_BUFFER_DESC vertexBufferDesc{};
    vertexBufferDesc.ByteWidth = sizeof(kRttFullscreenVertices);
    vertexBufferDesc.Usage = D3D10_USAGE_IMMUTABLE;
    vertexBufferDesc.BindFlags = D3D10_BIND_VERTEX_BUFFER;
    vertexBufferDesc.CPUAccessFlags = 0U;
    vertexBufferDesc.MiscFlags = 0U;

    D3D10_SUBRESOURCE_DATA initialData{};
    initialData.pSysMem = kRttFullscreenVertices;
    initialData.SysMemPitch = 0U;
    initialData.SysMemSlicePitch = 0U;

    ID3D10Buffer* quadVertexBuffer = nullptr;
    static_cast<void>(device->CreateBuffer(&vertexBufferDesc, &initialData, &quadVertexBuffer));
    SafeRelease(mRttQuadVertexBuffer);
    mRttQuadVertexBuffer = quadVertexBuffer;

    D3D10_INPUT_ELEMENT_DESC inputElements[2]{};
    inputElements[0].SemanticName = "POSITION";
    inputElements[0].SemanticIndex = 0U;
    inputElements[0].Format = DXGI_FORMAT_R32G32B32_FLOAT;
    inputElements[0].InputSlot = 0U;
    inputElements[0].AlignedByteOffset = 0U;
    inputElements[0].InputSlotClass = D3D10_INPUT_PER_VERTEX_DATA;
    inputElements[0].InstanceDataStepRate = 0U;

    inputElements[1].SemanticName = "TEXCOORD";
    inputElements[1].SemanticIndex = 0U;
    inputElements[1].Format = DXGI_FORMAT_R32G32_FLOAT;
    inputElements[1].InputSlot = 0U;
    inputElements[1].AlignedByteOffset = 12U;
    inputElements[1].InputSlotClass = D3D10_INPUT_PER_VERTEX_DATA;
    inputElements[1].InstanceDataStepRate = 0U;

    auto* const technique = mRttTechnique;
    auto* const pass = technique->GetPassByIndex(0U);
    D3D10_PASS_DESC passDesc{};
    static_cast<void>(pass->GetDesc(&passDesc));

    ID3D10InputLayout* inputLayout = nullptr;
    const HRESULT createInputLayoutResult = device->CreateInputLayout(
      inputElements,
      2U,
      passDesc.pIAInputSignature,
      passDesc.IAInputSignatureSize,
      &inputLayout
    );
    if (createInputLayoutResult < 0) {
      ThrowDeviceD3D10Hresult(1970, createInputLayoutResult);
    }

    SafeRelease(mRttInputLayout);
    mRttInputLayout = inputLayout;
  }

  /**
   * Address: 0x008FF5B0 (FUN_008FF5B0)
   *
   * What it does:
   * Copies the requested device context into runtime, validates requested
   * head count, and populates per-head format/sample capability lanes.
   */
  std::uint32_t DeviceD3D10::CheckAvailableFormats(DeviceContext* const context)
  {
    mDeviceContext = *context;

    const std::uint32_t headCount = static_cast<std::uint32_t>(context->GetHeadCount());
    if (headCount > static_cast<std::uint32_t>(mAdapters.size())) {
      ThrowGalError("DeviceD3D10.cpp", 1695, "invalid head count specified in device context");
    }

    mDeviceContext.mMaxPrimitiveCount = 0x10000U;
    mDeviceContext.mMaxVertexCount = 0xFFFFU;
    mDeviceContext.mHWBasedInstancing = true;
    mDeviceContext.mVertexShaderProfile = 4;
    mDeviceContext.mPixelShaderProfile = 8;

    auto* const device = mDevice;
    for (std::uint32_t headIndex = 0U; headIndex < headCount; ++headIndex) {
      Head& head = mDeviceContext.GetHead(headIndex);
      const AdapterD3D10& adapter = mAdapters[headIndex];

      head.adapterModes.clear();
      for (const AdapterModeD3D10& adapterMode : adapter.modes_) {
        const DXGI_MODE_DESC* const modeBegin = adapterMode.modes_.begin();
        const DXGI_MODE_DESC* const modeEnd = adapterMode.modes_.end();
        for (const DXGI_MODE_DESC* mode = modeBegin; mode != modeEnd; ++mode) {
          HeadAdapterMode headMode{};
          headMode.width = mode->Width;
          headMode.height = mode->Height;
          headMode.refreshRate = (mode->RefreshRate.Denominator != 0U)
            ? (mode->RefreshRate.Numerator / mode->RefreshRate.Denominator)
            : mode->RefreshRate.Numerator;
          head.adapterModes.push_back(headMode);
        }
      }

      head.validFormats1.clear();
      for (int formatToken = 1; formatToken < 8; ++formatToken) {
        UINT supportFlags = 0U;
        const DXGI_FORMAT dxgiFormat = static_cast<DXGI_FORMAT>(MapGalRenderTargetFormatToDxgi(formatToken));
        if ((device->CheckFormatSupport(dxgiFormat, &supportFlags) >= 0) &&
            ((supportFlags & kD3D10FormatSupportRenderTarget) != 0U)) {
          head.validFormats1.push_back(formatToken);
        }
      }

      head.validFormats2.clear();
      for (int formatToken = 1; formatToken < 20; ++formatToken) {
        UINT supportFlags = 0U;
        const DXGI_FORMAT dxgiFormat = static_cast<DXGI_FORMAT>(MapGalTextureFormatToDxgi(formatToken));
        if ((device->CheckFormatSupport(dxgiFormat, &supportFlags) >= 0) &&
            ((supportFlags & kD3D10FormatSupportTexture2D) != 0U)) {
          head.validFormats2.push_back(formatToken);
        }
      }

      head.mStrs.clear();
      if (adapter.description_.VendorId != kVendorIdNvidia) {
        for (unsigned int sampleCount = 2U; sampleCount <= 16U; ++sampleCount) {
          UINT qualityLevels = 0U;
          if ((device->CheckMultisampleQualityLevels(DXGI_FORMAT_R8G8B8A8_UNORM, sampleCount, &qualityLevels) >= 0) &&
              (qualityLevels != 0U)) {
            char label[16]{};
            std::snprintf(label, sizeof(label), "%u", sampleCount);
            AppendHeadSampleOption(head, sampleCount, qualityLevels - 1U, label);
          }
        }
        continue;
      }

      for (const NvidiaSampleCandidate& candidate : kNvidiaSampleCandidates) {
        UINT qualityLevels = 0U;
        const HRESULT qualityResult =
          device->CheckMultisampleQualityLevels(DXGI_FORMAT_R8G8B8A8_UNORM, candidate.sampleType, &qualityLevels);
        if ((qualityResult < 0) || (qualityLevels <= candidate.sampleQuality)) {
          continue;
        }

        if ((candidate.sampleType == 4U) && (candidate.sampleQuality == 4U)) {
          UINT quality16 = 0U;
          const HRESULT quality16Result =
            device->CheckMultisampleQualityLevels(DXGI_FORMAT_R8G8B8A8_UNORM, 16U, &quality16);
          if ((quality16Result >= 0) && (quality16 > 16U)) {
            AppendHeadSampleOption(head, 16U, 16U, "16");
          }
          continue;
        }

        AppendHeadSampleOption(head, candidate.sampleType, candidate.sampleQuality, candidate.label);
      }
    }

    return headCount;
  }

  /**
   * FAF addition, not in the shipped binary.
   *
   * What it does:
   * Asks the device whether the format's DXGI equivalent can be a 2D texture
   * that shaders sample.
   */
  bool DeviceD3D10::SupportsVertexTextureFormat(const std::uint32_t textureFormat)
  {
    const auto dxgiFormat = static_cast<DXGI_FORMAT>(MapGalTextureFormatToDxgi(static_cast<int>(textureFormat)));
    if (mDevice == nullptr || dxgiFormat == DXGI_FORMAT_UNKNOWN) {
      return false;
    }

    UINT support = 0U;
    return SUCCEEDED(mDevice->CheckFormatSupport(dxgiFormat, &support)) &&
           (support & D3D10_FORMAT_SUPPORT_TEXTURE2D) != 0U && (support & D3D10_FORMAT_SUPPORT_SHADER_SAMPLE) != 0U;
  }

  /**
   * Address: 0x008FD500 (FUN_008FD500)
   *
   * What it does:
   * Creates per-head backbuffer render/depth target wrappers and stores
   * them in the runtime output-context array.
   */
  void DeviceD3D10::CreateRenderTargets()
  {
    const std::uint32_t headCount = static_cast<std::uint32_t>(mDeviceContext.GetHeadCount());

    if (mHeadOutputContexts != nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1818, "internal D3D10 device initialization error");
    }

    OutputContext* const outputContexts = NewOutputContexts(headCount);
    mHeadOutputContexts = outputContexts;

    auto* const device = mDevice;
    for (std::uint32_t headIndex = 0U; headIndex < headCount; ++headIndex) {
      auto* const swapChain = mSwapChains[headIndex];

      ID3D10Texture2D* backBuffer = nullptr;
      const HRESULT getBufferResult = swapChain->GetBuffer(0U, IID_PPV_ARGS(&backBuffer));
      if (getBufferResult < 0) {
        ThrowDeviceD3D10Hresult(1827, getBufferResult);
      }

      ID3D10RenderTargetView* renderTargetView = nullptr;
      const HRESULT createRtvResult = device->CreateRenderTargetView(backBuffer, nullptr, &renderTargetView);
      if (createRtvResult < 0) {
        ThrowDeviceD3D10Hresult(1835, createRtvResult);
      }

      D3D10_TEXTURE2D_DESC textureDesc{};
      backBuffer->GetDesc(&textureDesc);

      D3D10_SHADER_RESOURCE_VIEW_DESC shaderResourceViewDesc{};
      shaderResourceViewDesc.Format = textureDesc.Format;
      if (textureDesc.SampleDesc.Count > 1U) {
        shaderResourceViewDesc.ViewDimension = D3D10_SRV_DIMENSION_TEXTURE2DMS;
      } else {
        shaderResourceViewDesc.ViewDimension = D3D10_SRV_DIMENSION_TEXTURE2D;
        shaderResourceViewDesc.Texture2D.MostDetailedMip = 0U;
        shaderResourceViewDesc.Texture2D.MipLevels = textureDesc.MipLevels;
      }

      ID3D10ShaderResourceView* shaderResourceView = nullptr;
      const HRESULT createSrvResult =
        device->CreateShaderResourceView(backBuffer, &shaderResourceViewDesc, &shaderResourceView);
      if (createSrvResult < 0) {
        ThrowDeviceD3D10Hresult(1848, createSrvResult);
      }

      outputContexts[headIndex].surface.reset(new RenderTargetD3D10(backBuffer, renderTargetView, shaderResourceView));

      const DepthStencilTargetContext depthStencilContext(textureDesc.Width, textureDesc.Height, 3U, false);
      outputContexts[headIndex].depthStencil = CreateDepthStencilTarget(&depthStencilContext);
    }

    if (headCount > 0U) {
      static_cast<void>(ClearTarget(outputContexts));
    }
  }

  /**
   * Address: 0x00900B30 (FUN_00900B30)
   *
   * What it does:
   * Executes full D3D10 startup setup chain for one requested device
   * context (dynamic link, DXGI/device/swapchain/effects/state/capability
   * initialization).
   */
  void DeviceD3D10::Setup(DeviceContext* const context)
  {

    DynamicLink();
    mLog.clear();

    const HRESULT createFactoryResult = mCreateDXGIFactory(IID_PPV_ARGS(&mDXGIFactory));
    if (createFactoryResult < 0) {
      ThrowDeviceD3D10Hresult(610, createFactoryResult);
    }

    static_cast<void>(SetupDXGIDevice());
    if (mAdapters.empty()) {
      ThrowGalError("DeviceD3D10.cpp", 620, "unable to enumerate adapters");
    }

    const HRESULT createDeviceResult = mD3D10CreateDevice(
      mAdapters.front().dxgiAdapter_,
      D3D10_DRIVER_TYPE_HARDWARE,
      nullptr,
      0U,
      D3D10_SDK_VERSION,
      &mDevice
    );
    if (createDeviceResult < 0) {
      ThrowDeviceD3D10Hresult(622, createDeviceResult);
    }

    auto* const dxgiFactory = mDXGIFactory;
    for (unsigned int headIndex = 0U; headIndex < static_cast<unsigned int>(context->GetHeadCount()); ++headIndex) {
      const Head& head = context->GetHead(headIndex);
      DXGI_SWAP_CHAIN_DESC swapChainDesc{};
      BuildSwapChainDescFromHead(&swapChainDesc, &head);

      IDXGISwapChain* swapChain = nullptr;
      const HRESULT createSwapChainResult = dxgiFactory->CreateSwapChain(mDevice, &swapChainDesc, &swapChain);
      if (createSwapChainResult < 0) {
        ThrowDeviceD3D10Hresult(631, createSwapChainResult);
      }

      mSwapChains.push_back(swapChain);
    }

    const HRESULT createSignatureResult = mD3DX10CreateEffectFromMemory(
      kSignaturePreambleEffectSource,
      sizeof(kSignaturePreambleEffectSource),
      nullptr,
      nullptr,
      nullptr,
      D3D10_SHADER_ENABLE_STRICTNESS,
      0U,
      mDevice,
      nullptr,
      nullptr,
      &mSignatureEffect,
      nullptr
    );
    if (createSignatureResult < 0) {
      ThrowDeviceD3D10Hresult(641, createSignatureResult);
    }

    SetUpRTT();

    std::memset(mStreamFrequencies, 0, sizeof(mStreamFrequencies));
    mPipelineState.reset(new PipelineStateD3D10(mDevice));
    mPipelineState->SetDeviceState();

    static_cast<void>(CheckAvailableFormats(context));
    CreateRenderTargets();
  }

  /**
   * Address: 0x008FAB80 (FUN_008FAB80)
   *
   * What it does:
   * Validates one head index against the device context's head count
   * (`sizeof(Head)` is 0x80, the `>> 7` of `size()`) and returns that head's
   * output context from `mHeadOutputContexts`.
   */
  OutputContext* DeviceD3D10::GetHeadOutputContext(const unsigned int headIndex)
  {
    if (headIndex >= mDeviceContext.mHeads.size()) {
      ThrowGalError("DeviceD3D10.cpp", 727, "invalid head index specified");
    }

    return &mHeadOutputContexts[headIndex];
  }

  /**
   * Address: 0x008FAC50 (FUN_008FAC50)
   *
   * What it does:
   * The const overload of `GetHeadOutputContext`; same body.
   */
  const OutputContext* DeviceD3D10::GetHeadOutputContext(const unsigned int headIndex) const
  {
    if (headIndex >= mDeviceContext.mHeads.size()) {
      ThrowGalError("DeviceD3D10.cpp", 733, "invalid head index specified");
    }

    return &mHeadOutputContexts[headIndex];
  }

  /**
   * Address: 0x008FA220 (FUN_008FA220)
   *
   * What it does:
   * Returns a new reference to the device's pipeline state.
   */
  boost::shared_ptr<PipelineState> DeviceD3D10::GetPipelineState()
  {
    return mPipelineState;
  }

  /**
   * Address: 0x008FEA00 (FUN_008FEA00)
   * Slot: 9
   *
   * What it does:
   * Copies the context and defines the 20 D3D10 state macros on the copy
   * (`EffectContext::DefineMacro`, which throws on a duplicate key), then
   * compiles the caller's source with the copy's macros. The copy and the
   * error text go out of scope before the effect is wrapped (0x008FEF4D, then
   * `new` at 0x008FEF5A), and the define array is never freed -- the binary
   * has no `delete[]` for it on any path, the same as the D3D9 builder's.
   */
  boost::shared_ptr<Effect> DeviceD3D10::CreateEffect(const EffectContext& context)
  {
    ID3D10Effect* dxEffect = nullptr;
    {
      EffectContext localContext(context);
      for (std::size_t i = 0U; i < kDeviceCreateEffectInjectedMacroCount; ++i) {
        localContext.DefineMacro(
          kDeviceCreateEffectInjectedMacros[i].key,
          kDeviceCreateEffectInjectedMacros[i].value
        );
      }

      const std::size_t macroCount = localContext.mMacros.size();
      D3D10_SHADER_MACRO* defines = nullptr;
      if (macroCount != 0U) {
        defines = new D3D10_SHADER_MACRO[macroCount + 1U];

        std::size_t index = 0U;
        for (const EffectMacro& macro : localContext.mMacros) {
          defines[index].Name = macro.keyText_.c_str();
          defines[index].Definition = macro.valueText_.c_str();
          ++index;
        }

        defines[macroCount].Name = nullptr;
        defines[macroCount].Definition = nullptr;
      }

      ID3D10Blob* errorBlob = nullptr;
      if (context.mSourceType != 2U) {
        ThrowGalError("DeviceD3D10.cpp", 818, "invalid source defined for effect");
      }

      const char* const sourceData = context.mSourceBuffer.mBegin;
      const SIZE_T sourceBytes = static_cast<SIZE_T>(context.mSourceBuffer.mEnd - context.mSourceBuffer.mBegin);
      const HRESULT result = mD3DX10CreateEffectFromMemory(
        sourceData,
        sourceBytes,
        nullptr,
        defines,
        nullptr,
        D3D10_SHADER_ENABLE_BACKWARDS_COMPATIBILITY,
        0U,
        mDevice,
        nullptr,
        nullptr,
        &dxEffect,
        &errorBlob
      );

      fa::string reason("unknown error");
      if ((result < 0) && (errorBlob != nullptr)) {
        reason.assign_owned(static_cast<const char*>(errorBlob->GetBufferPointer()));
      }

      SafeRelease(errorBlob);

      if (result < 0) {
        fa::string message("unable to create effect: ");
        message = message + context.mSourcePath;
        message = message + " reason: ";
        message = message + reason;
        ThrowGalError("DeviceD3D10.cpp", 828, message.c_str());
      }
    }

    return boost::shared_ptr<Effect>(new EffectD3D10(context, dxEffect));
  }

  /**
   * Address: 0x008FAD20 (FUN_008FAD20)
   *
   * What it does:
   * Creates one texture (from in-memory file data, or empty at the context's
   * size and format) with its shader-resource view and wraps both in a
   * `TextureD3D10`.
   */
  boost::shared_ptr<Texture> DeviceD3D10::CreateTexture(const TextureContext* const context)
  {
    ID3D10Texture2D* nativeTexture = nullptr;
    ID3D10ShaderResourceView* shaderResourceView = nullptr;

    if (context->source_ != 1U) {
      if (context->source_ != 2U) {
        ThrowGalError("DeviceD3D10.cpp", 890, "invalid source specified for texture data");
      }

      D3D10_TEXTURE2D_DESC textureDesc{};
      textureDesc.Width = context->width_;
      textureDesc.Height = context->height_;
      textureDesc.MipLevels = (context->mipmapLevels_ != 0U) ? context->mipmapLevels_ : 1U;
      textureDesc.ArraySize = 1U;
      textureDesc.Format = static_cast<DXGI_FORMAT>(MapGalTextureFormatToDxgi(static_cast<int>(context->format_)));
      if (textureDesc.Format == DXGI_FORMAT_B8G8R8A8_UNORM) {
        gpg::HandleAssertFailure(
          "DXGI_FORMAT_B8G8R8A8_UNORM != tex2ddesc.Format",
          872,
          "c:\\work\\rts\\main\\code\\src\\libs\\gpggal\\DeviceD3D10.cpp"
        );
      }
      if (textureDesc.Format == DXGI_FORMAT_B8G8R8X8_UNORM) {
        gpg::HandleAssertFailure(
          "DXGI_FORMAT_B8G8R8X8_UNORM != tex2ddesc.Format",
          873,
          "c:\\work\\rts\\main\\code\\src\\libs\\gpggal\\DeviceD3D10.cpp"
        );
      }
      textureDesc.SampleDesc.Count = 1U;
      textureDesc.SampleDesc.Quality = 0U;
      textureDesc.Usage = D3D10_USAGE_DYNAMIC;
      textureDesc.BindFlags = 8U;
      textureDesc.CPUAccessFlags = 0x10000U;
      textureDesc.MiscFlags = 0U;

      const HRESULT createTextureResult = mDevice->CreateTexture2D(&textureDesc, nullptr, &nativeTexture);
      if (createTextureResult < 0) {
        ThrowGalErrorFromHresult("DeviceD3D10.cpp", 886, createTextureResult);
      }
    } else {
      if (context->dataBuffer_.mEnd == context->dataBuffer_.mBegin) {
        ThrowGalError("DeviceD3D10.cpp", 855, "attempt to create texture from uninitialized memory");
      }

      ID3D10Resource* textureResource = nullptr;
      const char* const sourceData = context->dataBuffer_.mBegin;
      const SIZE_T sourceBytes = context->DataSizeBytes();
      const HRESULT createFromMemoryResult =
        mD3DX10CreateTextureFromMemory(mDevice, sourceData, sourceBytes, nullptr, nullptr, &textureResource);
      if (createFromMemoryResult < 0) {
        ThrowGalErrorFromHresult("DeviceD3D10.cpp", 857, createFromMemoryResult);
      }

      if (textureResource != nullptr) {
        static_cast<void>(textureResource->QueryInterface(IID_PPV_ARGS(&nativeTexture)));
        SafeRelease(textureResource);
      }
    }

    if (nativeTexture != nullptr) {
      D3D10_TEXTURE2D_DESC textureDesc{};
      nativeTexture->GetDesc(&textureDesc);

      D3D10_SHADER_RESOURCE_VIEW_DESC shaderResourceViewDesc{};
      shaderResourceViewDesc.Format = DXGI_FORMAT_UNKNOWN;
      shaderResourceViewDesc.ViewDimension =
        (textureDesc.MiscFlags != 4U) ? D3D10_SRV_DIMENSION_TEXTURE2D : D3D10_SRV_DIMENSION_TEXTURECUBE;
      shaderResourceViewDesc.Texture2D.MostDetailedMip = 0U;
      shaderResourceViewDesc.Texture2D.MipLevels = textureDesc.MipLevels;

      const HRESULT createSrvResult =
        mDevice->CreateShaderResourceView(nativeTexture, &shaderResourceViewDesc, &shaderResourceView);
      if (createSrvResult < 0) {
        ThrowGalErrorFromHresult("DeviceD3D10.cpp", 912, createSrvResult);
      }
    }

    return boost::shared_ptr<Texture>(new TextureD3D10(context, nativeTexture, shaderResourceView));
  }

  /**
   * Address: 0x008FB1D0 (FUN_008FB1D0)
   *
   * What it does:
   * Creates one render-target/shader-resource 2D texture with its RTV and
   * SRV, sets a viewport covering it, and wraps all three in a
   * `RenderTargetD3D10`.
   */
  boost::shared_ptr<RenderTarget> DeviceD3D10::CreateRenderTarget(const RenderTargetContext* const context)
  {
    D3D10_TEXTURE2D_DESC textureDesc{};
    textureDesc.Width = context->width_;
    textureDesc.Height = context->height_;
    textureDesc.MipLevels = 1U;
    textureDesc.ArraySize = 1U;
    textureDesc.Format = static_cast<DXGI_FORMAT>(MapGalRenderTargetFormatToDxgi(static_cast<int>(context->format_)));
    textureDesc.SampleDesc.Count = 1U;
    textureDesc.SampleDesc.Quality = 0U;
    textureDesc.Usage = D3D10_USAGE_DEFAULT;
    textureDesc.BindFlags = 0x28U;
    textureDesc.CPUAccessFlags = 0U;
    textureDesc.MiscFlags = 0U;

    ID3D10Texture2D* nativeTexture = nullptr;
    const HRESULT createTextureResult = mDevice->CreateTexture2D(&textureDesc, nullptr, &nativeTexture);
    if (createTextureResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 941, createTextureResult);
    }

    ID3D10RenderTargetView* renderTargetView = nullptr;
    const HRESULT createRtvResult = mDevice->CreateRenderTargetView(nativeTexture, nullptr, &renderTargetView);
    if (createRtvResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 945, createRtvResult);
    }

    D3D10_SHADER_RESOURCE_VIEW_DESC shaderResourceViewDesc{};
    shaderResourceViewDesc.Format = textureDesc.Format;
    shaderResourceViewDesc.ViewDimension = D3D10_SRV_DIMENSION_TEXTURE2D;
    shaderResourceViewDesc.Texture2D.MostDetailedMip = 0U;
    shaderResourceViewDesc.Texture2D.MipLevels = textureDesc.MipLevels;

    ID3D10ShaderResourceView* shaderResourceView = nullptr;
    const HRESULT createSrvResult =
      mDevice->CreateShaderResourceView(nativeTexture, &shaderResourceViewDesc, &shaderResourceView);
    if (createSrvResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 954, createSrvResult);
    }

    D3DVIEWPORT9 viewport{};
    viewport.Width = context->width_;
    viewport.Height = context->height_;
    viewport.MinZ = 0.0f;
    viewport.MaxZ = 1.0f;
    SetViewport(&viewport);

    return boost::shared_ptr<RenderTarget>(
      new RenderTargetD3D10(context, nativeTexture, renderTargetView, shaderResourceView)
    );
  }

  /**
   * Address: 0x008FA6B0 (FUN_008FA6B0)
   *
   * What it does:
   * Returns an empty `CubeRenderTargetD3D10`. Its constructor (0x008F7F80)
   * takes the context but only default-constructs its own copy, and the
   * D3D10 backend never creates a native cube texture.
   */
  boost::shared_ptr<CubeRenderTarget> DeviceD3D10::CreateCubeRenderTarget(const CubeRenderTargetContext* const context)
  {
    return boost::shared_ptr<CubeRenderTarget>(new CubeRenderTargetD3D10(context));
  }

  /**
   * Address: 0x008FB570 (FUN_008FB570)
   *
   * What it does:
   * Creates one depth texture with its DSV (plus an SRV when the context asks
   * for a sampleable target) and wraps them in a `DepthStencilTargetD3D10`.
   */
  boost::shared_ptr<DepthStencilTarget> DeviceD3D10::CreateDepthStencilTarget(const DepthStencilTargetContext* const context)
  {
    const DXGI_FORMAT depthFormat =
      static_cast<DXGI_FORMAT>(ResolveDepthStencilFormatToDxgi(static_cast<int>(context->format_)));

    D3D10_TEXTURE2D_DESC textureDesc{};
    textureDesc.Width = context->width_;
    textureDesc.Height = context->height_;
    textureDesc.MipLevels = 1U;
    textureDesc.ArraySize = 1U;
    textureDesc.Format = depthFormat;
    textureDesc.SampleDesc.Count = 1U;
    textureDesc.SampleDesc.Quality = 0U;
    textureDesc.Usage = D3D10_USAGE_DEFAULT;
    textureDesc.BindFlags = context->field0x10_ ? 0x48U : 0x40U;
    textureDesc.CPUAccessFlags = 0U;
    textureDesc.MiscFlags = 0U;

    ID3D10Texture2D* depthTexture = nullptr;
    const HRESULT createTextureResult = mDevice->CreateTexture2D(&textureDesc, nullptr, &depthTexture);
    if (createTextureResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 993, createTextureResult);
    }

    D3D10_DEPTH_STENCIL_VIEW_DESC depthStencilViewDesc{};
    depthStencilViewDesc.Format = depthFormat;
    depthStencilViewDesc.ViewDimension = D3D10_DSV_DIMENSION_TEXTURE2D;
    depthStencilViewDesc.Texture2D.MipSlice = 0U;

    ID3D10DepthStencilView* depthStencilView = nullptr;
    const HRESULT createDsvResult =
      mDevice->CreateDepthStencilView(depthTexture, &depthStencilViewDesc, &depthStencilView);
    if (createDsvResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1001, createDsvResult);
    }

    ID3D10ShaderResourceView* shaderResourceView = nullptr;
    if (context->field0x10_) {
      D3D10_SHADER_RESOURCE_VIEW_DESC shaderResourceViewDesc{};
      shaderResourceViewDesc.Format = depthFormat;
      shaderResourceViewDesc.ViewDimension = D3D10_SRV_DIMENSION_TEXTURE2D;
      shaderResourceViewDesc.Texture2D.MostDetailedMip = 0U;
      shaderResourceViewDesc.Texture2D.MipLevels = 1U;

      const HRESULT createSrvResult =
        mDevice->CreateShaderResourceView(depthTexture, &shaderResourceViewDesc, &shaderResourceView);
      if (createSrvResult < 0) {
        ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1013, createSrvResult);
      }
    }

    return boost::shared_ptr<DepthStencilTarget>(
      new DepthStencilTargetD3D10(context, depthTexture, depthStencilView, shaderResourceView)
    );
  }

  /**
   * Address: 0x008FE220 (FUN_008FE220)
   *
   * What it does:
   * Builds the input layout for gal vertex format `formatToken` against the
   * signature effect's pass for that format and wraps it in a
   * `VertexFormatD3D10`.
   */
  boost::shared_ptr<VertexFormat> DeviceD3D10::CreateVertexFormat(const std::uint32_t formatToken)
  {
    const D3D10_INPUT_ELEMENT_DESC* const elements = GetVertexLayoutElementsOrThrow(formatToken);
    const std::uint32_t elementCount = GetVertexLayoutElementCountOrThrow(formatToken);

    D3D10_PASS_DESC passDesc{};
    GetVertexInputSignatureOrThrow(this, static_cast<int>(formatToken), &passDesc);

    ID3D10InputLayout* inputLayout = nullptr;
    const HRESULT createInputLayoutResult = mDevice->CreateInputLayout(
      elements, elementCount, passDesc.pIAInputSignature, passDesc.IAInputSignatureSize, &inputLayout
    );
    if (createInputLayoutResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1029, createInputLayoutResult);
    }

    return boost::shared_ptr<VertexFormat>(new VertexFormatD3D10(formatToken, inputLayout));
  }

  /**
   * Address: 0x008FB8D0 (FUN_008FB8D0)
   *
   * What it does:
   * Creates one GPU vertex buffer and the staging buffer `Lock` maps, and
   * wraps both in a `VertexBufferD3D10`.
   */
  boost::shared_ptr<VertexBuffer> DeviceD3D10::CreateVertexBuffer(const VertexBufferContext* const context)
  {
    const std::uint32_t byteWidth = context->vertexCount_ * context->stride_;

    D3D10_BUFFER_DESC gpuBufferDesc{};
    gpuBufferDesc.ByteWidth = byteWidth;
    gpuBufferDesc.Usage = (context->usage_ == 2U) ? D3D10_USAGE_DYNAMIC : D3D10_USAGE_DEFAULT;
    gpuBufferDesc.BindFlags = 1U;
    gpuBufferDesc.CPUAccessFlags = (context->usage_ == 2U) ? 0x10000U : 0U;
    gpuBufferDesc.MiscFlags = 0U;

    ID3D10Buffer* gpuBuffer = nullptr;
    const HRESULT createGpuBufferResult = mDevice->CreateBuffer(&gpuBufferDesc, nullptr, &gpuBuffer);
    if (createGpuBufferResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1049, createGpuBufferResult);
    }

    D3D10_BUFFER_DESC stagingBufferDesc{};
    stagingBufferDesc.ByteWidth = byteWidth;
    stagingBufferDesc.Usage = D3D10_USAGE_STAGING;
    stagingBufferDesc.BindFlags = 0U;
    stagingBufferDesc.CPUAccessFlags = 0x10000U;
    stagingBufferDesc.MiscFlags = 0U;

    ID3D10Buffer* stagingBuffer = nullptr;
    const HRESULT createStagingBufferResult = mDevice->CreateBuffer(&stagingBufferDesc, nullptr, &stagingBuffer);
    if (createStagingBufferResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1056, createStagingBufferResult);
    }

    return boost::shared_ptr<VertexBuffer>(
      new VertexBufferD3D10(context, mDevice, gpuBuffer, stagingBuffer)
    );
  }

  /**
   * Address: 0x008FBB60 (FUN_008FBB60)
   *
   * What it does:
   * Creates one GPU index buffer and the staging buffer `Lock` maps, and
   * wraps both in an `IndexBufferD3D10`.
   */
  boost::shared_ptr<IndexBuffer> DeviceD3D10::CreateIndexBuffer(const IndexBufferContext* const context)
  {
    const std::uint32_t bytesPerIndex = (context->format_ == 1U) ? 2U : 4U;
    const std::uint32_t byteWidth = context->size_ * bytesPerIndex;

    D3D10_BUFFER_DESC gpuBufferDesc{};
    gpuBufferDesc.ByteWidth = byteWidth;
    gpuBufferDesc.Usage = (context->type_ == 2U) ? D3D10_USAGE_DYNAMIC : D3D10_USAGE_DEFAULT;
    gpuBufferDesc.BindFlags = 2U;
    gpuBufferDesc.CPUAccessFlags = (context->type_ == 2U) ? 0x10000U : 0U;
    gpuBufferDesc.MiscFlags = 0U;

    ID3D10Buffer* gpuBuffer = nullptr;
    const HRESULT createGpuBufferResult = mDevice->CreateBuffer(&gpuBufferDesc, nullptr, &gpuBuffer);
    if (createGpuBufferResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1076, createGpuBufferResult);
    }

    D3D10_BUFFER_DESC stagingBufferDesc{};
    stagingBufferDesc.ByteWidth = byteWidth;
    stagingBufferDesc.Usage = D3D10_USAGE_STAGING;
    stagingBufferDesc.BindFlags = 0U;
    stagingBufferDesc.CPUAccessFlags = 0x10000U;
    stagingBufferDesc.MiscFlags = 0U;

    ID3D10Buffer* stagingBuffer = nullptr;
    const HRESULT createStagingBufferResult = mDevice->CreateBuffer(&stagingBufferDesc, nullptr, &stagingBuffer);
    if (createStagingBufferResult < 0) {
      ThrowGalErrorFromHresult("DeviceD3D10.cpp", 1083, createStagingBufferResult);
    }

    return boost::shared_ptr<IndexBuffer>(
      new IndexBufferD3D10(context, mDevice, gpuBuffer, stagingBuffer)
    );
  }

  /**
   * Address: 0x008FC540 (FUN_008FC540)
   *
   * What it does:
   * Reads one colour target back into a texture with one native
   * `CopyResource` from the target's texture into the destination's.
   */
  void DeviceD3D10::GetRenderTargetData(
    const boost::shared_ptr<RenderTarget>& source, const boost::shared_ptr<Texture>& destination
  )
  {
    if (source.get() == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1230, "Missing source texture");
    }

    if (destination.get() == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1231, "Missing dest   texture");
    }

    ID3D10Texture2D* const sourceResource = static_cast<RenderTargetD3D10*>(source.get())->GetRenderTextureOrThrow();
    ID3D10Texture2D* const destinationResource = static_cast<TextureD3D10*>(destination.get())->GetTextureOrThrow();
    mDevice->CopyResource(destinationResource, sourceResource);
  }

  /**
   * Address: 0x008FC290 (FUN_008FC290)
   *
   * What it does:
   * Copies from source to destination target directly when their size and
   * format match; otherwise draws the source's SRV into the destination's
   * RTV through the RTT effect. On D3D10 only the destination rectangle's
   * top-left corner is used.
   */
  void DeviceD3D10::StretchRect(
    const boost::shared_ptr<RenderTarget>& source,
    const boost::shared_ptr<RenderTarget>& destination,
    const RECT* const sourceRect,
    const RECT* const destinationRect
  )
  {
    if (source.get() == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1174, "Missing source texture");
    }

    if (destination.get() == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1175, "Missing dest   texture");
    }

    auto* const sourceTarget = static_cast<RenderTargetD3D10*>(source.get());
    auto* const destinationTarget = static_cast<RenderTargetD3D10*>(destination.get());
    const RenderTargetContext* const sourceContext = sourceTarget->GetContext();
    const RenderTargetContext* const destinationContext = destinationTarget->GetContext();

    if ((sourceContext->width_ == destinationContext->width_) &&
        (sourceContext->height_ == destinationContext->height_) &&
        (sourceContext->format_ == destinationContext->format_)) {
      unsigned int destinationX = 0U;
      unsigned int destinationY = 0U;
      if (destinationRect != nullptr) {
        destinationX = static_cast<unsigned int>(destinationRect->left);
        destinationY = static_cast<unsigned int>(destinationRect->top);
      }

      D3D10_BOX sourceBox{};
      const D3D10_BOX* sourceBoxPtr = nullptr;
      if (sourceRect != nullptr) {
        const RECT* const rect = sourceRect;
        sourceBox.left = static_cast<unsigned int>(rect->left);
        sourceBox.top = static_cast<unsigned int>(rect->top);
        sourceBox.front = 0U;
        sourceBox.right = static_cast<unsigned int>(rect->right);
        sourceBox.bottom = static_cast<unsigned int>(rect->bottom);
        sourceBox.back = 1U;
        sourceBoxPtr = &sourceBox;
      }

      ID3D10Texture2D* const sourceResource = sourceTarget->GetRenderTextureOrThrow();
      ID3D10Texture2D* const destinationResource = destinationTarget->GetRenderTextureOrThrow();
      mDevice->CopySubresourceRegion(
        destinationResource, 0U, destinationX, destinationY, 0U, sourceResource, 0U, sourceBoxPtr
      );
      return;
    }

    StretchRectBlit(
      destinationContext->width_,
      destinationContext->height_,
      destinationTarget->GetRenderTargetViewOrThrow(),
      sourceTarget->GetShaderResourceViewOrThrow()
    );
  }

  /**
   * Address: 0x008F8920 (FUN_008F8920)
   *
   * What it does:
   * Saves the viewport, covers the destination with one when there is a
   * destination, saves the bound targets, binds the RTT layout, quad strip and
   * destination, then draws the four-vertex strip once per RTT pass with
   * `g_txSource` set to `source`, and restores the viewport and targets.
   */
  void DeviceD3D10::StretchRectBlit(
    const UINT width, const UINT height, ID3D10RenderTargetView* const destination, ID3D10ShaderResourceView* const source
  )
  {
    D3D10_VIEWPORT savedViewport{};
    UINT savedViewportCount = 1U;
    mDevice->RSGetViewports(&savedViewportCount, &savedViewport);

    if (destination != nullptr) {
      D3D10_VIEWPORT fullViewport{};
      fullViewport.Width = width;
      fullViewport.Height = height;
      fullViewport.MinDepth = 0.0f;
      fullViewport.MaxDepth = 1.0f;
      mDevice->RSSetViewports(1U, &fullViewport);
    }

    ID3D10RenderTargetView* previousRenderTargetView = nullptr;
    ID3D10DepthStencilView* previousDepthStencilView = nullptr;
    mDevice->OMGetRenderTargets(1U, &previousRenderTargetView, &previousDepthStencilView);

    mDevice->IASetInputLayout(mRttInputLayout);
    const UINT stride = sizeof(RttVertex);
    const UINT offset = 0U;
    mDevice->IASetVertexBuffers(0U, 1U, &mRttQuadVertexBuffer, &stride, &offset);
    mDevice->IASetPrimitiveTopology(D3D10_PRIMITIVE_TOPOLOGY_TRIANGLESTRIP);

    if (destination != nullptr) {
      ID3D10RenderTargetView* const renderTargets[1] = {destination};
      mDevice->OMSetRenderTargets(1U, renderTargets, nullptr);
    }

    D3D10_TECHNIQUE_DESC techniqueDesc{};
    mRttTechnique->GetDesc(&techniqueDesc);
    for (UINT passIndex = 0U; passIndex < techniqueDesc.Passes; ++passIndex) {
      mRttEffect->GetVariableByName("g_txSource")->AsShaderResource()->SetResource(source);
      mRttTechnique->GetPassByIndex(passIndex)->Apply(0U);
      mDevice->Draw(4U, 0U);
    }

    mDevice->RSSetViewports(1U, &savedViewport);
    mDevice->OMSetRenderTargets(1U, &previousRenderTargetView, previousDepthStencilView);
  }

  /**
   * Address: 0x008FBDF0 (FUN_008FBDF0)
   *
   * What it does:
   * Copies matching texture contexts directly; otherwise executes recovered
   * memory-encode/decode fallback before the final destination copy.
   */
  void DeviceD3D10::UpdateSurface(
    const boost::shared_ptr<Texture>& source,
    const boost::shared_ptr<Texture>& destination,
    const RECT* const sourceRect,
    const RECT* const destinationRect
  )
  {
    if (source.get() == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1091, "Missing source texture");
    }

    if (destination.get() == nullptr) {
      ThrowGalError("DeviceD3D10.cpp", 1092, "Missing dest   texture");
    }

    auto* const sourceTexture = static_cast<TextureD3D10*>(source.get());
    auto* const destinationTexture = static_cast<TextureD3D10*>(destination.get());
    const TextureContext* const sourceContext = sourceTexture->GetContext();
    const TextureContext* const destinationContext = destinationTexture->GetContext();
    if ((sourceContext->width_ == destinationContext->width_) &&
        (sourceContext->height_ == destinationContext->height_) &&
        (sourceContext->format_ == destinationContext->format_)) {
      unsigned int destinationX = 0U;
      unsigned int destinationY = 0U;
      if (destinationRect != nullptr) {
        destinationX = static_cast<unsigned int>(destinationRect->left);
        destinationY = static_cast<unsigned int>(destinationRect->top);
      }

      D3D10_BOX sourceBox{};
      const D3D10_BOX* sourceBoxPtr = nullptr;
      if (sourceRect != nullptr) {
        const RECT* const rect = sourceRect;
        sourceBox.left = static_cast<unsigned int>(rect->left);
        sourceBox.top = static_cast<unsigned int>(rect->top);
        sourceBox.front = 0U;
        sourceBox.right = static_cast<unsigned int>(rect->right);
        sourceBox.bottom = static_cast<unsigned int>(rect->bottom);
        sourceBox.back = 1U;
        sourceBoxPtr = &sourceBox;
      }

      ID3D10Texture2D* const sourceResource = sourceTexture->GetTextureOrThrow();
      ID3D10Texture2D* const destinationResource = destinationTexture->GetTextureOrThrow();
      mDevice->CopySubresourceRegion(
        destinationResource, 0U, destinationX, destinationY, 0U, sourceResource, 0U, sourceBoxPtr
      );
      return;
    }

    ID3D10Blob* createBlobScratch = nullptr;
    HRESULT result = mD3D10CreateBlob(0U, &createBlobScratch);
    if (result < 0) {
      ThrowDeviceD3D10Hresult(1109, result);
    }

    ID3D10Blob* encodedTextureBlob = nullptr;
    result = mD3DX10SaveTextureToMemory(sourceTexture->GetTextureOrThrow(), D3DX10_IFF_DDS, &encodedTextureBlob);
    if (result < 0) {
      SafeRelease(createBlobScratch);
      ThrowDeviceD3D10Hresult(1112, result);
    }

    // The SDK constructor's defaults (the out-of-line copy is 0x008F8670),
    // then one mip level of DXT5.
    D3DX10_IMAGE_LOAD_INFO loadInfo;
    loadInfo.MipLevels = 1U;
    loadInfo.Format = DXGI_FORMAT_BC3_UNORM;

    ID3D10Resource* recreatedTexture = nullptr;
    if (encodedTextureBlob != nullptr) {
      result = mD3DX10CreateTextureFromMemory(
        mDevice,
        encodedTextureBlob->GetBufferPointer(),
        encodedTextureBlob->GetBufferSize(),
        &loadInfo,
        nullptr,
        &recreatedTexture
      );
      if (result < 0) {
        SafeRelease(encodedTextureBlob);
        SafeRelease(createBlobScratch);
        ThrowDeviceD3D10Hresult(1130, result);
      }
    }

    if (recreatedTexture != nullptr) {
      mDevice->CopyResource(destinationTexture->GetTextureOrThrow(), recreatedTexture);
    }

    if (encodedTextureBlob == createBlobScratch) {
      createBlobScratch = nullptr;
    }

    SafeRelease(recreatedTexture);
    SafeRelease(encodedTextureBlob);
    SafeRelease(createBlobScratch);
  }

  /**
   * Address: 0x008FC9B0 (FUN_008FC9B0)
   *
   * What it does:
   * Writes one colour target's texture to `filePath`, mapping `fileFormat`
   * through the image-format table at `DAT_00D430A0`.
   */
  void DeviceD3D10::SaveRenderTarget(
    const boost::shared_ptr<RenderTarget>& renderTarget, const fa::string& filePath, const int fileFormat
  )
  {
    const int imageFileFormat = ResolveImageFileFormatToken(fileFormat);
    auto* const target = static_cast<RenderTargetD3D10*>(renderTarget.get());
    const HRESULT result = mD3DX10SaveTextureToFileA(
      target->GetRenderTextureOrThrow(), static_cast<D3DX10_IMAGE_FILE_FORMAT>(imageFileFormat), filePath.c_str()
    );
    if (result < 0) {
      ThrowDeviceD3D10Hresult(1286, result);
    }
  }

  /**
   * Address: 0x008FC6B0 (FUN_008FC6B0)
   *
   * What it does:
   * Encodes one texture in image format `fileFormat`: to `filePath` when
   * `outBuffer` is null, otherwise into `outBuffer` through a D3DX memory
   * blob.
   */
  void DeviceD3D10::SaveTexture(
    const boost::shared_ptr<Texture>& texture,
    const fa::string& filePath,
    const int fileFormat,
    gpg::MemBuffer<char>* const outBuffer
  )
  {
    const int imageFileFormat = ResolveImageFileFormatToken(fileFormat);
    auto* const sourceTexture = static_cast<TextureD3D10*>(texture.get());

    if (outBuffer == nullptr) {
      const HRESULT result = mD3DX10SaveTextureToFileA(
        sourceTexture->GetTextureOrThrow(), static_cast<D3DX10_IMAGE_FILE_FORMAT>(imageFileFormat), filePath.c_str()
      );
      if (result < 0) {
        ThrowDeviceD3D10Hresult(1275, result);
      }
      return;
    }

    ID3D10Blob* createBlobScratch = nullptr;
    HRESULT result = mD3D10CreateBlob(0U, &createBlobScratch);
    if (result < 0) {
      ThrowDeviceD3D10Hresult(1259, result);
    }

    ID3D10Blob* encodedBlob = nullptr;
    result = mD3DX10SaveTextureToMemory(
      sourceTexture->GetTextureOrThrow(), static_cast<D3DX10_IMAGE_FILE_FORMAT>(imageFileFormat), &encodedBlob
    );
    if (result >= 0) {
      const std::size_t encodedBytes = encodedBlob->GetBufferSize();
      if (outBuffer->Size() != encodedBytes) {
        gpg::MemBuffer<char> resizedBuffer = gpg::AllocMemBuffer(encodedBytes);
        *outBuffer = resizedBuffer;
      }

      // Raw encoded blob copy from the D3DX buffer.
      std::copy_n(static_cast<const char*>(encodedBlob->GetBufferPointer()), encodedBytes, outBuffer->GetPtr(0U, 0U));
    }

    if (encodedBlob == createBlobScratch) {
      createBlobScratch = nullptr;
    }

    SafeRelease(encodedBlob);
    SafeRelease(createBlobScratch);

    if (result < 0) {
      ThrowDeviceD3D10Hresult(1270, result);
    }
  }

  /**
   * Address: 0x008FCAC0 (FUN_008FCAC0)
   *
   * void const *,uint32_t,gpg::MemBuffer<char> *,uint32_t *,int *
   *
   * What it does:
   * Builds one texture resource from in-memory bytes, stages it for CPU read,
   * then copies mapped texture blocks into caller memory and writes width/height.
   */
  void DeviceD3D10::GetTexture2D(
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

    // The SDK constructor's defaults (inlined here), then one mip level of DXT5.
    D3DX10_IMAGE_LOAD_INFO loadInfo;
    loadInfo.MipLevels = 1U;
    loadInfo.Format = DXGI_FORMAT_BC3_UNORM;

    ID3D10Resource* decodedResource = nullptr;
    HRESULT result = mD3DX10CreateTextureFromMemory(mDevice, sourceData, sourceBytes, &loadInfo, nullptr, &decodedResource);
    if (result < 0) {
      ThrowDeviceD3D10Hresult(1317, result);
    }

    if (decodedResource == nullptr) {
      return;
    }

    ID3D10Texture2D* sourceTexture = nullptr;
    static_cast<void>(decodedResource->QueryInterface(IID_PPV_ARGS(&sourceTexture)));
    if (sourceTexture == nullptr) {
      // Kept from the binary: without the interface it uses the resource as a
      // 2D texture anyway.
      sourceTexture = static_cast<ID3D10Texture2D*>(decodedResource);
      sourceTexture->AddRef();
    }

    D3D10_TEXTURE2D_DESC textureDesc{};
    sourceTexture->GetDesc(&textureDesc);
    *outWidth = textureDesc.Width;
    *outHeight = static_cast<int>(textureDesc.Height);

    textureDesc.Usage = D3D10_USAGE_STAGING;
    textureDesc.BindFlags = 0U;
    textureDesc.CPUAccessFlags = D3D10_CPU_ACCESS_READ;

    ID3D10Texture2D* stagingTexture = nullptr;
    result = mDevice->CreateTexture2D(&textureDesc, nullptr, &stagingTexture);
    if (result < 0) {
      SafeRelease(sourceTexture);
      SafeRelease(decodedResource);
      ThrowDeviceD3D10Hresult(1343, result);
    }

    mDevice->CopyResource(stagingTexture, sourceTexture);

    D3D10_MAPPED_TEXTURE2D mappedTexture{};
    result = stagingTexture->Map(0U, D3D10_MAP_READ, 0U, &mappedTexture);
    if (result < 0) {
      SafeRelease(stagingTexture);
      SafeRelease(sourceTexture);
      SafeRelease(decodedResource);
      ThrowDeviceD3D10Hresult(1352, result);
    }

    const std::uint32_t rowBytes = 16U * ((textureDesc.Width + 3U) / 4U);
    const std::uint32_t rowCount = (textureDesc.Height + 3U) / 4U;
    const std::size_t requiredBytes = static_cast<std::size_t>(rowBytes) * static_cast<std::size_t>(rowCount);
    if (outTextureData->Size() != requiredBytes) {
      gpg::MemBuffer<char> resizedBuffer = gpg::AllocMemBuffer(requiredBytes);
      *outTextureData = resizedBuffer;
    }

    char* const destinationBytes = outTextureData->GetPtr(0U, 0U);
    const auto* const sourceBytesPtr = reinterpret_cast<const std::uint8_t*>(mappedTexture.pData);
    if (static_cast<unsigned int>(mappedTexture.RowPitch) == rowBytes) {
      // Raw texture blob copy from the mapped subresource.
      std::copy_n(sourceBytesPtr, requiredBytes, destinationBytes);
    } else {
      // Raw texture row blob copies from the mapped, pitched subresource.
      char* writeCursor = destinationBytes;
      for (std::uint32_t row = 0U; row < rowCount; ++row) {
        std::copy_n(sourceBytesPtr + (static_cast<std::size_t>(mappedTexture.RowPitch) * row), rowBytes, writeCursor);
        writeCursor += rowBytes;
      }
    }

    stagingTexture->Unmap(0U);
    SafeRelease(stagingTexture);
    SafeRelease(sourceTexture);
    SafeRelease(decodedResource);
  }

  /**
   * Address: 0x008FA260 (FUN_008FA260)
   *
   * boost::weak_ptr<void> *,boost::shared_ptr<void>
   *
   * What it does:
   * Clears caller weak-handle output lane and consumes one temporary shared
   * handle by value.
   */
  boost::weak_ptr<void>*
  DeviceD3D10::Func7(boost::weak_ptr<void>* const outWeakHandle, boost::shared_ptr<void> temporarySharedHandle)
  {
    static_cast<void>(temporarySharedHandle);
    outWeakHandle->reset();
    return outWeakHandle;
  }

  /**
   * Address: 0x008F8700 (FUN_008F8700)
   *
   * What it does:
   * D3D10 cannot save a cube target: the body is a bare `ret 8`.
   */
  void DeviceD3D10::SaveCubeRenderTarget(
    const boost::shared_ptr<CubeRenderTarget>& cubeTarget, const fa::string& filePath
  )
  {
    static_cast<void>(cubeTarget);
    static_cast<void>(filePath);
  }

  /**
   * Address: 0x008F8720 (FUN_008F8720)
   *
   * What it does:
   * Preserves the binary no-op virtual slot.
   */
  void DeviceD3D10::Reset() {}

  /**
   * Address: 0x008F8710 (FUN_008F8710)
   *
   * int
   *
   * What it does:
   * Preserves the binary no-op virtual slot (`retn 4` shape).
   */
  void DeviceD3D10::Reset(DeviceContext* const /*context*/)
  {
  }

  /**
   * Address: 0x008F8730 (FUN_008F8730)
   *
   * What it does:
   * Preserves the binary "device-ready" lane by returning success (`0`).
   */
  int DeviceD3D10::TestCooperativeLevel()
  {
    return 0;
  }

  /**
   * Address: 0x008F8740 (FUN_008F8740)
   *
   * What it does:
   * Preserves the binary no-op begin-scene slot.
   */
  void DeviceD3D10::BeginScene() {}

  /**
   * Address: 0x008F8750 (FUN_008F8750)
   *
   * What it does:
   * Preserves the binary no-op end-scene slot.
   */
  void DeviceD3D10::EndScene() {}

  /**
   * Address: 0x008F8760 (FUN_008F8760)
   *
   * CursorContext const *
   *
   * What it does:
   * Tail-delegates to the retained `CursorD3D10` lane at `this+0x11C` and
   * rebuilds/applies cursor icon state from caller context.
   */
  void DeviceD3D10::SetCursor(const CursorContext* const context)
  {
    static_cast<void>(mCursor.SetCursor(context));
  }

  /**
   * Address: 0x008F8770 (FUN_008F8770)
   *
   * What it does:
   * Tail-delegates to retained cursor lane initialization (`CursorD3D10::InitCursor`).
   */
  void DeviceD3D10::InitCursor()
  {
    static_cast<void>(mCursor.InitCursor());
  }

  /**
   * Address: 0x008F8780 (FUN_008F8780)
   *
   * bool
   *
   * What it does:
   * Tail-delegates to retained cursor show/hide loop control
   * (`CursorD3D10::ShowCursor`).
   */
  int DeviceD3D10::ShowCursor(const bool show)
  {
    return mCursor.ShowCursor(show);
  }

  /**
   * Address: 0x008F8790 (FUN_008F8790)
   *
   * void const *
   *
   * What it does:
   * Copies one caller viewport payload and binds it as the single native D3D10 viewport.
   */
  void DeviceD3D10::SetViewport(const D3DVIEWPORT9* const viewport)
  {
    D3D10_VIEWPORT viewportCopy{};
    viewportCopy.TopLeftX = static_cast<INT>(viewport->X);
    viewportCopy.TopLeftY = static_cast<INT>(viewport->Y);
    viewportCopy.Width = viewport->Width;
    viewportCopy.Height = viewport->Height;
    viewportCopy.MinDepth = viewport->MinZ;
    viewportCopy.MaxDepth = viewport->MaxZ;
    mDevice->RSSetViewports(1U, &viewportCopy);
  }

  /**
   * Address: 0x008F87F0 (FUN_008F87F0)
   *
   * void *
   *
   * What it does:
   * Fetches one native viewport payload and copies it back into caller memory.
   */
  void DeviceD3D10::GetViewport(D3DVIEWPORT9* const outViewport)
  {
    UINT viewportCount = 1U;
    D3D10_VIEWPORT viewport{};
    mDevice->RSGetViewports(&viewportCount, &viewport);

    outViewport->X = static_cast<DWORD>(viewport.TopLeftX);
    outViewport->Y = static_cast<DWORD>(viewport.TopLeftY);
    outViewport->Width = viewport.Width;
    outViewport->Height = viewport.Height;
    outViewport->MinZ = viewport.MinDepth;
    outViewport->MaxZ = viewport.MaxDepth;
  }

  /**
   * Address: 0x008FCEA0 (FUN_008FCEA0)
   *
   * What it does:
   * Presents each retained swap-chain slot and throws `gpg::gal::Error` on the
   * first failing HRESULT.
   */
  void DeviceD3D10::Present()
  {
    for (IDXGISwapChain* const swapChain : mSwapChains) {
      const HRESULT result = swapChain->Present(0U, 0U);
      if (result < 0) {
        throw Error(MakeShortString("DeviceD3D10.cpp"), 1415, MakeD3DErrorString(result));
      }
    }
  }

  /**
   * Address: 0x008FCF90 (FUN_008FCF90)
   *
   * What it does:
   * Validates the topology, binds the native primitive topology, then dispatches
   * `Draw` vs `DrawInstanced` using the instance count at `this+0xD8`.
   */
  void DeviceD3D10::DrawPrimitive(const DrawContext* const context)
  {
    // D3D10's Draw takes the vertex count as is (`mov edx,[edi+8]` at
    // 0x008FD05D); only the D3D9 backend converts it to primitives.
    if (context->topology_ == 0) {
      ThrowInvalidTopologyError(1561);
    }

    mDevice->IASetPrimitiveTopology(static_cast<D3D10_PRIMITIVE_TOPOLOGY>(ResolvePrimitiveTopology(context->topology_)));

    // Slot 0's frequency is the instance count (0x008FD049 reads this+0xD8).
    const UINT instanceCount = static_cast<UINT>(mStreamFrequencies[0]);
    if (instanceCount > 1U) {
      mDevice->DrawInstanced(context->vertexCount_, instanceCount, context->startVertex_, 0U);
    } else {
      mDevice->Draw(context->vertexCount_, context->startVertex_);
    }

    // FAF instrumentation (see gpg/gal/DrawStatistics.h); not in the binary.
    RecordDraw(context->GetPrimitiveCount(), context->vertexCount_);
  }

  /**
   * Address: 0x008FD0A0 (FUN_008FD0A0)
   *
   * What it does:
   * Validates the topology, binds the native primitive topology, then
   * dispatches `DrawIndexed` vs `DrawIndexedInstanced`.
   */
  void DeviceD3D10::DrawIndexedPrimitive(const DrawIndexedContext* const context)
  {
    // As above: DrawIndexed takes the index count as is (`mov edx,[edi+0x10]`
    // at 0x008FD16E).
    if (context->topology_ == 0) {
      ThrowInvalidTopologyError(1580);
    }

    mDevice->IASetPrimitiveTopology(static_cast<D3D10_PRIMITIVE_TOPOLOGY>(ResolvePrimitiveTopology(context->topology_)));

    // Slot 0's frequency is the instance count (0x008FD159 reads this+0xD8).
    const UINT instanceCount = static_cast<UINT>(mStreamFrequencies[0]);
    if (instanceCount > 1U) {
      mDevice->DrawIndexedInstanced(context->indexCount_, instanceCount, context->startIndex_, 0, 0U);
    } else {
      mDevice->DrawIndexed(context->indexCount_, context->startIndex_, 0);
    }

    // FAF instrumentation (see gpg/gal/DrawStatistics.h); not in the binary.
    RecordDraw(context->GetPrimitiveCount(), context->vertexCount_);
  }

  /**
   * Address: 0x008F94B0 (FUN_008F94B0)
   *
   * OutputContext const *
   *
   * What it does:
   * Copies one output-context snapshot into retained device state, resolves
   * active render/depth view handles, and dispatches native target clear.
   */
  void DeviceD3D10::ClearTarget(const OutputContext* const context)
  {
    Device::ClearTarget(context);

    ID3D10RenderTargetView* renderTargetView = nullptr;
    ID3D10DepthStencilView* depthStencilView = nullptr;

    if (context != nullptr) {
      if (context->surface.get() != nullptr) {
        renderTargetView = static_cast<RenderTargetD3D10*>(context->surface.get())->GetRenderTargetViewOrThrow();
      }

      if (context->depthStencil.get() != nullptr) {
        depthStencilView =
          static_cast<DepthStencilTargetD3D10*>(context->depthStencil.get())->GetDepthStencilViewOrThrow();
      }
    }

    mDevice->OMSetRenderTargets(1U, &renderTargetView, depthStencilView);
  }

  /**
   * Address: 0x008F9510 (FUN_008F9510)
   *
   * bool,bool,bool,uint32_t,float,int
   *
   * What it does:
   * Clears the bound colour view with the unpacked ARGB colour, and the
   * depth-stencil view with the depth/stencil flags that were asked for.
   */
  void DeviceD3D10::Clear(
    const bool clearColor,
    const bool clearDepth,
    const bool clearStencil,
    const std::uint32_t packedColor,
    const float depth,
    const int stencil
  )
  {
    ID3D10RenderTargetView* renderTargetView = nullptr;
    ID3D10DepthStencilView* depthStencilView = nullptr;

    if (outputContext_.surface.get() != nullptr) {
      renderTargetView = static_cast<RenderTargetD3D10*>(outputContext_.surface.get())->GetRenderTargetViewOrThrow();
    }

    if (outputContext_.depthStencil.get() != nullptr) {
      depthStencilView =
        static_cast<DepthStencilTargetD3D10*>(outputContext_.depthStencil.get())->GetDepthStencilViewOrThrow();
    }

    if (clearColor && (renderTargetView != nullptr)) {
      // FAF fix: the shipped body converts each 0-255 channel to float and
      // stops there (`cvtsi2ss` with no scale), so every nonzero channel
      // cleared to 1.0. ClearRenderTargetView takes normalized colours.
      constexpr float kChannelScale = 1.0f / 255.0f;
      float clearColorRgba[4] = {
        static_cast<float>((packedColor >> 16U) & 0xFFU) * kChannelScale,
        static_cast<float>((packedColor >> 8U) & 0xFFU) * kChannelScale,
        static_cast<float>(packedColor & 0xFFU) * kChannelScale,
        static_cast<float>((packedColor >> 24U) & 0xFFU) * kChannelScale,
      };
      mDevice->ClearRenderTargetView(renderTargetView, clearColorRgba);
    }

    int clearMask = 0;
    if (clearDepth) {
      clearMask |= 1;
    }
    if (clearStencil) {
      clearMask |= 2;
    }

    if ((clearMask != 0) && (depthStencilView != nullptr)) {
      mDevice->ClearDepthStencilView(
        depthStencilView, static_cast<UINT>(clearMask), depth, static_cast<UINT8>(stencil)
      );
    }
  }

  /**
   * Address: 0x008FE6D0 (FUN_008FE6D0)
   *
   * What it does:
   * Preserves the binary no-op fog-state lane.
   */
  void DeviceD3D10::SetFogState(
    const bool /*enable*/,
    const Matrix* const /*projection*/,
    const float /*fogStart*/,
    const float /*fogEnd*/,
    const int /*fogColor*/
  )
  {
  }

  /**
   * Address: 0x008FE6E0 (FUN_008FE6E0)
   *
   * What it does:
   * The shipped body is empty. FAF addition: records the toggle; every effect
   * pass applied afterwards draws wireframe unless it sets its own fill mode
   * (`ApplyStateOverrides`).
   */
  void DeviceD3D10::SetWireframeState(const bool enabled)
  {
    sWireframe = enabled;
  }

  /**
   * Address: 0x008FE6F0 (FUN_008FE6F0)
   *
   * What it does:
   * The shipped body is empty. FAF addition: records the mask the D3D9 backend
   * would use; every effect pass applied afterwards writes only those
   * channels unless it restricts its own (`ApplyStateOverrides`).
   */
  void DeviceD3D10::SetColorWriteState(const bool writeColor, const bool writeAlpha)
  {
    sColorWriteMask = ColorWriteMask(writeColor, writeAlpha);
  }

  /**
   * Address: 0x008F95F0 (FUN_008F95F0)
   *
   * What it does:
   * Clears shader-resource bindings for 128 texture slots on the retained
   * technique-state native device lane.
   */
  void DeviceD3D10::ClearTextures()
  {
    mPipelineState->ClearTextures();
  }

  /**
   * Address: 0x008F9600 (FUN_008F9600)
   *
   * What it does:
   * Binds `vertexFormat`'s input layout (through
   * `VertexFormatD3D10::ValidateLayoutOrThrow`, 0x008F962B).
   */
  void DeviceD3D10::SetVertexDeclaration(const boost::shared_ptr<VertexFormat> vertexFormat)
  {
    mDevice->IASetInputLayout(static_cast<VertexFormatD3D10*>(vertexFormat.get())->ValidateLayoutOrThrow());
  }

  /**
   * Address: 0x008F9690 (FUN_008F9690)
   *
   * What it does:
   * Binds `vertexBuffer` on input slot `streamSlot`, starting `startVertex`
   * vertices in, and records `streamFrequencyToken` for the slot. D3D10 has
   * no stream frequency of its own: the draws read slot 0's value back as the
   * instance count.
   */
  void DeviceD3D10::SetVertexBuffer(
    const std::uint32_t streamSlot,
    const boost::shared_ptr<VertexBuffer> vertexBuffer,
    const int streamFrequencyToken,
    const int startVertex
  )
  {
    const VertexBufferContext* const context = vertexBuffer->GetContext();
    ID3D10Buffer* const nativeVertexBuffer = static_cast<VertexBufferD3D10*>(vertexBuffer.get())->GetNativeBufferOrThrow();
    const UINT stride = context->stride_;
    const UINT offset = static_cast<UINT>(startVertex * static_cast<int>(stride));
    mDevice->IASetVertexBuffers(streamSlot, 1U, &nativeVertexBuffer, &stride, &offset);

    mStreamFrequencies[streamSlot] = streamFrequencyToken;
  }

  /**
   * Address: 0x008F9760 (FUN_008F9760)
   *
   * What it does:
   * Binds `indexBuffer` as the index source at offset 0, 32-bit for index
   * format 2 and 16-bit otherwise.
   */
  void DeviceD3D10::SetBufferIndices(const boost::shared_ptr<IndexBuffer> indexBuffer)
  {
    const IndexBufferContext* const context = indexBuffer->GetContext();
    const DXGI_FORMAT indexFormat = (context->format_ == 2U) ? DXGI_FORMAT_R32_UINT : DXGI_FORMAT_R16_UINT;
    ID3D10Buffer* const nativeIndexBuffer = static_cast<IndexBufferD3D10*>(indexBuffer.get())->GetNativeBufferOrThrow();
    mDevice->IASetIndexBuffer(nativeIndexBuffer, indexFormat, 0U);
  }

  /**
   * Address: 0x008F9810 (FUN_008F9810)
   *
   * What it does:
   * `mov ecx, [ecx+0xB4]; jmp`: the pipeline state's `BeginTechnique`.
   */
  void DeviceD3D10::BeginTechnique()
  {
    mPipelineState->BeginTechnique();
  }

  /**
   * Address: 0x008F9820 (FUN_008F9820)
   *
   * What it does:
   * `mov ecx, [ecx+0xB4]; jmp`: the pipeline state's (empty) `EndTechnique`.
   */
  void DeviceD3D10::EndTechnique()
  {
    mPipelineState->EndTechnique();
  }
}

