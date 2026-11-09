#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{
namespace
{

        constexpr std::uint32_t kVertexShaderModel20 = 0xFFFE0200U;
        constexpr std::uint32_t kVertexShaderModel30 = 0xFFFE0300U;
        constexpr std::uint32_t kPixelShaderModel20 = 0xFFFF0200U;
        constexpr std::uint32_t kDeclTypeFloat16_2 = 0x100U;
        constexpr std::uint32_t kDeclTypeFloat16_4 = 0x200U;
        constexpr std::uint32_t kVendorIdNvidia = 4318U;
        constexpr std::uint32_t kVendorIdAti = 32902U;
        constexpr std::uint32_t kAtiDeviceRadeonX800 = 10626U;
        constexpr std::uint32_t kAtiDeviceRadeonX850 = 10658U;
        constexpr std::uint32_t kAtiDeviceRadeonX1650 = 10754U;
        // ATI's instancing switch: a surface format check for FOURCC 'INST'.
        constexpr D3DFORMAT kInstancingFourCC = static_cast<D3DFORMAT>(MAKEFOURCC('I', 'N', 'S', 'T'));
        // Address: 0x00D421CC - indexed by `DrawContext::TOPOLOGY` with no
        // bounds check (zero is rejected before the lookup).
        constexpr D3DPRIMITIVETYPE kTopologyPrimitiveTypes[6] = {
            D3DPT_POINTLIST,
            D3DPT_POINTLIST,
            D3DPT_LINELIST,
            D3DPT_LINESTRIP,
            D3DPT_TRIANGLELIST,
            D3DPT_TRIANGLESTRIP,
        };

        fa::vector<fa::string> gD3D9LogStorage{};

        std::uint32_t GetDeviceContextHeadCount(const DeviceContext* const context) noexcept
        {
            if (context == nullptr)
            {
                return 0U;
            }

            return static_cast<std::uint32_t>(context->GetHeadCount());
        }

        std::uint32_t GetDeviceHeadCount(const DeviceD3D9* const device) noexcept
        {
            return GetDeviceContextHeadCount(&device->mDeviceContext);
        }

        OutputContext* GetDeviceHeadArrayBase(const DeviceD3D9* const device) noexcept
        {
            return device->mHeads;
        }

        std::uint32_t GetD3DFormat(std::uint32_t formatToken);
        std::uint32_t FormatToD3DFormat(std::uint32_t formatToken);
        std::uint32_t FormatGalToD3D(std::uint32_t mohoFormat);

        // Address: 0x00D421E4 - the gal image file format, as the D3DX one. Both
        // save paths index it directly (0x008EC78E, 0x008ECAAF).
        constexpr D3DXIMAGE_FILEFORMAT kD3DXImageFileFormats[5] = {
            D3DXIFF_BMP,
            D3DXIFF_JPG,
            D3DXIFF_TGA,
            D3DXIFF_PNG,
            D3DXIFF_DDS,
        };

        unsigned int AlignToDword(const unsigned int value) noexcept
        {
            return (value + 3U) & ~3U;
        }

        int ResolveVertexShaderProfileToken(const char* const profileName) noexcept
        {
            static constexpr const char* kVertexProfiles[] = {
                "undefined",
                "vs_1_1",
                "vs_2_0",
                "vs_2_a",
                "vs_3_0",
            };

            if (profileName == nullptr)
            {
                return 2;
            }

            for (int index = 0; index < static_cast<int>(sizeof(kVertexProfiles) / sizeof(kVertexProfiles[0])); ++index)
            {
                if (std::strcmp(profileName, kVertexProfiles[index]) == 0)
                {
                    return index;
                }
            }

            return 2;
        }

        int ResolvePixelShaderProfileToken(const char* const profileName) noexcept
        {
            static constexpr const char* kPixelProfiles[] = {
                "undefined",
                "ps_1_1",
                "ps_1_2",
                "ps_1_3",
                "ps_1_4",
                "ps_2_0",
                "ps_2_a",
                "ps_2_b",
                "ps_3_0",
            };

            if (profileName == nullptr)
            {
                return 5;
            }

            for (int index = 0; index < static_cast<int>(sizeof(kPixelProfiles) / sizeof(kPixelProfiles[0])); ++index)
            {
                if (std::strcmp(profileName, kPixelProfiles[index]) == 0)
                {
                    return index;
                }
            }

            return 5;
        }

        /**
         * Address: 0x008F1480 (FUN_008F1480, func_CheckAdapters)
         *
         * What it does:
         * Validates setup adapter selection against the requested device-context
         * head configuration.
         */
        void CheckAdapterSelectionForSetup(DeviceD3D9& device, const DeviceContext& context)
        {
            device.Func1();

            const unsigned int headCount = static_cast<unsigned int>(context.GetHeadCount());
            const unsigned int adapterCount = static_cast<unsigned int>(device.mAdapters.size());

            if (headCount > adapterCount)
            {
                ThrowGalError("DeviceD3D9.cpp", 1229, "invalid head count");
            }

            if ((headCount > 1U) && (context.mAdapter != 0U))
            {
                ThrowGalError("DeviceD3D9.cpp", 1235, "invalid primary adapter index");
            }
        }

        void AppendD3D9SetupLogMessage(const char* const message)
        {
            gD3D9LogStorage.push_back(MakeShortString(message));
        }

        /**
         * Address: 0x008F1CB0 (FUN_008F1CB0, func_CollectAllAdapters)
         *
         * What it does:
         * Enumerates all Direct3D adapters, captures identity/mode lists, and
         * appends them to the backend adapter storage.
         */
        void CollectAllAdaptersForSetup(DeviceD3D9& device)
        {
            device.Func1();

            const unsigned int adapterCount = device.mDirect3D->GetAdapterCount();
            for (unsigned int adapterIndex = 0; adapterIndex < adapterCount; ++adapterIndex)
            {
                D3DADAPTER_IDENTIFIER9 adapterIdentifier{};
                const HRESULT identifierResult =
                    device.mDirect3D->GetAdapterIdentifier(adapterIndex, 0U, &adapterIdentifier);
                if (identifierResult < 0)
                {
                    AppendD3D9SetupLogMessage("unable to enumerate adapters");
                    ThrowGalError("DeviceD3D9.cpp", 1199, "unable to enumerate adapters");
                }

                const fa::string description(
                    adapterIdentifier.Description,
                    std::strlen(adapterIdentifier.Description)
                );
                const fa::string deviceName(adapterIdentifier.DeviceName, std::strlen(adapterIdentifier.DeviceName));
                const fa::string driver(adapterIdentifier.Driver, std::strlen(adapterIdentifier.Driver));

                AdapterD3D9 adapter(
                    adapterIdentifier.VendorId,
                    adapterIdentifier.DeviceId,
                    driver,
                    deviceName,
                    description
                );

                const unsigned int modeCount =
                    device.mDirect3D->GetAdapterModeCount(adapterIndex, D3DFMT_X8R8G8B8);
                for (unsigned int modeIndex = 0; modeIndex < modeCount; ++modeIndex)
                {
                    D3DDISPLAYMODE displayMode{};
                    const HRESULT modeResult = device.mDirect3D->EnumAdapterModes(adapterIndex, D3DFMT_X8R8G8B8, modeIndex, &displayMode);
                    if (modeResult < 0)
                    {
                        AppendD3D9SetupLogMessage("unable to enumerate adapters");
                        ThrowGalError("DeviceD3D9.cpp", 1212, "unable to enumerate adapters");
                    }

                    adapter.AddMode(AdapterModeD3D9(displayMode.Width, displayMode.Height, displayMode.RefreshRate));
                }

                device.mAdapters.push_back(adapter);
            }
        }

        [[nodiscard]] bool IsLegacyAtiCreateDeviceFallbackAdapter(const AdapterD3D9& adapter) noexcept
        {
            if (adapter.vendorId != kVendorIdAti)
            {
                return false;
            }

            return (adapter.deviceId == kAtiDeviceRadeonX800) ||
                   (adapter.deviceId == kAtiDeviceRadeonX850) ||
                   (adapter.deviceId == kAtiDeviceRadeonX1650);
        }

        [[nodiscard]] bool HeadSupportsCapability2(const Head& head, const int capabilityToken) noexcept
        {
            for (const int token : head.validFormats2)
            {
                if (token == capabilityToken)
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * Address: 0x008F1600 (FUN_008F1600, gpg::gal::DeviceD3D9::CheckHardwareBasedInstancing)
         *
         * IDA signature:
         * void __thiscall CheckHardwareBasedInstancing(gpg::gal::DeviceD3D9 *this, D3DCAPS9 *caps);
         *
         * What it does:
         * Dispatches the virtual Func1() pre-hook, then probes D3D9 hardware
         * instancing support: for pre-SM3.0 devices it checks the INST FourCC
         * surface format and the POINTSIZE render-state trick, with an ATI/Intel
         * deviceId fallback whitelist (X800/X850/X1650). Clears mHWBasedInstancing
         * when unsupported.
         */
        void CheckHardwareInstancingSupport(DeviceD3D9& device, const D3DCAPS9& caps)
        {
            DeviceContext& context = device.mDeviceContext;

            device.Func1();
            context.mHWBasedInstancing = true;
            if (caps.VertexShaderVersion < kVertexShaderModel30)
            {
                const HRESULT instancingFormatResult = device.mDirect3D->CheckDeviceFormat(static_cast<unsigned int>(context.mAdapter), D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0U, D3DRTYPE_SURFACE, kInstancingFourCC);

                if (instancingFormatResult >= 0)
                {
                    const HRESULT pointSizeResult =
                        device.mDevice->SetRenderState(D3DRS_POINTSIZE, kInstancingFourCC);
                    if (pointSizeResult < 0)
                    {
                        context.mHWBasedInstancing = false;
                    }
                }
                else
                {
                    bool supportedAdapterFallback = false;
                    const auto adapterIndex = static_cast<std::size_t>(context.mAdapter);
                    if (adapterIndex < device.mAdapters.size())
                    {
                        const AdapterD3D9& adapter = device.mAdapters[adapterIndex];
                        supportedAdapterFallback =
                            (adapter.vendorId == kVendorIdAti) &&
                            ((adapter.deviceId == kAtiDeviceRadeonX800) || (adapter.deviceId == kAtiDeviceRadeonX850) ||
                             (adapter.deviceId == kAtiDeviceRadeonX1650));
                    }

                    if (!supportedAdapterFallback)
                    {
                        context.mHWBasedInstancing = false;
                    }
                }
            }

            if (context.mValidate && !context.mHWBasedInstancing)
            {
                ThrowGalError("DeviceD3D9.cpp", 1434, "device does not support hardware based instancing");
            }
        }

        struct D3D9FormatToMohoPair final
        {
            std::uint32_t d3dFormat = 0U;
            std::uint32_t mohoFormat = 0U;
        };

        // Address: 0x00D47FF0 (DAT_00D47FF0)
        constexpr D3D9FormatToMohoPair kD3D9FormatToMohoPairs[60] = {
            {0x00000000U, 0x00000014U},
            {0x00000014U, 0x00000001U},
            {0x00000015U, 0x00000002U},
            {0x00000016U, 0x00000003U},
            {0x00000017U, 0x00000004U},
            {0x00000018U, 0x00000014U},
            {0x00000019U, 0x00000014U},
            {0x0000001AU, 0x00000014U},
            {0x0000001BU, 0x00000014U},
            {0x0000001CU, 0x00000005U},
            {0x0000001DU, 0x00000014U},
            {0x0000001EU, 0x00000014U},
            {0x0000001FU, 0x00000014U},
            {0x00000020U, 0x00000014U},
            {0x00000021U, 0x00000014U},
            {0x00000022U, 0x00000014U},
            {0x00000023U, 0x00000014U},
            {0x00000024U, 0x00000014U},
            {0x00000028U, 0x00000014U},
            {0x00000029U, 0x00000014U},
            {0x00000032U, 0x00000006U},
            {0x00000033U, 0x00000007U},
            {0x00000034U, 0x00000014U},
            {0x0000003CU, 0x00000014U},
            {0x0000003DU, 0x00000014U},
            {0x0000003EU, 0x00000014U},
            {0x0000003FU, 0x00000014U},
            {0x00000040U, 0x00000014U},
            {0x00000043U, 0x00000014U},
            {0x59565955U, 0x00000014U},
            {0x47424752U, 0x00000014U},
            {0x32595559U, 0x00000014U},
            {0x42475247U, 0x00000014U},
            {0x31545844U, 0x00000008U},
            {0x32545844U, 0x00000009U},
            {0x33545844U, 0x0000000AU},
            {0x34545844U, 0x0000000BU},
            {0x35545844U, 0x0000000CU},
            {0x00000046U, 0x00000014U},
            {0x00000047U, 0x00000014U},
            {0x00000049U, 0x00000014U},
            {0x0000004BU, 0x00000014U},
            {0x0000004DU, 0x00000014U},
            {0x0000004FU, 0x00000014U},
            {0x00000050U, 0x00000014U},
            {0x00000052U, 0x00000014U},
            {0x00000053U, 0x00000014U},
            {0x00000051U, 0x00000014U},
            {0x00000064U, 0x00000014U},
            {0x00000065U, 0x00000014U},
            {0x00000066U, 0x00000014U},
            {0x0000006EU, 0x00000014U},
            {0x3154454DU, 0x00000014U},
            {0x0000006FU, 0x0000000DU},
            {0x00000070U, 0x0000000EU},
            {0x00000071U, 0x0000000FU},
            {0x00000072U, 0x00000010U},
            {0x00000073U, 0x00000011U},
            {0x00000074U, 0x00000012U},
            {0x00000075U, 0x00000014U},
        };

        // Address: 0x00D42E84 (`gpg::gal::sGalFormatToD3D`)
        // Address: 0x00D47C8C (`dword_D47C8C`) -- identical cube-target format map.
        constexpr std::uint32_t kGalFormatToD3D[9] = {
            0x00000000U,
            0x00000023U,
            0x00000015U,
            0x00000016U,
            0x00000019U,
            0x00000018U,
            0x00000017U,
            0x00000022U,
            0x00000000U,
        };

        // Address: 0x00D42194 (`gpg::gal::D3DFormats`)
        constexpr std::uint32_t kDepthStencilFormatToD3D[8] = {
            0x00000000U,
            0x00000047U,
            0x00000049U,
            0x0000004BU,
            0x0000004DU,
            0x0000004FU,
            0x00000050U,
            0x00000000U,
        };

        /**
         * Address: 0x008F52F0 (FUN_008F52F0)
         *
         * int
         *
         * What it does:
         * Maps gal texture-format token to D3D9 format via `sGalFormatToD3D`.
         */
        std::uint32_t GetD3DFormat(const std::uint32_t formatToken)
        {
            return (formatToken < static_cast<std::uint32_t>(sizeof(kGalFormatToD3D) / sizeof(kGalFormatToD3D[0])))
                     ? kGalFormatToD3D[formatToken]
                     : 0U;
        }

        /**
         * Address: 0x008E7F50 (FUN_008E7F50)
         *
         * int
         *
         * What it does:
         * Maps depth-stencil format token to D3D9 depth format via `D3DFormats`.
         */
        std::uint32_t FormatToD3DFormat(const std::uint32_t formatToken)
        {
            return (formatToken <
                    static_cast<std::uint32_t>(sizeof(kDepthStencilFormatToD3D) / sizeof(kDepthStencilFormatToD3D[0])))
                     ? kDepthStencilFormatToD3D[formatToken]
                     : 0U;
        }

        /**
         * Address: 0x0094A0D0 (FUN_0094A0D0)
         *
         * What it does:
         * Converts a D3D9 format token to the legacy Moho format enum via the
         * static pair table at `DAT_00D47FF0`.
         */
        std::uint32_t FormatD3D9ToMoho(const std::uint32_t d3dFormat)
        {
            for (const D3D9FormatToMohoPair& pair : kD3D9FormatToMohoPairs)
            {
                if (pair.d3dFormat == d3dFormat)
                {
                    return pair.mohoFormat;
                }
            }

            return 0x14U;
        }

        /**
         * Address: 0x0094A100 (FUN_0094A100)
         *
         * What it does:
         * Converts a legacy Moho format token back to its paired D3D9 format value.
         */
        std::uint32_t FormatGalToD3D(const std::uint32_t mohoFormat)
        {
            for (const D3D9FormatToMohoPair& pair : kD3D9FormatToMohoPairs)
            {
                if (pair.mohoFormat == mohoFormat)
                {
                    return pair.d3dFormat;
                }
            }

            return 0U;
        }

        [[nodiscard]] fa::string ReadD3DXErrorText(ID3DXBuffer* const errors)
        {
            const char* const errorText =
                (errors != nullptr) ? static_cast<const char*>(errors->GetBufferPointer()) : "unknown error";

            fa::string reason{};
            reason.assign_owned(errorText);
            return reason;
        }

        [[nodiscard]]
        fa::string BuildEffectCreationMessage(
            const char* const prefix,
            const EffectContext& context,
            const fa::string& reason
        )
        {
            fa::string message(prefix != nullptr ? prefix : "");
            message = message + context.mSourcePath;
            message = message + " reason: ";
            message = message + reason;
            return message;
        }

        /**
         * The context's macros as the NUL-terminated `D3DXMACRO` array D3DX
         * takes, or null when there are none. `CreateEffectFromSourceBuffer`
         * (0x008F0A81) allocates it with `new[]` and never frees it; the
         * array points into the context's strings.
         */
        [[nodiscard]] D3DXMACRO* BuildD3DXMacroDefines(const fa::vector<EffectMacro>& macros)
        {
            const std::size_t macroCount = macros.size();
            if (macroCount == 0U)
            {
                return nullptr;
            }

            D3DXMACRO* const defines = new D3DXMACRO[macroCount + 1U];
            std::size_t index = 0U;
            for (const EffectMacro& macro : macros)
            {
                defines[index].Name = macro.keyText_.c_str();
                defines[index].Definition = macro.valueText_.c_str();
                ++index;
            }

            defines[index].Name = nullptr;
            defines[index].Definition = nullptr;
            return defines;
        }

        /**
         * FAF addition, not in the shipped binary: whether `macros` defines
         * `name`.
         */
        [[nodiscard]] bool DefinesMacro(const fa::vector<EffectMacro>& macros, const char* const name)
        {
            for (const EffectMacro& macro : macros)
            {
                if (std::strcmp(macro.keyText_.c_str(), name) == 0)
                {
                    return true;
                }
            }
            return false;
        }

        /**
         * Address: 0x008F04A0 (FUN_008F04A0)
         *
         * What it does:
         * Writes one raw byte lane into a target output stream and applies
         * `badbit` when sentry/buffer writes fail.
         */
        std::ostream& WriteRawByteLaneToStream(
            std::ostream& stream,
            const void* const data,
            const std::size_t byteCount
        )
        {
            std::ostream::sentry sentry(stream);
            std::ios_base::iostate ioState = std::ios_base::goodbit;
            if (sentry)
            {
                std::streambuf* const outputBuffer = stream.rdbuf();
                const std::streamsize writeCount = static_cast<std::streamsize>(byteCount);
                if (outputBuffer == nullptr ||
                    outputBuffer->sputn(static_cast<const char*>(data), writeCount) != writeCount)
                {
                    ioState |= std::ios_base::badbit;
                }
            }
            else
            {
                ioState |= std::ios_base::badbit;
            }

            if (ioState != std::ios_base::goodbit)
            {
                stream.setstate(ioState);
            }
            return stream;
        }

        /**
         * Address: 0x008E8F70 (FUN_008E8F70)
         *
         * What it does:
         * Returns the current input-stream position using
         * `streambuf::pubseekoff(0, cur, in)` when stream state is valid, or
         * `-1` when fail/bad flags are set.
         */
        std::streampos QueryCurrentInputPosition(
            std::istream& inputStream
        ) noexcept
        {
            if ((inputStream.rdstate() & (std::ios::failbit | std::ios::badbit)) != 0) {
                return std::streampos(-1);
            }

            std::streambuf* const streamBuffer = inputStream.rdbuf();
            if (streamBuffer == nullptr) {
                return std::streampos(-1);
            }

            return streamBuffer->pubseekoff(0, std::ios_base::cur, std::ios_base::in);
        }
}


    /**
     * Address: 0x008EFD50 (FUN_008EFD50)
     *
     * What it does:
     * Builds an empty device: every member has its initializer, so the body
     * is empty (the stores at 0x008EFD84..0x008EFDB5 are those
     * initializers, `DeviceContext(DeviceApi::Unset)` included). `Device::Create` then
     * runs `Setup`.
     */
    DeviceD3D9::DeviceD3D9() = default;

    /**
     * Address: 0x008F3270 (FUN_008F3270)
     * Address: 0x008F37F0 (FUN_008F37F0, slot 0: the scalar deleting destructor)
     *
     * What it does:
     * Runs `Shutdown`, then the member destructors (pipeline state, device
     * context, adapter vector) and the `Device` base destructor.
     */
    DeviceD3D9::~DeviceD3D9()
    {
        Shutdown();
    }

    /**
     * Address: 0x008E81D0 (FUN_008E81D0)
     *
     * What it does:
     * Returns the global D3D9 log-storage lane used by this backend.
     */
    void* DeviceD3D9::GetLog()
    {
        return &gD3D9LogStorage;
    }

    /**
     * Address: 0x008E81E0 (FUN_008E81E0)
     *
     * What it does:
     * Runs the `Func1` pre-hook and returns the embedded device context.
     */
    DeviceContext* DeviceD3D9::GetDeviceContext()
    {
        Func1();
        return &mDeviceContext;
    }

    /**
     * Address: 0x008E81F0 (FUN_008E81F0)
     *
     * What it does:
     * Returns the retained current thread-id lane at `this+0x24`.
     */
    int DeviceD3D9::GetCurThreadId()
    {
        return mCurThreadId;
    }

    /**
     * Address: 0x008E8200 (FUN_008E8200)
     *
     * What it does:
     * Preserves the binary no-op virtual pre-hook slot.
     */
    void DeviceD3D9::Func1() const
    {
    }

    /**
     * Address: 0x008F0170 (FUN_008F0170)
     *
     * What it does:
     * Replaces `outModes` with the display modes of adapter `adapterIndex` as
     * `{width, height, refresh}` triples - the options screen's resolution list
     * (`SetupPrimaryAdapterSettings` asks for adapter 0 at 0x008D22F7, the
     * secondary for adapter 1 at 0x008D2807). An index past the adapter list
     * leaves it empty. The recovered body pushed 16-byte `AdapterModeD3D9`s into
     * a vector the caller walks at a 12-byte stride.
     */
    void DeviceD3D9::GetModesForAdapter(fa::vector<HeadAdapterMode>& outModes, const int adapterIndex)
    {
        outModes.clear();
        if (adapterIndex >= static_cast<int>(mAdapters.size()))
        {
            return;
        }

        for (const AdapterModeD3D9& mode : mAdapters[static_cast<std::size_t>(adapterIndex)].modes)
        {
            const HeadAdapterMode headMode{mode.width_, mode.height_, mode.refreshRate_};
            outModes.push_back(headMode);
        }
    }

    /**
     * Address: 0x008E9B00 (FUN_008E9B00)
     *
     * What it does:
     * Runs the `Func1` pre-hook and returns a new reference to the device's
     * pipeline state.
     */
    boost::shared_ptr<PipelineState> DeviceD3D9::GetPipelineState()
    {
        Func1();
        return mPipelineState;
    }

    /**
     * Address: 0x008F09A0 (FUN_008F09A0)
     *
     * What it does:
     * Compiles one effect from source-memory + macro lanes, builds a D3D9
     * effect object, installs the active pipeline state-manager, and emits
     * the compiled bytecode to cache-path when the file can be opened.
     */
    boost::shared_ptr<Effect> DeviceD3D9::CreateEffectFromSourceBuffer(const EffectContext& context)
    {
        if (context.mSourceType != 2U)
        {
            ThrowGalError("DeviceD3D9.cpp", 1514, "");
        }

        const D3DXMACRO* const defines = BuildD3DXMacroDefines(context.mMacros);

        // FAF: the FAF_BONE_TEXTURE variant of mesh.fx is shader model 3
        // throughout, and for ps_3_0 the legacy compiler weighs dynamic
        // branches: 44 seconds for mesh.fx against 4 for its 2.0 build, paid
        // at every launch because FAF's init empties the shader cache. Asking
        // it to avoid flow control brings that back to 4 seconds and keeps the
        // shaders flattened like their 2.0 builds.
        const DWORD flowControlFlags =
            DefinesMacro(context.mMacros, "FAF_BONE_TEXTURE") ? D3DXSHADER_AVOID_FLOW_CONTROL : 0U;

        ID3DXEffectCompiler* effectCompiler = nullptr;
        ID3DXBuffer* compiledEffect = nullptr;
        ID3DXEffect* effect = nullptr;
        ID3DXBuffer* errors = nullptr;
        try
        {
            const char* const sourceData = context.mSourceBuffer.mBegin;
            const unsigned int sourceBytes =
                static_cast<unsigned int>(context.mSourceBuffer.mEnd - context.mSourceBuffer.mBegin);

            HRESULT result = D3DXCreateEffectCompiler(
                sourceData, sourceBytes, defines, nullptr,
                D3DXSHADER_DEBUG | D3DXSHADER_USE_LEGACY_D3DX9_31_DLL | flowControlFlags, &effectCompiler, &errors
            );
            if (FAILED(result))
            {
                const fa::string message =
                    BuildEffectCreationMessage("unable to compile effect: ", context, ReadD3DXErrorText(errors));
                ThrowGalError("DeviceD3D9.cpp", 1549, message.c_str());
            }
            SafeRelease(errors);

            result = effectCompiler->CompileEffect(D3DXSHADER_DEBUG | flowControlFlags, &compiledEffect, &errors);
            if (FAILED(result))
            {
                const fa::string message =
                    BuildEffectCreationMessage("unable to compile effect: ", context, ReadD3DXErrorText(errors));
                ThrowGalError("DeviceD3D9.cpp", 1557, message.c_str());
            }
            SafeRelease(errors);
            SafeRelease(effectCompiler);

            result = D3DXCreateEffect(
                mDevice, compiledEffect->GetBufferPointer(), compiledEffect->GetBufferSize(), defines,
                nullptr, D3DXSHADER_DEBUG, nullptr, &effect, &errors
            );
            if (FAILED(result))
            {
                const fa::string message =
                    BuildEffectCreationMessage("unable to create effect: ", context, ReadD3DXErrorText(errors));
                ThrowGalError("DeviceD3D9.cpp", 1575, message.c_str());
            }
            SafeRelease(errors);

            result = effect->SetStateManager(mPipelineState->GetStateManager());
            if (FAILED(result))
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1580, result);
            }

            std::ofstream compiledCache(context.mCachePath.c_str(), std::ios::binary);
            if (compiledCache.is_open())
            {
                WriteRawByteLaneToStream(
                    compiledCache,
                    compiledEffect->GetBufferPointer(),
                    static_cast<std::size_t>(compiledEffect->GetBufferSize())
                );
                compiledCache.close();
            }
            SafeRelease(compiledEffect);
        }
        catch (...)
        {
            SafeRelease(effectCompiler);
            SafeRelease(compiledEffect);
            SafeRelease(effect);
            SafeRelease(errors);
            throw;
        }

        return boost::shared_ptr<Effect>(new EffectD3D9(context, effect));
    }

    /**
     * Address: 0x008F0F90 (FUN_008F0F90)
     *
     * What it does:
     * Loads one cached compiled-effect payload from `cachePath`, creates the
     * native D3D9 effect, and installs the active pipeline state-manager.
     */
    boost::shared_ptr<Effect> DeviceD3D9::CreateEffectFromCachedBinary(const EffectContext& context)
    {
        if (context.mSourceType != 2U)
        {
            ThrowGalError("DeviceD3D9.cpp", 1609, "");
        }

        std::ifstream compiledCache(context.mCachePath.c_str(), std::ios::binary);
        if (!compiledCache.is_open())
        {
            ThrowGalError("DeviceD3D9.cpp", 1612, "");
        }

        ID3DXBuffer* errors = nullptr;
        ID3DXEffect* effect = nullptr;
        char* compiledBytes = nullptr;
        try
        {
            compiledCache.seekg(0, std::ios::end);
            const std::size_t compiledSize = static_cast<std::size_t>(QueryCurrentInputPosition(compiledCache));
            compiledCache.seekg(0, std::ios::beg);

            compiledBytes = new char[compiledSize];
            // Address: 0x008F0230 (FUN_008F0230) -- std::basic_istream<char>::read(),
            // a genuine CRT/STL <istream> body (sentry guard, virtual
            // streambuf::_Sgetn_s dispatch, std::ios_base::clear on short read,
            // std::_Mutex::_Unlock) with zero engine-specific behavior. Not a
            // recovery target; this call is its real, already-wired invocation.
            compiledCache.read(compiledBytes, static_cast<std::streamsize>(compiledSize));

            HRESULT result = D3DXCreateEffect(
                mDevice, compiledBytes, static_cast<UINT>(compiledSize), nullptr, nullptr, 0U, nullptr,
                &effect, &errors
            );
            if (FAILED(result))
            {
                const fa::string message =
                    BuildEffectCreationMessage("unable to create effect: ", context, ReadD3DXErrorText(errors));
                ThrowGalError("DeviceD3D9.cpp", 1640, message.c_str());
            }
            SafeRelease(errors);
            // The binary leaves the pointer dangling here, so a failing
            // SetStateManager below deletes the bytes a second time in the
            // handler. Clearing it keeps that path defined.
            delete[] compiledBytes;
            compiledBytes = nullptr;

            result = effect->SetStateManager(mPipelineState->GetStateManager());
            if (FAILED(result))
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1646, result);
            }
        }
        catch (...)
        {
            SafeRelease(errors);
            SafeRelease(effect);
            delete[] compiledBytes;
            throw;
        }

        return boost::shared_ptr<Effect>(new EffectD3D9(context, effect));
    }

    /**
     * Address: 0x008F13D0 (FUN_008F13D0)
     * Slot: 9
     *
     * What it does:
     * Runs the `Func1` pre-hook, then builds the effect from the compiled
     * cache when the context asks for it and from source otherwise. Both
     * builders construct straight into this call's return slot.
     */
    boost::shared_ptr<Effect> DeviceD3D9::CreateEffect(const EffectContext& context)
    {
        Func1();
        if (context.mUseCache)
        {
            return CreateEffectFromCachedBinary(context);
        }

        return CreateEffectFromSourceBuffer(context);
    }

    /**
     * Address: 0x008F3320 (FUN_008F3320)
     *
     * What it does:
     * Brings the device up for `context`: shuts down whatever was there,
     * creates Direct3D and the device (falling back for three old ATI parts),
     * enumerates adapters, builds the capabilities, the heads, the pipeline
     * state and the frame event query. `Device::Create` calls it right after
     * constructing the device (0x008E6CD8).
     */
    /**
     * Address: 0x008F2F70 (FUN_008F2F70)
     *
     * What it does:
     * Releases everything `Setup` built: the head output contexts, the
     * pipeline state, the frame query, the device and Direct3D, and puts the
     * device context back to an empty one. The destructor and `Setup` both
     * start with it.
     */
    void DeviceD3D9::Shutdown()
    {
        DeleteOutputContexts(mHeads, GetDeviceHeadCount(this));
        mHeads = nullptr;

        mPipelineState.reset();

        SafeRelease(mFrameEventQuery);
        SafeRelease(mDevice);
        SafeRelease(mDirect3D);

        mDeviceContext = DeviceContext(DeviceApi::Unset);
    }

    void DeviceD3D9::Setup(const DeviceContext* const context)
    {
        Shutdown();

        const int headCount = context->GetHeadCount();
        if (headCount == 0)
        {
            ThrowGalError("DeviceD3D9.cpp", 122, "invalid device context specified");
        }

        // Freed on both ways out; a failure also takes down whatever was
        // brought up (the catch at 0x008F37CC).
        D3DPRESENT_PARAMETERS* const presentParameters = new D3DPRESENT_PARAMETERS[static_cast<std::size_t>(headCount)];
        try
        {
            mCurThreadId = static_cast<int>(::GetCurrentThreadId());

            // Engine change (issue #317): d3dx9_43.dll is delay-loaded (src/CMakeLists.txt), and this
            // renderer is the only caller. Without it the renderer can't start: say so here rather
            // than fail on the first D3DX call.
            if (::LoadLibraryW(L"d3dx9_43.dll") == nullptr)
            {
                AppendD3D9SetupLogMessage("d3dx9_43.dll is missing (DirectX End-User Runtime)");
                ThrowGalError("DeviceD3D9.cpp", 131, "d3dx9_43.dll is missing (DirectX End-User Runtime)");
            }

            mDirect3D = Direct3DCreate9(0x20U);
            if (mDirect3D == nullptr)
            {
                AppendD3D9SetupLogMessage("unable to create Direct3D");
                ThrowGalError("DeviceD3D9.cpp", 132, "unable to create Direct3D");
            }

            CollectAllAdaptersForSetup(*this);
            CheckAdapterSelectionForSetup(*this, *context);

            const HWND primaryWindow = reinterpret_cast<HWND>(context->GetHead(0U).mHandle);
            const unsigned int behaviorFlags = ((headCount > 1) ? 0x200U : 0U) | 0x44U;
            GetDeviceParameters(presentParameters, context);

            unsigned int selectedAdapter = static_cast<unsigned int>(context->mAdapter);
            D3DDEVTYPE deviceType = D3DDEVTYPE_HAL;
            const std::size_t adapterCount = mAdapters.size();
            for (std::size_t adapterIndex = 0; adapterIndex < adapterCount; ++adapterIndex)
            {
                if (mAdapters[adapterIndex].description.find("NVPerfHUD", 0U, 9U) != fa::string::npos)
                {
                    deviceType = D3DDEVTYPE_REF;
                    selectedAdapter = static_cast<unsigned int>(adapterIndex);
                    AppendD3D9SetupLogMessage("using NVPerfHUD adapter");
                    break;
                }
            }

            HRESULT createResult = mDirect3D->CreateDevice(selectedAdapter, deviceType, primaryWindow, behaviorFlags, presentParameters, &mDevice);
            if (createResult < 0)
            {
                const std::size_t primaryAdapterIndex = static_cast<std::size_t>(context->mAdapter);
                if (primaryAdapterIndex < mAdapters.size() &&
                    IsLegacyAtiCreateDeviceFallbackAdapter(mAdapters[primaryAdapterIndex]))
                {
                    createResult = mDirect3D->CreateDevice(static_cast<unsigned int>(context->mAdapter), D3DDEVTYPE_HAL, primaryWindow, 36U, presentParameters, &mDevice);
                    if (createResult < 0)
                    {
                        AppendD3D9SetupLogMessage("unable to create device");
                        ThrowGalError("DeviceD3D9.cpp", 183, "unable to create device");
                    }
                }
                else
                {
                    AppendD3D9SetupLogMessage("unable to create device");
                    ThrowGalError("DeviceD3D9.cpp", 189, "unable to create device");
                }
            }

            mPipelineState.reset(new PipelineStateD3D9(mDevice));
            if (mPipelineState.get() != nullptr)
            {
                mPipelineState->InitState();
            }

            static_cast<void>(BuildDeviceCapabilities(context));
            mDeviceContext.mAdapter = static_cast<int>(selectedAdapter);
            CreateHeads();

            bool supportsDxt = true;
            const int builtHeadCount = mDeviceContext.GetHeadCount();
            for (int headIndex = 0; headIndex < builtHeadCount; ++headIndex)
            {
                supportsDxt = supportsDxt && HeadSupportsCapability2(mDeviceContext.GetHead(static_cast<unsigned int>(headIndex)), 12);
            }

            if (!supportsDxt)
            {
                AppendD3D9SetupLogMessage("Device does not support DXT texture formats");
                ThrowGalError("DeviceD3D9.cpp", 209, "Device does not support DXT texture formats");
            }

            static_cast<void>(mDevice->CreateQuery(D3DQUERYTYPE_EVENT, &mFrameEventQuery));
            AppendD3D9SetupLogMessage("device setup complete");
        }
        catch (...)
        {
            delete[] presentParameters;
            Shutdown();
            throw;
        }
        delete[] presentParameters;
    }

    /**
     * Address: 0x008E9B40 (FUN_008E9B40)
     *
     * boost::weak_ptr<void> *,boost::shared_ptr<void>
     *
     * What it does:
     * Dispatches `Func1`, clears caller weak-handle output, and consumes one
     * temporary shared-handle argument by value.
     */
    boost::weak_ptr<void>*
    DeviceD3D9::Func7(boost::weak_ptr<void>* const outWeakHandle, boost::shared_ptr<void> temporarySharedHandle)
    {
        Func1();
        static_cast<void>(temporarySharedHandle);
        outWeakHandle->reset();
        return outWeakHandle;
    }

    /**
     * Address: 0x008E8210 (FUN_008E8210)
     *
     * What it does:
     * Resets for the context the device already has, through slot 26.
     */
    void DeviceD3D9::Reset()
    {
        Reset(&mDeviceContext);
    }

    /**
     * Address: 0x008E8220 (FUN_008E8220)
     *
     * What it does:
     * Preserves the binary no-op cursor-init slot body.
     */
    void DeviceD3D9::InitCursor()
    {
    }

    /**
     * Address: 0x008E8230 (FUN_008E8230)
     *
     * bool
     *
     * What it does:
     * Dispatches `Func1` pre-hook then forwards to native D3D9 `ShowCursor`.
     */
    int DeviceD3D9::ShowCursor(const bool show)
    {
        Func1();
        return mDevice->ShowCursor(show ? TRUE : FALSE);
    }

    /**
     * Address: 0x008E82B0 (FUN_008E82B0)
     *
     * What it does:
     * Builds one present-parameter block for the requested head index.
     */
    D3DPRESENT_PARAMETERS* DeviceD3D9::GetHeadParameters(
        D3DPRESENT_PARAMETERS* const outParameters,
        const DeviceContext* const context,
        const unsigned int headIndex
    )
    {
        Func1();

        const Head& head = context->GetHead(headIndex);
        std::memset(outParameters, 0, sizeof(D3DPRESENT_PARAMETERS));
        if (head.mWindow != nullptr)
        {
            outParameters->BackBufferWidth = head.mWidth;
            outParameters->BackBufferHeight = head.mHeight;
            outParameters->BackBufferFormat = D3DFMT_A8R8G8B8;
            outParameters->BackBufferCount = 1U;
            outParameters->MultiSampleType = static_cast<D3DMULTISAMPLE_TYPE>(head.antialiasingHigh);
            outParameters->MultiSampleQuality = head.antialiasingLow;
            outParameters->SwapEffect = D3DSWAPEFFECT_DISCARD;
            outParameters->hDeviceWindow =
                (headIndex == 0U && head.mWindowed) ? reinterpret_cast<HWND>(head.mHandle) : reinterpret_cast<HWND>(head.mWindow);
            outParameters->Windowed = head.mWindowed ? 0 : 1;
            outParameters->EnableAutoDepthStencil = 0;
            outParameters->AutoDepthStencilFormat = D3DFMT_UNKNOWN;
            outParameters->Flags = 0U;
            outParameters->FullScreen_RefreshRateInHz = head.mWindowed ? head.framesPerSecond : 0U;
            outParameters->PresentationInterval =
                ((headIndex == 0U) && context->mVSync) ? 1U : D3DPRESENT_INTERVAL_IMMEDIATE;
        }

        return outParameters;
    }

    /**
     * Address: 0x008E8F00 (FUN_008E8F00)
     *
     * What it does:
     * Builds present-parameter blocks for all heads in one device-context payload.
     */
    void DeviceD3D9::GetDeviceParameters(D3DPRESENT_PARAMETERS* const outParameters, const DeviceContext* const context)
    {
        Func1();

        const unsigned int headCount = static_cast<unsigned int>(context->GetHeadCount());
        for (unsigned int headIndex = 0; headIndex < headCount; ++headIndex)
        {
            static_cast<void>(GetHeadParameters(&outParameters[headIndex], context, headIndex));
        }
    }

    /**
     * Address: 0x008EEB80 (FUN_008EEB80)
     *
     * What it does:
     * Rebuilds per-head output/depth wrappers after one native device reset.
     */
    void DeviceD3D9::CreateHeads()
    {
        Func1();

        const unsigned int headCount = static_cast<unsigned int>(mDeviceContext.GetHeadCount());
        if (mHeads != nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 1444, "internal D3D9 device initialization error");
        }

        OutputContext* const heads = NewOutputContexts(headCount);
        mHeads = heads;

        for (unsigned int headIndex = 0; headIndex < headCount; ++headIndex)
        {
            IDirect3DSurface9* backBuffer = nullptr;
            HRESULT result = mDevice->GetBackBuffer(headIndex, 0U, D3DBACKBUFFER_TYPE_MONO, &backBuffer);
            if (FAILED(result))
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1451, result);
            }

            Clear(true, false, false, 0U, 0.0f, 0);
            mDevice->Present(nullptr, nullptr, nullptr, nullptr);

            D3DSURFACE_DESC surfaceDesc;
            backBuffer->GetDesc(&surfaceDesc);

            IDirect3DSurface9* depthStencilSurface = nullptr;
            result = mDevice->CreateDepthStencilSurface(
                surfaceDesc.Width, surfaceDesc.Height, D3DFMT_D24S8, surfaceDesc.MultiSampleType,
                surfaceDesc.MultiSampleQuality, FALSE, &depthStencilSurface, nullptr
            );
            if (FAILED(result))
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1462, result);
            }

            // Both surfaces pass straight into their wrappers, which own them
            // from here; a throw above leaks what was already acquired, as the
            // binary does (neither local is in its unwind map).
            heads[headIndex].surface.reset(new RenderTargetD3D9(backBuffer));

            const DepthStencilTargetContext depthStencilContext(surfaceDesc.Width, surfaceDesc.Height, 3U, false);
            heads[headIndex].depthStencil.reset(new DepthStencilTargetD3D9(&depthStencilContext, depthStencilSurface));
        }
    }

    /**
     * Address: 0x008F2080 (FUN_008F2080)
     *
     * What it does:
     * Copies device-context capabilities, probes format/multisample support, and
     * updates shader/capability profile fields.
     */
    int DeviceD3D9::BuildDeviceCapabilities(const DeviceContext* const context)
    {
        Func1();
        mDeviceContext = *context;

        const unsigned int headCount = static_cast<unsigned int>(context->GetHeadCount());
        if (headCount > mAdapters.size())
        {
            ThrowGalError("DeviceD3D9.cpp", 1250, "invalid head count specified in device context");
        }

        for (unsigned int adapterIndex = 0; adapterIndex < headCount; ++adapterIndex)
        {
            Head& head = mDeviceContext.mHeads[adapterIndex];
            const AdapterD3D9& adapter = mAdapters[adapterIndex];

            head.adapterModes.clear();
            for (const AdapterModeD3D9& mode : adapter.modes)
            {
                const HeadAdapterMode headMode{mode.width_, mode.height_, mode.refreshRate_};
                head.adapterModes.push_back(headMode);
            }

            head.validFormats1.clear();
            for (int formatToken = 1; formatToken < 8; ++formatToken)
            {
                const HRESULT result = mDirect3D->CheckDeviceFormat(adapterIndex, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 1U, D3DRTYPE_TEXTURE, static_cast<D3DFORMAT>(GetD3DFormat(static_cast<std::uint32_t>(formatToken))));
                if (result >= 0)
                {
                    head.validFormats1.push_back(formatToken);
                }
            }

            head.validFormats2.clear();
            for (int formatToken = 1; formatToken < 20; ++formatToken)
            {
                const HRESULT result = mDirect3D->CheckDeviceFormat(adapterIndex, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0U, D3DRTYPE_TEXTURE, static_cast<D3DFORMAT>(FormatGalToD3D(static_cast<std::uint32_t>(formatToken))));
                if (result >= 0)
                {
                    head.validFormats2.push_back(formatToken);
                }
            }

            D3DADAPTER_IDENTIFIER9 adapterIdentifier{};
            static_cast<void>(mDirect3D->GetAdapterIdentifier(0U, 0U, &adapterIdentifier));

            head.mStrs.clear();
            if (adapterIdentifier.VendorId != kVendorIdNvidia)
            {
                for (unsigned int sampleType = 2U; sampleType <= 16U; ++sampleType)
                {
                    const HRESULT result = mDirect3D->CheckDeviceMultiSampleType(adapterIndex, D3DDEVTYPE_HAL, D3DFMT_A8R8G8B8, (!head.mWindowed) ? TRUE : FALSE, static_cast<D3DMULTISAMPLE_TYPE>(sampleType), nullptr);
                    if (result < 0)
                    {
                        continue;
                    }

                    HeadSampleOption option{};
                    option.sampleType = sampleType;
                    option.sampleQuality = 0U;
                    char label[16] = {};
                    std::snprintf(label, sizeof(label), "%u", sampleType);
                    option.label.assign_owned(label);
                    head.mStrs.push_back(option);
                }
            }
            else
            {
                struct SampleCandidate final
                {
                    unsigned int sampleType = 0U;
                    unsigned int sampleQuality = 0U;
                    const char* label = nullptr;
                };

                static constexpr SampleCandidate kNvidiaSampleCandidates[] = {
                    {2U, 0U, "2"},
                    {4U, 0U, "4"},
                    {4U, 2U, "8"},
                    {8U, 0U, "8Q"},
                    {4U, 4U, "16"},
                    {8U, 2U, "16Q"},
                };

                for (const SampleCandidate& candidate : kNvidiaSampleCandidates)
                {
                    DWORD qualityLevels = 0U;
                    const HRESULT checkResult = mDirect3D->CheckDeviceMultiSampleType(adapterIndex, D3DDEVTYPE_HAL, D3DFMT_A8R8G8B8, (!head.mWindowed) ? TRUE : FALSE, static_cast<D3DMULTISAMPLE_TYPE>(candidate.sampleType), &qualityLevels);

                    if ((checkResult < 0) || (qualityLevels <= candidate.sampleQuality))
                    {
                        continue;
                    }

                    if (candidate.sampleType == 4U && candidate.sampleQuality == 4U)
                    {
                        const HRESULT sixteenSampleResult = mDirect3D->CheckDeviceMultiSampleType(adapterIndex, D3DDEVTYPE_HAL, D3DFMT_A8R8G8B8, (!head.mWindowed) ? TRUE : FALSE, static_cast<D3DMULTISAMPLE_TYPE>(16U), nullptr);
                        if (sixteenSampleResult >= 0)
                        {
                            HeadSampleOption option{};
                            option.sampleType = 16U;
                            option.sampleQuality = 0U;
                            option.label.assign_owned("16");
                            head.mStrs.push_back(option);
                        }
                        continue;
                    }

                    HeadSampleOption option{};
                    option.sampleType = candidate.sampleType;
                    option.sampleQuality = candidate.sampleQuality;
                    option.label.assign_owned(candidate.label);
                    head.mStrs.push_back(option);
                }
            }
        }

        D3DCAPS9 caps{};
        const HRESULT capsResult = mDevice->GetDeviceCaps(&caps);
        if (capsResult < 0)
        {
            ThrowGalError("DeviceD3D9.cpp", 1343, "unable to retreive device caps");
        }

        CheckHardwareInstancingSupport(*this, caps);

        mDeviceContext.mSupportsFloat16 =
            ((caps.DeclTypes & kDeclTypeFloat16_2) != 0U) && ((caps.DeclTypes & kDeclTypeFloat16_4) != 0U);
        mDeviceContext.mMaxPrimitiveCount = caps.MaxPrimitiveCount;
        mDeviceContext.mMaxVertexCount = caps.MaxVertexIndex;

        if (mDeviceContext.mValidate && (caps.VertexShaderVersion < kVertexShaderModel20))
        {
            ThrowGalError("DeviceD3D9.cpp", 1355, "Vertex shader 2.0 required");
        }

        if (mDeviceContext.mValidate && (caps.PixelShaderVersion < kPixelShaderModel20))
        {
            ThrowGalError("DeviceD3D9.cpp", 1361, "Pixel shader 2.0 required");
        }

        mDeviceContext.mVertexShaderProfile =
            ResolveVertexShaderProfileToken(D3DXGetVertexShaderProfile(mDevice));
        mDeviceContext.mPixelShaderProfile =
            ResolvePixelShaderProfileToken(D3DXGetPixelShaderProfile(mDevice));
        return mDeviceContext.mPixelShaderProfile;
    }

    /**
     * FAF addition, not in the shipped binary.
     *
     * What it does:
     * Asks the adapter whether a vertex shader can sample `textureFormat`. A
     * vertex texture read needs a 3.0 vertex shader, which Direct3D 9 pairs
     * only with a 3.0 pixel shader, so both versions are checked. Software
     * vertex processing is refused outright rather than trusting the
     * adapter's hardware answer for it.
     */
    bool DeviceD3D9::SupportsVertexTextureFormat(const std::uint32_t textureFormat)
    {
        if (mDirect3D == nullptr || mDevice == nullptr)
        {
            return false;
        }

        D3DCAPS9 caps{};
        if (FAILED(mDevice->GetDeviceCaps(&caps)) || caps.VertexShaderVersion < D3DVS_VERSION(3, 0) ||
            caps.PixelShaderVersion < D3DPS_VERSION(3, 0))
        {
            return false;
        }

        D3DDEVICE_CREATION_PARAMETERS creation{};
        D3DDISPLAYMODE displayMode{};
        if (FAILED(mDevice->GetCreationParameters(&creation)) ||
            (creation.BehaviorFlags & D3DCREATE_SOFTWARE_VERTEXPROCESSING) != 0U ||
            FAILED(mDirect3D->GetAdapterDisplayMode(creation.AdapterOrdinal, &displayMode)))
        {
            return false;
        }

        const HRESULT result = mDirect3D->CheckDeviceFormat(
            creation.AdapterOrdinal, creation.DeviceType, displayMode.Format, D3DUSAGE_QUERY_VERTEXTEXTURE,
            D3DRTYPE_TEXTURE, static_cast<D3DFORMAT>(FormatGalToD3D(textureFormat))
        );
        return SUCCEEDED(result);
    }

    bool DeviceD3D9::GetRuntimeInfo(DeviceRuntimeInfo& out)
    {
        if (mDirect3D == nullptr || mDevice == nullptr)
        {
            return false;
        }

        out.api = "D3D9";
        D3DDEVICE_CREATION_PARAMETERS creation{};
        const UINT adapterOrdinal = SUCCEEDED(mDevice->GetCreationParameters(&creation))
            ? creation.AdapterOrdinal
            : static_cast<UINT>(mDeviceContext.mAdapter);
        D3DADAPTER_IDENTIFIER9 identifier{};
        if (SUCCEEDED(mDirect3D->GetAdapterIdentifier(adapterOrdinal, 0U, &identifier)))
        {
            out.adapter = identifier.Description;
            out.vendorId = identifier.VendorId;
            out.deviceId = identifier.DeviceId;
            char version[48] = {};
            const std::uint64_t driver = static_cast<std::uint64_t>(identifier.DriverVersion.QuadPart);
            std::snprintf(
                version, sizeof(version), "%u.%u.%u.%u", static_cast<unsigned>((driver >> 48) & 0xFFFFU),
                static_cast<unsigned>((driver >> 32) & 0xFFFFU), static_cast<unsigned>((driver >> 16) & 0xFFFFU),
                static_cast<unsigned>(driver & 0xFFFFU)
            );
            out.driverVersion = version;
        }

        D3DCAPS9 caps{};
        if (SUCCEEDED(mDevice->GetDeviceCaps(&caps)))
        {
            char model[48] = {};
            std::snprintf(
                model, sizeof(model), "VS %u.%u / PS %u.%u", static_cast<unsigned>(D3DSHADER_VERSION_MAJOR(caps.VertexShaderVersion)),
                static_cast<unsigned>(D3DSHADER_VERSION_MINOR(caps.VertexShaderVersion)),
                static_cast<unsigned>(D3DSHADER_VERSION_MAJOR(caps.PixelShaderVersion)),
                static_cast<unsigned>(D3DSHADER_VERSION_MINOR(caps.PixelShaderVersion))
            );
            out.featureLevel = model;
        }
        out.availableTextureMemory = mDevice->GetAvailableTextureMem();
        // The budget and usage of the same adapter, through DXGI (Windows 10).
        (void)FillDxgiAdapterMemoryByPciId(out.vendorId, out.deviceId, out);

        std::string chains;
        const UINT chainCount = mDevice->GetNumberOfSwapChains();
        for (UINT index = 0U; index < chainCount; ++index)
        {
            IDirect3DSwapChain9* chain = nullptr;
            if (FAILED(mDevice->GetSwapChain(index, &chain)) || chain == nullptr)
            {
                continue;
            }
            D3DPRESENT_PARAMETERS parameters{};
            const HRESULT result = chain->GetPresentParameters(&parameters);
            chain->Release();
            if (FAILED(result))
            {
                continue;
            }
            const char* const effect = parameters.SwapEffect == D3DSWAPEFFECT_DISCARD ? "discard"
                : parameters.SwapEffect == D3DSWAPEFFECT_FLIP                        ? "flip"
                : parameters.SwapEffect == D3DSWAPEFFECT_COPY                        ? "copy"
                                                                                     : "other";
            char text[128] = {};
            std::snprintf(
                text, sizeof(text), "%s%ux%u %s %u buffers, %s", chains.empty() ? "" : "; ", parameters.BackBufferWidth,
                parameters.BackBufferHeight, effect, parameters.BackBufferCount, parameters.Windowed ? "windowed" : "full screen"
            );
            chains += text;
        }
        out.swapChain = chains.c_str();
        out.vsync = mDeviceContext.mVSync;
        out.gpuDrivenFeatures = GetGpuDrivenFeatures();
        return true;
    }

    /**
     * Address: 0x008F3070 (FUN_008F3070)
     *
     * What it does:
     * Resets the native D3D9 device using caller context payload, then rebuilds
     * capabilities, head resources, pipeline state, and frame event-query state.
     */
    void DeviceD3D9::Reset(DeviceContext* const context)
    {
        if (mPipelineState.get() != nullptr)
        {
            static_cast<void>(mPipelineState->ClearTextures());
        }
        mPipelineState.reset();

        // Before BuildDeviceCapabilities below: the context still holds the head count the array was made with.
        DeleteOutputContexts(mHeads, GetDeviceHeadCount(this));
        mHeads = nullptr;

        SafeRelease(mFrameEventQuery);

        // Allocated with new[] (0x008F3130) and, unlike Setup's, never freed.
        D3DPRESENT_PARAMETERS* const parameters =
            new D3DPRESENT_PARAMETERS[static_cast<std::size_t>(context->GetHeadCount())];
        GetDeviceParameters(parameters, context);

        const HRESULT resetResult = mDevice->Reset(parameters);
        if (resetResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 866, resetResult);
        }

        static_cast<void>(BuildDeviceCapabilities(context));
        CreateHeads();

        mPipelineState.reset(new PipelineStateD3D9(mDevice));
        if (mPipelineState.get() != nullptr)
        {
            static_cast<void>(mPipelineState->InitState());
        }

        static_cast<void>(mDevice->CreateQuery(D3DQUERYTYPE_EVENT, &mFrameEventQuery));
    }

    /**
     * Address: 0x008EAB20 (FUN_008EAB20)
     *
     * What it does:
     * Validates one head index against the device context's head count and
     * returns that head's output context from the array at `this+0x7C`
     * (`shl eax,5` - `sizeof(OutputContext)` is 0x20).
     */
    OutputContext* DeviceD3D9::GetHeadOutputContext(const unsigned int headIndex)
    {
        Func1();
        if (headIndex >= GetDeviceHeadCount(this))
        {
            ThrowGalError("DeviceD3D9.cpp", 295, "invalid head index specified");
        }

        return &GetDeviceHeadArrayBase(this)[headIndex];
    }

    /**
     * Address: 0x008EABF0 (FUN_008EABF0)
     *
     * What it does:
     * The const overload of `GetHeadOutputContext`; same body.
     */
    const OutputContext* DeviceD3D9::GetHeadOutputContext(const unsigned int headIndex) const
    {
        Func1();
        if (headIndex >= GetDeviceHeadCount(this))
        {
            ThrowGalError("DeviceD3D9.cpp", 303, "invalid head index specified");
        }

        return &GetDeviceHeadArrayBase(this)[headIndex];
    }

    /**
     * Address: 0x008EACC0 (FUN_008EACC0)
     *
     * What it does:
     * Creates one D3D9 texture - empty at the context's size and format, or
     * decoded from in-memory file data as a 2D, cube or volume texture - and
     * wraps it in a `TextureD3D9` whose context records what was built.
     */
    boost::shared_ptr<Texture> DeviceD3D9::CreateTexture(const TextureContext* const context)
    {
        Func1();

        TextureContext textureContext{};
        textureContext.AssignFrom(*context);
        textureContext.ClearDataBuffer();

        const char* const sourceData = context->dataBuffer_.mBegin;
        const unsigned int sourceBytes = static_cast<unsigned int>(context->DataSizeBytes());

        IDirect3DBaseTexture9* nativeTexture = nullptr;
        if (context->source_ == 2U)
        {
            const unsigned int mappedFormat = FormatGalToD3D(context->format_);

            unsigned int usageFlags = (context->usage_ == 2U) ? 0x200U : 0U;
            D3DPOOL pool = (context->usage_ == 2U) ? D3DPOOL_DEFAULT : D3DPOOL_MANAGED;
            if (context->usage_ == 3U)
            {
                pool = D3DPOOL_SYSTEMMEM;
            }
            if ((context->mipmapLevels_ == 0U) && (context->usage_ != 2U))
            {
                usageFlags |= 0x400U;
            }

            IDirect3DTexture9* texture;
            const HRESULT createResult = D3DXCreateTexture(mDevice, context->width_, context->height_, context->mipmapLevels_, usageFlags, static_cast<D3DFORMAT>(mappedFormat), pool, &texture);
            if (createResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 477, createResult);
            }

            D3DSURFACE_DESC surfaceDesc;
            const HRESULT levelDescResult = texture->GetLevelDesc(0U, &surfaceDesc);
            if (levelDescResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 481, levelDescResult);
            }

            textureContext.type_ = 1U;
            textureContext.mipmapLevels_ = texture->GetLevelCount();
            textureContext.format_ = FormatD3D9ToMoho(surfaceDesc.Format);
            textureContext.width_ = surfaceDesc.Width;
            textureContext.height_ = surfaceDesc.Height;
            nativeTexture = texture;
        }
        else if (context->source_ == 1U)
        {
            if (context->dataBuffer_.mEnd == context->dataBuffer_.mBegin)
            {
                ThrowGalError("DeviceD3D9.cpp", 350, "attempt to create texture from uninitialized memory");
            }

            D3DXIMAGE_INFO imageInfo{};
            const HRESULT imageInfoResult = D3DXGetImageInfoFromFileInMemory(sourceData, sourceBytes, &imageInfo);
            if (imageInfoResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 354, imageInfoResult);
            }

            if (imageInfo.ResourceType == D3DRTYPE_CUBETEXTURE)
            {
                const unsigned int edgeLength = (context->width_ != 0U) ? context->width_ : D3DX_DEFAULT;
                IDirect3DCubeTexture9* cubeTexture;
                const HRESULT createResult = D3DXCreateCubeTextureFromFileInMemoryEx(mDevice, sourceData, sourceBytes, edgeLength, D3DX_DEFAULT, 0U, static_cast<D3DFORMAT>(FormatGalToD3D(context->format_)), D3DPOOL_MANAGED, D3DX_DEFAULT, D3DX_DEFAULT, 0U, nullptr, nullptr, &cubeTexture);
                if (createResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 410, createResult);
                }

                D3DSURFACE_DESC surfaceDesc;
                const HRESULT levelDescResult = cubeTexture->GetLevelDesc(0U, &surfaceDesc);
                if (levelDescResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 414, levelDescResult);
                }

                textureContext.type_ = 2U;
                textureContext.mipmapLevels_ = cubeTexture->GetLevelCount();
                textureContext.format_ = FormatD3D9ToMoho(surfaceDesc.Format);
                textureContext.width_ = surfaceDesc.Width;
                textureContext.height_ = surfaceDesc.Height;
                nativeTexture = cubeTexture;
            }
            else if (imageInfo.ResourceType == D3DRTYPE_VOLUMETEXTURE)
            {
                IDirect3DVolumeTexture9* volumeTexture;
                const HRESULT createResult = D3DXCreateVolumeTextureFromFileInMemoryEx(mDevice, sourceData, sourceBytes, D3DX_DEFAULT, D3DX_DEFAULT, D3DX_DEFAULT, D3DX_DEFAULT, 0U, static_cast<D3DFORMAT>(FormatGalToD3D(context->format_)), D3DPOOL_MANAGED, D3DX_DEFAULT, D3DX_DEFAULT, 0U, nullptr, nullptr, &volumeTexture);
                if (createResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 442, createResult);
                }

                D3DVOLUME_DESC volumeDesc;
                const HRESULT levelDescResult = volumeTexture->GetLevelDesc(0U, &volumeDesc);
                if (levelDescResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 446, levelDescResult);
                }

                textureContext.type_ = 3U;
                textureContext.mipmapLevels_ = volumeTexture->GetLevelCount();
                textureContext.format_ = FormatD3D9ToMoho(volumeDesc.Format);
                textureContext.width_ = volumeDesc.Width;
                textureContext.height_ = volumeDesc.Height;
                nativeTexture = volumeTexture;
            }
            else if (imageInfo.ResourceType == D3DRTYPE_TEXTURE)
            {
                const unsigned int width = (context->width_ != 0U) ? context->width_ : D3DX_DEFAULT;
                const unsigned int height = (context->height_ != 0U) ? context->height_ : D3DX_DEFAULT;
                // 0x008EB42A..0x008EB455, read off the pushes (IDA applies the sixteen-parameter
                // volume prototype here too, shifting every label from `format` on by one slot):
                // Filter = D3DX_DEFAULT, MipFilter = D3DX_SKIP_DDS_MIP_LEVELS(skip) | D3DX_FILTER_BOX.
                // Passing the skip mask as Filter and 0 as MipFilter leaves every mip below
                // level 0 unfilled, which renders as opaque black at any minification.
                const unsigned int mipFilter = ((context->reserved0x44_ & 0x1FU) << 26U) | 5U;

                IDirect3DTexture9* texture;
                const HRESULT createResult = D3DXCreateTextureFromFileInMemoryEx(mDevice, sourceData, sourceBytes, width, height, D3DX_DEFAULT, 0U, static_cast<D3DFORMAT>(FormatGalToD3D(context->format_)), D3DPOOL_MANAGED, D3DX_DEFAULT, mipFilter, 0U, nullptr, nullptr, &texture);
                if (createResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 377, createResult);
                }

                D3DSURFACE_DESC surfaceDesc;
                const HRESULT levelDescResult = texture->GetLevelDesc(0U, &surfaceDesc);
                if (levelDescResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 381, levelDescResult);
                }

                textureContext.type_ = 1U;
                textureContext.mipmapLevels_ = texture->GetLevelCount();
                textureContext.format_ = FormatD3D9ToMoho(surfaceDesc.Format);
                textureContext.width_ = surfaceDesc.Width;
                textureContext.height_ = surfaceDesc.Height;
                nativeTexture = texture;
            }
            else
            {
                ThrowGalError("DeviceD3D9.cpp", 458, "unknown texture type");
            }
        }
        else
        {
            ThrowGalError("DeviceD3D9.cpp", 493, "invalid source specified for texture data");
        }

        return boost::shared_ptr<Texture>(new TextureD3D9(&textureContext, nativeTexture));
    }

    /**
     * Address: 0x008EB610 (FUN_008EB610)
     *
     * What it does:
     * Creates one single-level `D3DUSAGE_RENDERTARGET` texture of the
     * context's size and format in the default pool and hands it to a new
     * `RenderTargetD3D9`, which takes its level-0 surface.
     */
    boost::shared_ptr<RenderTarget> DeviceD3D9::CreateRenderTarget(const RenderTargetContext* const context)
    {
        Func1();

        IDirect3DTexture9* renderTexture = nullptr;
        const HRESULT createResult = mDevice->CreateTexture(context->width_, context->height_, 1U, 1U, static_cast<D3DFORMAT>(GetD3DFormat(context->format_)), D3DPOOL_DEFAULT, &renderTexture, nullptr);
        if (createResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 508, createResult);
        }

        return boost::shared_ptr<RenderTarget>(new RenderTargetD3D9(context, renderTexture));
    }

    /**
     * Address: 0x008EB780 (FUN_008EB780)
     *
     * What it does:
     * Creates one single-level render-target cube texture and hands it to a
     * new `CubeRenderTargetD3D9`, which takes the six face surfaces.
     */
    boost::shared_ptr<CubeRenderTarget> DeviceD3D9::CreateCubeRenderTarget(const CubeRenderTargetContext* const context)
    {
        Func1();

        IDirect3DCubeTexture9* cubeTexture = nullptr;
        const HRESULT createResult = mDevice->CreateCubeTexture(context->dimension_, 1U, 1U, static_cast<D3DFORMAT>(GetD3DFormat(context->format_)), D3DPOOL_DEFAULT, &cubeTexture, nullptr);
        if (createResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 521, createResult);
        }

        return boost::shared_ptr<CubeRenderTarget>(new CubeRenderTargetD3D9(context, cubeTexture));
    }

    /**
     * Address: 0x008EB8E0 (FUN_008EB8E0)
     *
     * What it does:
     * Creates one non-multisampled depth/stencil surface of the context's size
     * and format and wraps it in a `DepthStencilTargetD3D9`.
     */
    boost::shared_ptr<DepthStencilTarget> DeviceD3D9::CreateDepthStencilTarget(
        const DepthStencilTargetContext* const context
    )
    {
        Func1();

        IDirect3DSurface9* depthStencilSurface = nullptr;
        const HRESULT createResult = mDevice->CreateDepthStencilSurface(context->width_, context->height_, static_cast<D3DFORMAT>(FormatToD3DFormat(context->format_)), D3DMULTISAMPLE_NONE, 0U, FALSE, &depthStencilSurface, nullptr);
        if (createResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 534, createResult);
        }

        return boost::shared_ptr<DepthStencilTarget>(new DepthStencilTargetD3D9(context, depthStencilSurface));
    }

    /**
     * Address: 0x008EBA50 (FUN_008EBA50)
     *
     * What it does:
     * Creates the D3D9 vertex declaration for gal vertex format `formatCode`
     * and wraps it in a `VertexFormatD3D9`. An unknown code throws from the
     * element-table lookup.
     */
    boost::shared_ptr<VertexFormat> DeviceD3D9::CreateVertexFormat(const std::uint32_t formatCode)
    {
        Func1();

        IDirect3DVertexDeclaration9* vertexDeclaration = nullptr;
        const HRESULT createResult = mDevice->CreateVertexDeclaration(GetVertexFormatElementsOrThrow(formatCode), &vertexDeclaration);
        if (createResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 546, createResult);
        }

        return boost::shared_ptr<VertexFormat>(new VertexFormatD3D9(formatCode, vertexDeclaration));
    }

    /**
     * Address: 0x008EBBB0 (FUN_008EBBB0)
     *
     * What it does:
     * Creates one D3D9 vertex buffer of `vertexCount * stride` bytes (dynamic
     * buffers in the default pool, the rest managed) and wraps it in a
     * `VertexBufferD3D9`.
     */
    boost::shared_ptr<VertexBuffer> DeviceD3D9::CreateVertexBuffer(const VertexBufferContext* const context)
    {
        Func1();

        const unsigned int byteWidth = context->vertexCount_ * context->stride_;
        const unsigned int usageFlags = ((context->usage_ == 2U) ? 0x200U : 0U) | 0x8U;
        const D3DPOOL pool = (context->usage_ == 2U) ? D3DPOOL_DEFAULT : D3DPOOL_MANAGED;

        IDirect3DVertexBuffer9* nativeVertexBuffer = nullptr;
        const HRESULT createResult =
            mDevice->CreateVertexBuffer(byteWidth, usageFlags, 0U, pool, &nativeVertexBuffer, nullptr);
        if (createResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 560, createResult);
        }

        return boost::shared_ptr<VertexBuffer>(new VertexBufferD3D9(context, nativeVertexBuffer));
    }

    /**
     * Address: 0x008EBD30 (FUN_008EBD30)
     *
     * What it does:
     * Creates one D3D9 index buffer of 16- or 32-bit indices (format 0 throws
     * "undefined index buffer format") and wraps it in an `IndexBufferD3D9`.
     */
    boost::shared_ptr<IndexBuffer> DeviceD3D9::CreateIndexBuffer(const IndexBufferContext* const context)
    {
        Func1();

        if (context->format_ == 0U)
        {
            ThrowGalError("DeviceD3D9.cpp", 569, "undefined index buffer format");
        }

        const unsigned int bytesPerIndex = (context->format_ == 1U) ? 2U : 4U;
        const unsigned int byteSize = context->size_ * bytesPerIndex;
        const unsigned int usageFlags = ((context->type_ == 2U) ? 0x200U : 0U) | 0x8U;
        const D3DFORMAT d3dFormat = (context->format_ == 1U) ? D3DFMT_INDEX16 : D3DFMT_INDEX32;
        const D3DPOOL pool = (context->type_ == 2U) ? D3DPOOL_DEFAULT : D3DPOOL_MANAGED;

        IDirect3DIndexBuffer9* nativeIndexBuffer = nullptr;
        const HRESULT createResult =
            mDevice->CreateIndexBuffer(byteSize, usageFlags, d3dFormat, pool, &nativeIndexBuffer, nullptr);
        if (createResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 581, createResult);
        }

        return boost::shared_ptr<IndexBuffer>(new IndexBufferD3D9(context, nativeIndexBuffer));
    }

    /**
     * Address: 0x008EC440 (FUN_008EC440)
     *
     * What it does:
     * Reads one colour target back into a system-memory texture: resolves the
     * destination's level-0 surface and dispatches native
     * `GetRenderTargetData` from the target's surface into it.
     */
    void DeviceD3D9::GetRenderTargetData(
        const boost::shared_ptr<RenderTarget>& source,
        const boost::shared_ptr<Texture>& destination
    )
    {
        Func1();

        if (source.get() == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 645, "Missing source texture");
        }

        if (destination.get() == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 646, "Missing dest   texture");
        }

        IDirect3DSurface9* const sourceSurface = static_cast<RenderTargetD3D9*>(source.get())->GetSurface();

        IDirect3DSurface9* destinationSurface = nullptr;
        HRESULT result = static_cast<TextureD3D9*>(destination.get())->GetTexture1()->GetSurfaceLevel(0U, &destinationSurface);
        if (FAILED(result))
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 656, result);
        }

        result = mDevice->GetRenderTargetData(sourceSurface, destinationSurface);
        destinationSurface->Release();
        if (FAILED(result))
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 661, result);
        }
    }

    /**
     * Address: 0x008EC250 (FUN_008EC250)
     *
     * What it does:
     * Blits a rectangle of one colour target's surface into another through
     * native `IDirect3DDevice9::StretchRect` with linear filtering.
     */
    void DeviceD3D9::StretchRect(
        const boost::shared_ptr<RenderTarget>& source,
        const boost::shared_ptr<RenderTarget>& destination,
        const RECT* const sourceRect,
        const RECT* const destinationRect
    )
    {
        Func1();

        if (source.get() == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 624, "Missing source texture");
        }

        if (destination.get() == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 625, "Missing dest   texture");
        }

        const HRESULT stretchResult = mDevice->StretchRect(static_cast<RenderTargetD3D9*>(source.get())->GetSurface(), sourceRect, static_cast<RenderTargetD3D9*>(destination.get())->GetSurface(), destinationRect, D3DTEXF_LINEAR);
        if (stretchResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 637, stretchResult);
        }
    }

    /**
     * Address: 0x008EBF70 (FUN_008EBF70)
     *
     * What it does:
     * Resolves both textures' level-0 surfaces and copies the source region
     * into the destination region with `D3DXLoadSurfaceFromSurface`; null
     * rects mean the whole surface.
     */
    void DeviceD3D9::UpdateSurface(
        const boost::shared_ptr<Texture>& source,
        const boost::shared_ptr<Texture>& destination,
        const RECT* const sourceRect,
        const RECT* const destinationRect
    )
    {
        Func1();

        if (source.get() == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 592, "Missing source texture");
        }

        if (destination.get() == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 593, "Missing dest   texture");
        }

        IDirect3DSurface9* sourceSurface = nullptr;
        HRESULT result = static_cast<TextureD3D9*>(source.get())->GetTexture1()->GetSurfaceLevel(0U, &sourceSurface);
        if (FAILED(result))
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 599, result);
        }

        IDirect3DSurface9* destinationSurface = nullptr;
        result = static_cast<TextureD3D9*>(destination.get())->GetTexture1()->GetSurfaceLevel(0U, &destinationSurface);
        if (FAILED(result))
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 605, result);
        }

        result = D3DXLoadSurfaceFromSurface(
            destinationSurface, nullptr, destinationRect, sourceSurface, nullptr, sourceRect, D3DX_DEFAULT, 0U
        );
        sourceSurface->Release();
        destinationSurface->Release();
        if (FAILED(result))
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 610, result);
        }
    }

    /**
     * Address: 0x008ECB50 (FUN_008ECB50)
     *
     * What it does:
     * Writes one cube render target's texture to `filePath` as DDS.
     *
     * The target is a cube render target, not a texture: the texture comes
     * from `CubeRenderTargetD3D9::GetTexture` (0x00941270,
     * `mov eax,[ecx+0x10]`), and the failure text is "unable to get concrete
     * cube texture". This body used to type the argument as a `TextureD3D9`
     * and read that same +0x10 through a `GetLocation` accessor, which on a
     * texture is the middle of the location string - so D3DX would have been
     * handed string bytes as its texture.
     */
    void DeviceD3D9::SaveCubeRenderTarget(
        const boost::shared_ptr<CubeRenderTarget>& cubeTarget,
        const fa::string& filePath
    )
    {
        Func1();

        // `!*(_DWORD *)(a3 + 20)` - string+0x14 is mySize, not myRes: fa::string
        // keeps its allocator cookie at +0x00, bx at +0x04, mySize at +0x14 and
        // myRes at +0x18. The guard rejects an empty path.
        if (filePath.mySize == 0U)
        {
            ThrowGalError("DeviceD3D9.cpp", 736, "Missing file");
        }

        IDirect3DCubeTexture9* const nativeTexture = static_cast<CubeRenderTargetD3D9*>(cubeTarget.get())->GetTexture();
        if (nativeTexture == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 741, "unable to get concrete cube texture");
        }

        const HRESULT saveResult = D3DXSaveTextureToFileA(filePath.c_str(), D3DXIFF_DDS, nativeTexture, nullptr);
        if (saveResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 745, saveResult);
        }
    }

    /**
     * Address: 0x008EC970 (FUN_008EC970)
     *
     * What it does:
     * Writes one colour target's surface to `filePath` in image format
     * `fileFormat`.
     */
    void DeviceD3D9::SaveRenderTarget(
        const boost::shared_ptr<RenderTarget>& renderTarget,
        const fa::string& filePath,
        const int fileFormat
    )
    {
        Func1();

        // string+0x14 is mySize (see DeviceD3D9::SaveCubeRenderTarget) - the
        // guard rejects an empty path, and an SSO string's myRes is 15 even
        // when empty.
        if (filePath.mySize == 0U)
        {
            ThrowGalError("DeviceD3D9.cpp", 715, "Missing file");
        }

        // One `GetSurface` call (0x008ECA21); the result feeds the save.
        IDirect3DSurface9* const surface = static_cast<RenderTargetD3D9*>(renderTarget.get())->GetSurface();
        if (surface == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 720, "Unable to get back buffer surface");
        }

        const HRESULT saveResult =
            D3DXSaveSurfaceToFileA(filePath.c_str(), kD3DXImageFileFormats[fileFormat], surface, nullptr, nullptr);
        if (saveResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 728, saveResult);
        }
    }

    /**
     * Address: 0x008EC6A0 (FUN_008EC6A0)
     *
     * What it does:
     * Encodes one texture's level-0 surface in image format `fileFormat`:
     * into `outBuffer` through a D3DX buffer when it is non-null, otherwise
     * to `filePath`.
     */
    void DeviceD3D9::SaveTexture(
        const boost::shared_ptr<Texture>& texture,
        const fa::string& filePath,
        const int fileFormat,
        gpg::MemBuffer<char>* const outBuffer
    )
    {
        Func1();

        IDirect3DSurface9* sourceSurface = nullptr;
        const HRESULT getSurfaceResult =
            static_cast<TextureD3D9*>(texture.get())->GetTexture1()->GetSurfaceLevel(0U, &sourceSurface);
        if (FAILED(getSurfaceResult))
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 681, getSurfaceResult);
        }

        const D3DXIMAGE_FILEFORMAT format = kD3DXImageFileFormats[fileFormat];
        HRESULT saveResult;
        if (outBuffer != nullptr)
        {
            ID3DXBuffer* fileBuffer;
            if (FAILED(D3DXCreateBuffer(0U, &fileBuffer)))
            {
                // The binary's check macro evaluates its expression a second
                // time to name the failure (0x008EC7B1).
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 690, D3DXCreateBuffer(0U, &fileBuffer));
            }

            // Replaces the buffer made above without releasing it, and copies
            // whatever the buffer holds even when the encode failed - both as
            // the binary does.
            saveResult = D3DXSaveSurfaceToFileInMemory(&fileBuffer, format, sourceSurface, nullptr, nullptr);
            if (outBuffer->Size() != fileBuffer->GetBufferSize())
            {
                *outBuffer = gpg::AllocMemBuffer(fileBuffer->GetBufferSize());
            }
            // Raw shader/effect blob copy from the D3DX file buffer.
            std::copy_n(static_cast<const char*>(fileBuffer->GetBufferPointer()), fileBuffer->GetBufferSize(), outBuffer->GetPtr(0U, 0U));
            fileBuffer->Release();
        }
        else
        {
            saveResult = D3DXSaveSurfaceToFileA(filePath.c_str(), format, sourceSurface, nullptr, nullptr);
        }

        sourceSurface->Release();
        if (FAILED(saveResult))
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 707, saveResult);
        }
    }

    /**
     * Address: 0x008ECD20 (FUN_008ECD20)
     *
     * void const *,std::uint32_t,gpg::MemBuffer<char> *,std::uint32_t *,int *
     *
     * What it does:
     * Decodes texture payload bytes from memory, normalizes to DXT5 blocks when
     * needed, then exports packed blocks and decoded width/height lanes.
     */
    void DeviceD3D9::GetTexture2D(
        const void* const sourceData,
        const std::uint32_t sourceBytes,
        gpg::MemBuffer<char>* const outTextureData,
        std::uint32_t* const outWidth,
        int* const outHeight
    )
    {
        Func1();

        if (sourceData == nullptr)
        {
            return;
        }

        // The argument list below is read straight off the call at 0x008ECD87.
        // Take the pushes, not the decompiler's labels: IDA resolves the callee
        // to the 2D D3DXCreateTextureFromFileInMemoryEx (d3dx9_35.dll ordinal
        // 0x62) but then applies the sixteen-parameter *volume* prototype to
        // it, so it invents a `depth` argument and every label from `format`
        // onwards is shifted one place left. The repeat at 0x008ECDB7 settles
        // it: it pushes exactly fifteen arguments.
        //
        // Getting the shift wrong is not a subtle fidelity issue - it hands
        // D3DX a Format of 2, which is not a D3DFORMAT at all, so the call
        // fails and no texture in the game ever loads. Every Bitmap control
        // then reports 0x0, and since the whole MAUI layout is expressed
        // relative to control sizes, each dialog collapses onto a single point.
        D3DXIMAGE_INFO sourceImageInfo;
        IDirect3DTexture9* sourceTexture;
        CheckD3DCall("DeviceD3D9.cpp", 779, [&] {
            return D3DXCreateTextureFromFileInMemoryEx(
                mDevice, sourceData, sourceBytes, D3DX_DEFAULT_NONPOW2, D3DX_DEFAULT_NONPOW2, 1U, 0U, D3DFMT_UNKNOWN,
                D3DPOOL_SYSTEMMEM, D3DX_FILTER_NONE, D3DX_FILTER_NONE, 0U, &sourceImageInfo, nullptr, &sourceTexture
            );
        });

        IDirect3DSurface9* surface;
        CheckD3DCall("DeviceD3D9.cpp", 782, [&] { return sourceTexture->GetSurfaceLevel(0U, &surface); });

        D3DSURFACE_DESC sourceDesc;
        CheckD3DCall("DeviceD3D9.cpp", 785, [&] { return surface->GetDesc(&sourceDesc); });

        // The size is the file's (D3DXIMAGE_INFO at [esp+0xA8], 0x008ECF58),
        // not the surface's ([esp+0xC4], only read for Format). D3DX pads a
        // DXT surface to a multiple of 4, so the surface of the 792x21 lobby
        // slot is 792x24, and every bitmap built from it came out 3 px too tall.
        *outWidth = sourceImageInfo.Width;
        *outHeight = static_cast<int>(sourceImageInfo.Height);

        // Anything that is not already DXT5 is converted through a DXT5
        // system-memory copy, which then stands in for the source surface.
        IDirect3DTexture9* decodeTexture = nullptr;
        if (sourceDesc.Format != D3DFMT_DXT5)
        {
            CheckD3DCall("DeviceD3D9.cpp", 801, [&] {
                return mDevice->CreateTexture(
                    AlignToDword(*outWidth), AlignToDword(static_cast<unsigned int>(*outHeight)), 1U, 0U, D3DFMT_DXT5,
                    D3DPOOL_SYSTEMMEM, &decodeTexture, nullptr
                );
            });

            IDirect3DSurface9* decodeSurface;
            CheckD3DCall("DeviceD3D9.cpp", 804, [&] { return decodeTexture->GetSurfaceLevel(0U, &decodeSurface); });
            CheckD3DCall("DeviceD3D9.cpp", 809, [&] {
                return D3DXLoadSurfaceFromSurface(
                    decodeSurface, nullptr, nullptr, surface, nullptr, nullptr, D3DX_FILTER_NONE, 0U
                );
            });

            surface->Release();
            surface = decodeSurface;
        }

        D3DLOCKED_RECT lockedRect;
        CheckD3DCall("DeviceD3D9.cpp", 817, [&] { return surface->LockRect(&lockedRect, nullptr, D3DLOCK_READONLY); });

        const unsigned int alignedWidth = AlignToDword(*outWidth);
        const unsigned int alignedHeight = AlignToDword(static_cast<unsigned int>(*outHeight));
        const std::size_t bytesPerRow = static_cast<std::size_t>(alignedWidth >> 2U) * 16U;
        const std::size_t rowCount = static_cast<std::size_t>(alignedHeight >> 2U);
        const std::size_t totalBytes = bytesPerRow * rowCount;

        if (outTextureData->Size() != totalBytes)
        {
            *outTextureData = gpg::AllocMemBuffer(totalBytes);
        }

        char* const destinationBytes = outTextureData->GetPtr(0U, 0U);
        const char* const sourceBytesPtr = static_cast<const char*>(lockedRect.pBits);
        if (static_cast<std::size_t>(lockedRect.Pitch) == bytesPerRow)
        {
            // Raw texture blob copy from the locked surface.
            std::copy_n(sourceBytesPtr, totalBytes, destinationBytes);
        }
        else
        {
            // Raw texture row blob copies from the locked, pitched surface.
            for (std::size_t rowIndex = 0; rowIndex < rowCount; ++rowIndex)
            {
                std::copy_n(
                    sourceBytesPtr + (rowIndex * static_cast<std::size_t>(lockedRect.Pitch)),
                    bytesPerRow,
                    destinationBytes + (rowIndex * bytesPerRow)
                );
            }
        }

        CheckD3DCall("DeviceD3D9.cpp", 833, [&] { return surface->UnlockRect(); });

        surface->Release();
        sourceTexture->Release();
        if (decodeTexture != nullptr)
        {
            decodeTexture->Release();
        }
    }

    /**
     * Address: 0x008ED360 (FUN_008ED360)
     *
     * What it does:
     * Probes cooperative-level state and maps D3D lost/reset status into
     * backend result tokens.
     */
    int DeviceD3D9::TestCooperativeLevel()
    {
        Func1();
        const HRESULT result = mDevice->TestCooperativeLevel();
        if (result == D3DERR_DEVICELOST)
        {
            return 2;
        }

        if (result == D3DERR_DEVICENOTRESET)
        {
            return 1;
        }

        if (result == 0)
        {
            return 0;
        }

        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 901, result);
        }

        return 2;
    }

    /**
     * Address: 0x008ED450 (FUN_008ED450)
     *
     * What it does:
     * Begins the native scene, then issues the frame event query
     * (`D3DISSUE_END`, the only flag an event query takes: `push 1` at
     * 0x008ED527). The recovered body issued `D3DISSUE_BEGIN`, which D3D9
     * rejects for event queries, and skipped the call when the query was
     * null; the binary does neither.
     */
    void DeviceD3D9::BeginScene()
    {
        Func1();
        const HRESULT result = mDevice->BeginScene();
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 913, result);
        }

        static_cast<void>(mFrameEventQuery->Issue(D3DISSUE_END));
    }

    /**
     * Address: 0x008ED550 (FUN_008ED550)
     *
     * What it does:
     * Ends one native D3D9 scene and throws on failure.
     */
    void DeviceD3D9::EndScene()
    {
        Func1();
        const HRESULT result = mDevice->EndScene();
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 926, result);
        }
    }

    /**
     * Address: 0x008ED640 (FUN_008ED640)
     *
     * What it does:
     * Drains the frame-event query to completion then presents one native frame.
     */
    void DeviceD3D9::Present()
    {
        Func1();
        IDirect3DQuery9* const frameEventQuery = mFrameEventQuery;
        while (frameEventQuery->GetData(nullptr, 0U, D3DGETDATA_FLUSH) == 1)
        {
        }

        const HRESULT result = mDevice->Present(nullptr, nullptr, nullptr, nullptr);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 937, result);
        }
    }

    /**
     * Address: 0x008ED750 (FUN_008ED750)
     *
     * CursorContext const *
     *
     * What it does:
     * Resolves one cursor texture level-0 surface and binds hotspot/surface cursor state.
     */
    void DeviceD3D9::SetCursor(const CursorContext* const context)
    {
        Func1();

        auto* const cursorTexture = static_cast<TextureD3D9*>(context->texture_.get());
        IDirect3DSurface9* cursorSurface = nullptr;
        HRESULT result = cursorTexture->GetTexture1()->GetSurfaceLevel(0U, &cursorSurface);
        if (FAILED(result))
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 949, result);
        }

        result = mDevice->SetCursorProperties(
            static_cast<UINT>(context->hotspotX_), static_cast<UINT>(context->hotspotY_), cursorSurface
        );
        if (FAILED(result))
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 952, result);
        }
        SafeRelease(cursorSurface);
    }

    /**
     * Address: 0x008ED910 (FUN_008ED910)
     *
     * void const *
     *
     * What it does:
     * Binds one viewport payload on the native D3D9 device.
     */
    void DeviceD3D9::SetViewport(const D3DVIEWPORT9* const viewport)
    {
        Func1();
        const HRESULT result = mDevice->SetViewport(viewport);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 973, result);
        }
    }

    /**
     * Address: 0x008EDA00 (FUN_008EDA00)
     *
     * void *
     *
     * What it does:
     * Reads one native viewport payload into caller-provided storage.
     */
    void DeviceD3D9::GetViewport(D3DVIEWPORT9* const outViewport)
    {
        Func1();
        const HRESULT result = mDevice->GetViewport(outViewport);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 981, result);
        }
    }

    /**
     * Address: 0x008EDAF0 (FUN_008EDAF0)
     *
     * OutputContext const *
     *
     * What it does:
     * Applies render-target/depth-stencil bindings from one output-context payload.
     */
    void DeviceD3D9::ClearTarget(const OutputContext* const context)
    {
        Func1();

        // The current target is only compared against, so its reference is
        // dropped at once (0x008EDB37) and the pointer kept as a value.
        IDirect3DSurface9* currentRenderTarget = nullptr;
        mDevice->GetRenderTarget(0U, &currentRenderTarget);
        if (currentRenderTarget != nullptr)
        {
            currentRenderTarget->Release();
        }

        if (context->surface.get() != nullptr)
        {
            IDirect3DSurface9* const targetSurface = static_cast<RenderTargetD3D9*>(context->surface.get())->GetSurface();
            if (currentRenderTarget != targetSurface)
            {
                const HRESULT setResult = mDevice->SetRenderTarget(0U, targetSurface);
                if (setResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1004, setResult);
                }
            }
        }
        else if (context->cubeTarget.get() != nullptr)
        {
            IDirect3DSurface9* const targetSurface =
                static_cast<CubeRenderTargetD3D9*>(context->cubeTarget.get())->GetSurface(context->face);
            if (currentRenderTarget != targetSurface)
            {
                const HRESULT setResult = mDevice->SetRenderTarget(0U, targetSurface);
                if (setResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1017, setResult);
                }
            }
        }
        else if (currentRenderTarget != nullptr)
        {
            const HRESULT setResult = mDevice->SetRenderTarget(0U, nullptr);
            if (setResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1024, setResult);
            }
        }

        IDirect3DSurface9* currentDepthStencilSurface = nullptr;
        mDevice->GetDepthStencilSurface(&currentDepthStencilSurface);
        if (currentDepthStencilSurface != nullptr)
        {
            currentDepthStencilSurface->Release();
        }

        if (context->depthStencil.get() != nullptr)
        {
            IDirect3DSurface9* const depthStencilSurface =
                static_cast<DepthStencilTargetD3D9*>(context->depthStencil.get())->GetSurface();
            if (currentDepthStencilSurface != depthStencilSurface)
            {
                const HRESULT setResult = mDevice->SetDepthStencilSurface(depthStencilSurface);
                if (setResult < 0)
                {
                    ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1043, setResult);
                }
            }
        }
        else if (currentDepthStencilSurface != nullptr)
        {
            const HRESULT setResult = mDevice->SetDepthStencilSurface(nullptr);
            if (setResult < 0)
            {
                ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1049, setResult);
            }
        }
    }

    /**
     * Address: 0x008EDE30 (FUN_008EDE30)
     *
     * bool,bool,bool,std::uint32_t,float,int
     *
     * What it does:
     * Builds native clear mask bits from caller booleans and dispatches one D3D clear.
     */
    void DeviceD3D9::Clear(
        const bool clearTarget,
        const bool clearZbuffer,
        const bool clearStencil,
        const std::uint32_t color,
        const float depth,
        const int stencil
    )
    {
        Func1();
        if (!clearTarget && !clearZbuffer && !clearStencil)
        {
            return;
        }

        unsigned int clearMask = 0U;
        if (clearTarget)
        {
            clearMask |= D3DCLEAR_TARGET;
        }
        if (clearZbuffer)
        {
            clearMask |= D3DCLEAR_ZBUFFER;
        }
        if (clearStencil)
        {
            clearMask |= D3DCLEAR_STENCIL;
        }

        const HRESULT result = mDevice->Clear(0U, nullptr, clearMask, color, depth, static_cast<unsigned int>(stencil));
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1066, result);
        }
    }

    /**
     * Address: 0x008EDF70 (FUN_008EDF70)
     *
     * What it does:
     * Binds `vertexFormat`'s declaration on the device. The declaration comes
     * through `VertexFormatD3D9::GetDeclaration` (0x008EDFAC), which throws
     * "invalid vertex format" when it is unset.
     */
    void DeviceD3D9::SetVertexDeclaration(const boost::shared_ptr<VertexFormat> vertexFormat)
    {
        Func1();
        const HRESULT result = mDevice->SetVertexDeclaration(static_cast<VertexFormatD3D9*>(vertexFormat.get())->GetDeclaration());
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1082, result);
        }
        RecordStateChange(); // FAF instrumentation (gpg/gal/DrawStatistics.h); not in the binary.
    }

    /**
     * Address: 0x008EE0B0 (FUN_008EE0B0)
     *
     * What it does:
     * Binds `vertexBuffer` on stream `streamSlot`, starting `startVertex`
     * vertices in, then sets the stream frequency from the buffer's type:
     * type 2 (geometry) repeats every `streamFrequencyToken` instances,
     * type 3 (per-instance) advances once per instance. The stride comes from
     * the buffer's context (virtual `GetContext`, 0x008EE0EF) and the native
     * buffer through `VertexBufferD3D9::GetD3D` (0x008EE10E), which throws
     * when it is unset.
     */
    void DeviceD3D9::SetVertexBuffer(
        const std::uint32_t streamSlot,
        const boost::shared_ptr<VertexBuffer> vertexBuffer,
        const int streamFrequencyToken,
        const int startVertex
    )
    {
        Func1();

        VertexBufferContext* const vertexContext = vertexBuffer->GetContext();
        const unsigned int stride = vertexContext->stride_;
        const unsigned int offsetInBytes = static_cast<unsigned int>(startVertex) * stride;
        const HRESULT setStreamResult = mDevice->SetStreamSource(streamSlot, static_cast<VertexBufferD3D9*>(vertexBuffer.get())->GetD3D(), offsetInBytes, stride);
        if (setStreamResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1093, setStreamResult);
        }

        unsigned int frequencySetting = 1U;
        if (vertexContext->type_ == 2U)
        {
            frequencySetting = static_cast<unsigned int>(streamFrequencyToken) | D3DSTREAMSOURCE_INDEXEDDATA;
        }
        else if (vertexContext->type_ == 3U)
        {
            frequencySetting = D3DSTREAMSOURCE_INSTANCEDATA | 1U;
        }

        const HRESULT setFrequencyResult = mDevice->SetStreamSourceFreq(streamSlot, frequencySetting);
        if (setFrequencyResult < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1102, setFrequencyResult);
        }
        RecordStateChange(); // FAF instrumentation (gpg/gal/DrawStatistics.h); not in the binary.
    }

    /**
     * Address: 0x008EE2E0 (FUN_008EE2E0)
     *
     * What it does:
     * Binds `indexBuffer` as the device's index source. The native buffer
     * comes through `IndexBufferD3D9::GetBuffer` (0x008EE31C), which throws
     * "invalid index buffer" when it is unset.
     */
    void DeviceD3D9::SetBufferIndices(const boost::shared_ptr<IndexBuffer> indexBuffer)
    {
        Func1();

        const HRESULT result =
            mDevice->SetIndices(static_cast<IndexBufferD3D9*>(indexBuffer.get())->GetBuffer());
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1112, result);
        }
        RecordStateChange(); // FAF instrumentation (gpg/gal/DrawStatistics.h); not in the binary.
    }

    /**
     * Address: 0x008EE420 (FUN_008EE420)
     *
     * bool,void const *,float,float,int
     *
     * What it does:
     * Validates retained pipeline state then forwards one fog-state payload.
     */
    void DeviceD3D9::SetFogState(
        const bool enable,
        const Matrix* const projection,
        const float fogStart,
        const float fogEnd,
        const int fogColor
    )
    {
        Func1();

        PipelineStateD3D9* const pipelineState = mPipelineState.get();
        if (pipelineState == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 1120, "unable to set distance fog state, invalid pipeline state");
        }

        pipelineState->SetFogState(enable, projection, fogStart, fogEnd, fogColor);
    }

    /**
     * Address: 0x008EE510 (FUN_008EE510)
     *
     * bool
     *
     * What it does:
     * Validates retained pipeline state and applies recovered wireframe fill mode.
     */
    void DeviceD3D9::SetWireframeState(const bool enabled)
    {
        Func1();

        PipelineStateD3D9* const pipelineState = mPipelineState.get();
        if (pipelineState == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 1130, "unable to set wireframe state, invalid pipeline state");
        }

        static_cast<void>(pipelineState->SetWireframeState(enabled));
    }

    /**
     * Address: 0x008EE5E0 (FUN_008EE5E0)
     *
     * bool,bool
     *
     * What it does:
     * Validates retained pipeline state and applies recovered color-write mask.
     */
    void DeviceD3D9::SetColorWriteState(const bool writeColor, const bool writeAlpha)
    {
        Func1();

        PipelineStateD3D9* const pipelineState = mPipelineState.get();
        if (pipelineState == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 1140, "unable to set color write state, invalid pipeline state");
        }

        static_cast<void>(pipelineState->SetColorWriteState(writeColor, writeAlpha));
    }

    /**
     * Address: 0x008EE6B0 (FUN_008EE6B0)
     *
     * What it does:
     * Validates the topology and issues one non-indexed draw, converting the
     * context's vertex count into a primitive count.
     */
    void DeviceD3D9::DrawPrimitive(const DrawContext* const context)
    {
        Func1();

        if (context->topology_ == 0)
        {
            ThrowGalError("DeviceD3D9.cpp", 1149, "invalid topology specified");
        }

        const D3DPRIMITIVETYPE primitiveType = kTopologyPrimitiveTypes[context->topology_];
        const std::uint32_t primitiveCount = context->GetPrimitiveCount();
        const HRESULT result = mDevice->DrawPrimitive(primitiveType, context->startVertex_, primitiveCount);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1152, result);
        }

        // FAF instrumentation (see gpg/gal/DrawStatistics.h); not in the binary.
        RecordDraw(primitiveCount, context->vertexCount_);
    }

    /**
     * Address: 0x008EE850 (FUN_008EE850)
     *
     * What it does:
     * Validates the topology and issues one indexed draw, converting the
     * context's index count into a primitive count.
     */
    void DeviceD3D9::DrawIndexedPrimitive(const DrawIndexedContext* const context)
    {
        Func1();

        if (context->topology_ == 0)
        {
            ThrowGalError("DeviceD3D9.cpp", 1159, "invalid topology specified");
        }

        const D3DPRIMITIVETYPE primitiveType = kTopologyPrimitiveTypes[context->topology_];
        const std::uint32_t primitiveCount = context->GetPrimitiveCount();
        const HRESULT result = mDevice->DrawIndexedPrimitive(
            primitiveType,
            context->baseVertexIndex_,
            context->minVertexIndex_,
            context->vertexCount_,
            context->startIndex_,
            primitiveCount
        );
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1162, result);
        }

        // FAF instrumentation (see gpg/gal/DrawStatistics.h); not in the binary.
        RecordDraw(primitiveCount, context->vertexCount_);
    }

    /**
     * Address: 0x008EEA00 (FUN_008EEA00)
     *
     * What it does:
     * Validates retained pipeline state then forwards begin-technique state setup.
     */
    void DeviceD3D9::BeginTechnique()
    {
        Func1();

        PipelineStateD3D9* const pipelineState = mPipelineState.get();
        if (pipelineState == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 1170, "unable to begin technique, invalid pipeline state");
        }

        pipelineState->BeginTechnique();
    }

    /**
     * Address: 0x008EEAC0 (FUN_008EEAC0)
     *
     * What it does:
     * Validates retained pipeline state then forwards end-technique cleanup.
     */
    void DeviceD3D9::EndTechnique()
    {
        Func1();

        PipelineStateD3D9* const pipelineState = mPipelineState.get();
        if (pipelineState == nullptr)
        {
            ThrowGalError("DeviceD3D9.cpp", 1180, "unable to end technique, invalid pipeline state");
        }

        pipelineState->EndTechnique();
    }

    /**
     * Address: 0x008E8EE0 (FUN_008E8EE0)
     *
     * What it does:
     * Dispatches `Func1` pre-hook then clears bound textures through pipeline-state helper.
     */
    void DeviceD3D9::ClearTextures()
    {
        Func1();
        static_cast<void>(mPipelineState->ClearTextures());
    }
}

