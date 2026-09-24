#include "AdapterD3D9.hpp"
#include "AdapterModeD3D9.hpp"
#include "CubeRenderTargetD3D9.hpp"
#include "DepthStencilTargetD3D9.hpp"
#include "DeviceD3D9.hpp"
#include "EffectD3D9.hpp"
#include "EffectTechniqueD3D9.hpp"
#include "EffectVariableD3D9.hpp"
#include "Float16HardwareVertexFormatterD3D9.hpp"
#include "HardwareVertexFormatterD3D9.hpp"
#include "IndexBufferD3D9.hpp"
#include "PipelineStateD3D9.hpp"
#include "RenderTargetD3D9.hpp"
#include "StateManagerD3D9.hpp"
#include "TextureD3D9.hpp"
#include "VertexBufferD3D9.hpp"
#include "VertexFormatD3D9.hpp"

#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/core/utils/Logging.h" // TEMPORARY PROBE (do not commit)
#include "gpg/gal/EffectMacro.hpp"
#include "gpg/gal/EffectTechnique.hpp"
#include "gpg/gal/CubeRenderTarget.hpp"
#include "gpg/gal/IndexBuffer.hpp"
#include "gpg/gal/Head.hpp"
#include "gpg/gal/PipelineState.hpp"
#include "gpg/gal/RenderTarget.hpp"
#include "gpg/gal/CursorContext.hpp"
#include "gpg/gal/DrawIndexedContext.hpp"
#include "gpg/gal/OutputContext.hpp"

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/core/utils/BoostWrappers.h"

#include <d3d9.h>
#include <d3dx9.h>

#include <bit>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <new>
#include <stdexcept>
#include <utility>
#include <vector>

namespace gpg::gal
{
// TEMPORARY PROBE (do not commit): current technique name for the state-manager log.
char gProbeCurrentTechnique[64] = {}; // already inside namespace gpg::gal
int gProbeFrameSeq = 0; int gProbeFrameDiagLeft = 0; // TEMPORARY PROBE (do not commit)
extern "C" int FafProbeFrameSeq() { return gProbeFrameSeq; }
extern "C" int FafProbeFrameDiag() { return gProbeFrameDiagLeft; }
namespace { // TEMPORARY PROBE (do not commit)
    bool ProbeTexSetArmed()
    {
        static unsigned sCalls = 0; static bool sArmed = false;
        if ((sCalls++ % 256u) == 0u) {
            char dir[512] = {}; std::size_t length = 0; sArmed = false;
            if (::getenv_s(&length, dir, sizeof(dir), "FAF_TOGGLE_DIR") == 0 && length != 0u) {
                char path[600]; (void)std::snprintf(path, sizeof(path), "%s/statediag.on", dir);
                sArmed = ::GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
            }
        }
        return sArmed;
    }
    int gProbeTexSetBudget = 300;
}

    /**
     * Address: 0x008F3820 (FUN_008F3820)
     *
     * What it does:
     * Installs the abstract technique vtable.
     */
    EffectTechnique::EffectTechnique() = default;

    /**
     * Address: 0x008F3810 (FUN_008F3810)
     *
     * What it does:
     * Reinstalls the abstract technique vtable (`mov [ecx], 0x00D42CA0;
     * ret`). Both backend destructors inline it; this out-of-line copy is
     * what the backend constructors' unwind funclets jump to (0x00B5A083,
     * 0x00B5A0AE, 0x00B5B453, 0x00B5B476).
     */
    EffectTechnique::~EffectTechnique() = default;

    /**
     * Address: 0x008F4B80 (FUN_008F4B80)
     *
     * What it does:
     * Installs the abstract index-buffer vtable.
     */
    IndexBuffer::IndexBuffer() = default;

    /**
     * Address: 0x008F4B70
     *
     * What it does:
     * Reinstalls the abstract index-buffer vtable (`mov [ecx], 0x00D42D98;
     * ret`). Both backend destructors inline it; this out-of-line copy is for
     * their unwind paths, and IDA never boxed it as a function.
     */
    IndexBuffer::~IndexBuffer() = default;

    /**
     * Address: 0x008F5250 (FUN_008F5250)
     *
     * What it does:
     * Installs the abstract render-target vtable.
     */
    RenderTarget::RenderTarget() = default;

    /**
     * What it does:
     * Reinstalls the abstract render-target vtable. Both derived destructors
     * inline it (0x008F53F1, 0x00902EF1).
     */
    RenderTarget::~RenderTarget() = default;

    /**
     * Address: 0x008F7F20 (FUN_008F7F20)
     *
     * What it does:
     * Installs the abstract cube-render-target vtable.
     */
    CubeRenderTarget::CubeRenderTarget() = default;

    /**
     * What it does:
     * Reinstalls the abstract cube-render-target vtable. The derived
     * destructors inline it (0x008F8068 in `CubeRenderTargetD3D10`).
     */
    CubeRenderTarget::~CubeRenderTarget() = default;

    /**
     * Address: 0x00902240 (FUN_00902240)
     *
     * What it does:
     * Installs the abstract pipeline-state vtable and returns `this`. Both
     * backend constructors inline it.
     */
    PipelineState::PipelineState() = default;

    /**
     * Address: 0x00902230 (FUN_00902230)
     *
     * What it does:
     * Reinstalls the abstract pipeline-state vtable (`mov [ecx], 0x00D436F0;
     * ret` - no `this` in eax, so this is the destructor, not the constructor
     * it used to be annotated as). Called from both backends' pipeline-state
     * constructor unwind paths and destructors (0x00949F80 and 0x00946BE0 on
     * D3D9, 0x00902CA0 and 0x009023F0 on D3D10).
     */
    PipelineState::~PipelineState() = default;

    // Mesh-batching hardware capability flags. Console-settable (see
    // `Moho::CON_mesh_Rebatch`, moho/console/CConCommand.cpp), which writes
    // these two bytes directly rather than through an accessor - so they need
    // external linkage rather than living in the anonymous namespace below.
    // No owning header exists for this backend TU yet; the consumer declares
    // them `extern` locally where it writes them.
    std::uint8_t sMeshAllowFloat16 = 1U;
    std::uint8_t sMeshAllowInstancing = 1U;

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
        constexpr int kCubeFaceCount = 6;
        constexpr unsigned int kCubeFaceByIndex[kCubeFaceCount] = {
            0U,
            1U,
            2U,
            3U,
            4U,
            5U,
        };
        constexpr std::uint32_t kFloat16VertexStrideTableDefault[2] = {0x2CU, 0x44U};  // Address: 0x00F3275C
        constexpr std::uint32_t kFloat16VertexStrideTableCompact[2] = {0x2CU, 0x08U}; // Address: 0x00F32764
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

        /**
         * Address: 0x00941280 (FUN_00941280)
         *
         * What it does:
         * Maps one cube-face index (`0..5`) to the backend D3D9 face token.
         */
        [[nodiscard]] int ResolveD3D9CubeFaceToken(const int faceIndex) noexcept
        {
            return static_cast<int>(kCubeFaceByIndex[faceIndex]);
        }

        msvc8::vector<msvc8::string> gD3D9LogStorage{};

        /**
         * Address: 0x0094ABF0 (FUN_0094ABF0)
         *
         * What it does:
         * Maps one D3D declaration type token to the element byte-width used
         * when accumulating stream strides.
         */
        [[nodiscard]] std::uint32_t GetVertexElementTypeSizeBytes(const std::uint8_t elementType) noexcept
        {
            switch (elementType)
            {
            case 0U:
            case 4U:
            case 5U:
            case 6U:
            case 8U:
            case 9U:
            case 11U:
            case 13U:
            case 14U:
            case 15U:
                return 4U;
            case 1U:
            case 7U:
            case 10U:
            case 12U:
            case 16U:
                return 8U;
            case 2U:
                return 12U;
            case 3U:
                return 16U;
            default:
                return 0U;
            }
        }

        /**
         * The active backend device whenever any D3D9 body in this file runs.
         *
         * These bodies reach `Device::GetInstance()`, which is typed as the
         * abstract base. The methods they need (`GetPipelineState`,
         * `CreateVertexFormat`, ...) are declared only on `DeviceD3D9`, so the
         * call has to go through the backend type. This used to be done by
         * hand-indexing the vtable (`vtable[8]`, `vtable[14]`, ...), which was
         * doubly wrong: the base declares those slots as no-arg `purecallN()`
         * stubs, so the backend methods never actually override them - the
         * compiler appends them past the base's 50 slots and the stub still
         * sits at the indexed position. Dispatching `vtable[8]` therefore
         * called an empty `void purecall8()`: the output parameter was left
         * untouched, and because a `__thiscall` callee pops its own arguments,
         * the no-arg stub popped 0 bytes where the caller pushed 4 and the
         * debug CRT's `_RTC_CheckEsp` trapped on return.
         *
         * `Device::InitCursor` (Device.cpp) resolves the same problem the same
         * way. See the note on `Device::CreateEffect` for the one slot whose
         * signature was hoisted onto the base instead.
         */
        [[nodiscard]] DeviceD3D9& ActiveDeviceD3D9()
        {
            return *static_cast<DeviceD3D9*>(Device::GetInstance());
        }

        struct DwordPairRuntime final
        {
            std::uint32_t lane0 = 0U;
            std::uint32_t lane1 = 0U;
        };
        static_assert(sizeof(DwordPairRuntime) == 0x08, "DwordPairRuntime size must be 0x08");

        struct DwordTripleRuntime final
        {
            std::uint32_t lane0 = 0U;
            std::uint32_t lane1 = 0U;
            std::uint32_t lane2 = 0U;
        };
        static_assert(sizeof(DwordTripleRuntime) == 0x0C, "DwordTripleRuntime size must be 0x0C");

        struct DwordHeptRuntime final
        {
            std::uint32_t lanes[7]{};
        };
        static_assert(sizeof(DwordHeptRuntime) == 0x1C, "DwordHeptRuntime size must be 0x1C");

        /**
         * Address: 0x008E9FD0 (FUN_008E9FD0)
         *
         * What it does:
         * Copies one half-open 12-byte lane range backward from
         * `[sourceBegin, sourceEnd)` into storage ending at `destinationEnd`.
         */
        [[nodiscard]] DwordTripleRuntime* CopyDwordTripleRangeBackwardD3D9(
            const DwordTripleRuntime* const sourceBegin,
            const DwordTripleRuntime* sourceEnd,
            DwordTripleRuntime* destinationEnd
        ) noexcept
        {
            while (sourceEnd != sourceBegin)
            {
                --sourceEnd;
                --destinationEnd;
                *destinationEnd = *sourceEnd;
            }

            return destinationEnd;
        }

        /**
         * Address: 0x008EA000 (FUN_008EA000)
         *
         * What it does:
         * Copies one half-open dword range backward from `[sourceBegin,
         * sourceEnd)` into storage ending at `destinationEnd`.
         */
        [[nodiscard]] std::uint32_t* CopyDwordRangeBackwardD3D9A(
            const std::uint32_t* const sourceBegin,
            const std::uint32_t* sourceEnd,
            std::uint32_t* destinationEnd
        ) noexcept
        {
            while (sourceEnd != sourceBegin)
            {
                --sourceEnd;
                --destinationEnd;
                *destinationEnd = *sourceEnd;
            }

            return destinationEnd;
        }

        /**
         * Address: 0x008EA030 (FUN_008EA030)
         *
         * What it does:
         * Alias lane of `CopyDwordRangeBackwardD3D9A`.
         */
        [[nodiscard]] std::uint32_t* CopyDwordRangeBackwardD3D9B(
            const std::uint32_t* const sourceBegin,
            const std::uint32_t* const sourceEnd,
            std::uint32_t* const destinationEnd
        ) noexcept
        {
            return CopyDwordRangeBackwardD3D9A(sourceBegin, sourceEnd, destinationEnd);
        }

        /**
         * Address: 0x008F6580 (FUN_008F6580)
         *
         * What it does:
         * Copies one half-open 28-byte lane range backward from
         * `[sourceBegin, sourceEnd)` into storage ending at `destinationEnd`.
         */
        [[nodiscard]] DwordHeptRuntime* CopyDwordHeptRangeBackwardD3D9(
            const DwordHeptRuntime* const sourceBegin,
            const DwordHeptRuntime* sourceEnd,
            DwordHeptRuntime* destinationEnd
        ) noexcept
        {
            while (sourceEnd != sourceBegin)
            {
                --sourceEnd;
                --destinationEnd;
                *destinationEnd = *sourceEnd;
            }

            return destinationEnd;
        }

        [[nodiscard]] std::uint32_t* FillDwordRangeWithSourceLaneCore(
            std::uint32_t* destination,
            int count,
            const std::uint32_t* const sourceLane
        ) noexcept
        {
            for (int remaining = count; remaining != 0; --remaining, ++destination)
            {
                if (destination != nullptr)
                {
                    *destination = *sourceLane;
                }
            }
            return destination;
        }

        /**
         * Address: 0x008EA0D0 (FUN_008EA0D0)
         *
         * What it does:
         * Writes one repeated dword source lane into `count` consecutive dword
         * destination slots.
         */
        void FillDwordRangeWithSourceLaneDispatchA(
            std::uint32_t* const destination,
            const int count,
            const std::uint32_t* const sourceLane
        ) noexcept
        {
            (void)FillDwordRangeWithSourceLaneCore(destination, count, sourceLane);
        }

        /**
         * Address: 0x008EA2F0 (FUN_008EA2F0)
         *
         * What it does:
         * Adapter lane forwarding one repeated dword fill request to
         * `FillDwordRangeWithSourceLaneDispatchA`.
         */
        void FillDwordRangeWithSourceLaneDispatchAAdapter(
            std::uint32_t* const destination,
            const int count,
            const std::uint32_t* const sourceLane
        ) noexcept
        {
            FillDwordRangeWithSourceLaneDispatchA(destination, count, sourceLane);
        }

        /**
         * Address: 0x008EA540 (FUN_008EA540)
         *
         * What it does:
         * Dispatches one repeated dword fill lane through
         * `FillDwordRangeWithSourceLaneDispatchA` and returns one-past-end
         * destination cursor.
         */
        [[nodiscard]] std::uint32_t* FillDwordRangeWithSourceLaneDispatchAAndReturnEnd(
            std::uint32_t* const destination,
            const int count,
            const std::uint32_t* const sourceLane
        ) noexcept
        {
            FillDwordRangeWithSourceLaneDispatchA(destination, count, sourceLane);
            const auto destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
            const auto byteAdvance = static_cast<std::uintptr_t>(count) * sizeof(std::uint32_t);
            return reinterpret_cast<std::uint32_t*>(destinationAddress + byteAdvance);
        }

        /**
         * Address: 0x008EA100 (FUN_008EA100)
         *
         * What it does:
         * Dispatch alias for the repeated dword fill lane used by adjacent D3D9
         * capability/setup helper chains.
         */
        void FillDwordRangeWithSourceLaneDispatchB(
            std::uint32_t* const destination,
            const int count,
            const std::uint32_t* const sourceLane
        ) noexcept
        {
            (void)FillDwordRangeWithSourceLaneCore(destination, count, sourceLane);
        }

        /**
         * Address: 0x008EA320 (FUN_008EA320)
         *
         * What it does:
         * Adapter lane forwarding one repeated dword fill request to
         * `FillDwordRangeWithSourceLaneDispatchB`.
         */
        void FillDwordRangeWithSourceLaneDispatchBAdapter(
            std::uint32_t* const destination,
            const int count,
            const std::uint32_t* const sourceLane
        ) noexcept
        {
            FillDwordRangeWithSourceLaneDispatchB(destination, count, sourceLane);
        }

        /**
         * Address: 0x008EA580 (FUN_008EA580)
         *
         * What it does:
         * Dispatches one repeated dword fill lane through
         * `FillDwordRangeWithSourceLaneDispatchB` and returns one-past-end
         * destination cursor.
         */
        [[nodiscard]] std::uint32_t* FillDwordRangeWithSourceLaneDispatchBAndReturnEnd(
            std::uint32_t* const destination,
            const int count,
            const std::uint32_t* const sourceLane
        ) noexcept
        {
            FillDwordRangeWithSourceLaneDispatchB(destination, count, sourceLane);
            const auto destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
            const auto byteAdvance = static_cast<std::uintptr_t>(count) * sizeof(std::uint32_t);
            return reinterpret_cast<std::uint32_t*>(destinationAddress + byteAdvance);
        }

        struct PackedAdapterModeRuntime final
        {
            std::uint32_t vftable = 0U; // +0x00
            std::uint32_t width = 0U;   // +0x04
            std::uint32_t height = 0U;  // +0x08
            std::uint32_t refresh = 0U; // +0x0C
        };

        static_assert(sizeof(PackedAdapterModeRuntime) == 0x10, "PackedAdapterModeRuntime size must be 0x10");

        /**
         * Address: 0x008EA190 (FUN_008EA190)
         *
         * What it does:
         * Copies one packed adapter-mode tail range (`width/height/refresh`)
         * over `[sourceFirst, sourceLast)` into destination slots and returns
         * one-past the final destination element.
         */
        PackedAdapterModeRuntime* CopyPackedAdapterModeTailRange(
            const PackedAdapterModeRuntime* sourceFirst,
            const PackedAdapterModeRuntime* sourceLast,
            PackedAdapterModeRuntime* destinationFirst
        ) noexcept
        {
            const PackedAdapterModeRuntime* read = sourceFirst;
            PackedAdapterModeRuntime* write = destinationFirst;
            while (read != sourceLast)
            {
                write->width = read->width;
                write->height = read->height;
                write->refresh = read->refresh;
                ++read;
                ++write;
            }

            return write;
        }

        /**
         * Address: 0x00940A80 (FUN_00940A80)
         *
         * What it does:
         * Copies one packed adapter-mode tail range (`width/height/refresh`)
         * backward from `[sourceBegin, sourceEnd)` into storage ending at
         * `destinationEnd`, then returns the updated destination begin lane.
         */
        [[nodiscard]] PackedAdapterModeRuntime* CopyPackedAdapterModeTailRangeBackward(
            const PackedAdapterModeRuntime* const sourceBegin,
            const PackedAdapterModeRuntime* sourceEnd,
            PackedAdapterModeRuntime* destinationEnd
        ) noexcept
        {
            while (sourceEnd != sourceBegin)
            {
                --destinationEnd;
                --sourceEnd;
                destinationEnd->width = sourceEnd->width;
                destinationEnd->height = sourceEnd->height;
                destinationEnd->refresh = sourceEnd->refresh;
            }

            return destinationEnd;
        }

        /**
         * Address: 0x008EA210 (FUN_008EA210)
         * Address: 0x00940C60 (FUN_00940C60)
         *
         * What it does:
         * Copy-constructs one half-open `AdapterModeD3D9` range into caller
         * storage and returns one-past-last destination slot.
         */
        [[nodiscard]] AdapterModeD3D9* CopyAdapterModeRange(
            AdapterModeD3D9* const destinationBegin,
            const AdapterModeD3D9* sourceBegin,
            const AdapterModeD3D9* sourceEnd
        )
        {
            std::uintptr_t destinationCursor = reinterpret_cast<std::uintptr_t>(destinationBegin);
            for (const AdapterModeD3D9* sourceCursor = sourceBegin;
                 sourceCursor != sourceEnd;
                 ++sourceCursor, destinationCursor += sizeof(AdapterModeD3D9))
            {
                if (destinationCursor == 0U)
                {
                    continue;
                }

                auto* const destination = reinterpret_cast<AdapterModeD3D9*>(destinationCursor);
                ::new (static_cast<void*>(destination)) AdapterModeD3D9(
                    sourceCursor->width_,
                    sourceCursor->height_,
                    sourceCursor->refreshRate_
                );
            }

            return reinterpret_cast<AdapterModeD3D9*>(destinationCursor);
        }

        /**
         * Address: 0x008EA4D0 (FUN_008EA4D0)
         *
         * What it does:
         * Adapter lane forwarding one `AdapterModeD3D9` copy-range request to
         * `CopyAdapterModeRange`.
         */
        [[nodiscard]] AdapterModeD3D9* CopyAdapterModeRangeAdapter(
            AdapterModeD3D9* const destinationBegin,
            const AdapterModeD3D9* sourceBegin,
            const AdapterModeD3D9* sourceEnd
        )
        {
            return CopyAdapterModeRange(destinationBegin, sourceBegin, sourceEnd);
        }

        /**
         * Address: 0x008EA750 (FUN_008EA750)
         *
         * What it does:
         * Dispatch alias lane for `CopyAdapterModeRange`.
         */
        [[nodiscard]] AdapterModeD3D9* CopyAdapterModeRangeDispatch(
            AdapterModeD3D9* const destinationBegin,
            const AdapterModeD3D9* sourceBegin,
            const AdapterModeD3D9* sourceEnd
        )
        {
            return CopyAdapterModeRange(destinationBegin, sourceBegin, sourceEnd);
        }

        /**
         * Address: 0x00940BD0 (FUN_00940BD0)
         *
         * What it does:
         * Dispatch alias lane for `CopyAdapterModeRange`.
         */
        [[nodiscard]] AdapterModeD3D9* CopyAdapterModeRangeDispatchB(
            AdapterModeD3D9* const destinationBegin,
            const AdapterModeD3D9* sourceBegin,
            const AdapterModeD3D9* sourceEnd
        )
        {
            return CopyAdapterModeRange(destinationBegin, sourceBegin, sourceEnd);
        }

        /**
         * Address: 0x00940C30 (FUN_00940C30)
         *
         * What it does:
         * Legacy cdecl adapter lane that forwards one adapter-mode range copy
         * request to `CopyAdapterModeRange`.
         */
        [[nodiscard]] AdapterModeD3D9* CopyAdapterModeRangeDispatchLegacyLaneA(
            AdapterModeD3D9* const destinationBegin,
            const AdapterModeD3D9* sourceBegin,
            const AdapterModeD3D9* sourceEnd
        )
        {
            return CopyAdapterModeRange(destinationBegin, sourceBegin, sourceEnd);
        }

        /**
         * Address: 0x008EA490 (FUN_008EA490)
         *
         * What it does:
         * Copies one packed adapter-mode range (`4 dwords` stride) into
         * destination storage and rebinds `AdapterModeD3D9` vtable ownership.
         */
        [[nodiscard]] std::uint32_t* CopyPackedAdapterModeRangeRuntime(
            const std::uint32_t* sourceBegin,
            const std::uint32_t* sourceEnd,
            std::uint32_t* destinationBegin
        )
        {
            const std::uint32_t* sourceCursor = sourceBegin;
            std::uint32_t* destinationCursor = destinationBegin;

            while (sourceCursor != sourceEnd)
            {
                if (destinationCursor != nullptr)
                {
                    auto* const destinationMode = reinterpret_cast<AdapterModeD3D9*>(destinationCursor);
                    ::new (static_cast<void*>(destinationMode))
                        AdapterModeD3D9(sourceCursor[1], sourceCursor[2], sourceCursor[3]);
                }

                sourceCursor += 4;
                if (destinationCursor != nullptr)
                {
                    destinationCursor += 4;
                }
            }

            return destinationCursor;
        }

        /**
         * Address: 0x008EA6C0 (FUN_008EA6C0)
         *
         * What it does:
         * Cdecl adapter lane forwarding one packed adapter-mode copy-range
         * request to `CopyPackedAdapterModeRangeRuntime`.
         */
        [[nodiscard]] std::uint32_t* CopyPackedAdapterModeRangeRuntimeAdapterA(
            const std::uint32_t* sourceBegin,
            const std::uint32_t* sourceEnd,
            std::uint32_t* destinationBegin
        )
        {
            return CopyPackedAdapterModeRangeRuntime(sourceBegin, sourceEnd, destinationBegin);
        }

        /**
         * Address: 0x008EA8B0 (FUN_008EA8B0)
         *
         * What it does:
         * Stdcall adapter lane forwarding one packed adapter-mode copy-range
         * request to `CopyPackedAdapterModeRangeRuntime`.
         */
        [[nodiscard]] std::uint32_t* CopyPackedAdapterModeRangeRuntimeAdapterB(
            const std::uint32_t* sourceBegin,
            const std::uint32_t* sourceEnd,
            std::uint32_t* destinationBegin
        )
        {
            return CopyPackedAdapterModeRangeRuntime(sourceBegin, sourceEnd, destinationBegin);
        }

        /**
         * Address: 0x00940AF0 (FUN_00940AF0)
         *
         * What it does:
         * Writes one packed adapter-mode payload range (`+0x04/+0x08/+0x0C`
         * dwords per 16-byte lane) from one fixed source mode.
         */
        [[nodiscard]] std::uint32_t* CopyPackedAdapterModePayloadRangeRuntime(
            std::uint32_t* destinationBegin,
            std::uint32_t* const destinationEnd,
            const std::uint32_t* const sourceMode
        )
        {
            std::uint32_t* result = destinationBegin;
            if (destinationBegin != destinationEnd)
            {
                result = destinationBegin + 2;
                do
                {
                    result[-1] = sourceMode[1];
                    result[0] = sourceMode[2];
                    result[1] = sourceMode[3];
                    result += 4;
                } while (result - 2 != destinationEnd);
            }
            return result;
        }

        /**
         * Address: 0x00940B60 (FUN_00940B60)
         *
         * What it does:
         * Fills `count` packed adapter-mode slots (`4 dwords` stride) from one
         * source mode payload and rebinds `AdapterModeD3D9` vtable ownership.
         */
        void FillPackedAdapterModeRangeRuntime(
            std::uint32_t* destinationBegin,
            std::uint32_t count,
            const std::uint32_t* const sourceMode
        )
        {
            while (count != 0U)
            {
                if (destinationBegin != nullptr && sourceMode != nullptr)
                {
                    auto* const destinationMode = reinterpret_cast<AdapterModeD3D9*>(destinationBegin);
                    ::new (static_cast<void*>(destinationMode))
                        AdapterModeD3D9(sourceMode[1], sourceMode[2], sourceMode[3]);
                    destinationBegin += 4;
                }
                --count;
            }
        }

        /**
         * Address: 0x00940BA0 (FUN_00940BA0)
         *
         * What it does:
         * Dispatch alias lane for packed adapter-mode fill behavior.
         */
        void FillPackedAdapterModeRangeRuntimeDispatchA(
            std::uint32_t* const destinationBegin,
            const std::uint32_t count,
            const std::uint32_t* const sourceMode
        )
        {
            FillPackedAdapterModeRangeRuntime(destinationBegin, count, sourceMode);
        }

        /**
         * Address: 0x00940BF0 (FUN_00940BF0)
         *
         * What it does:
         * Fills `count` packed adapter-mode slots from one source payload and
         * returns the one-past-end destination cursor lane.
         */
        [[nodiscard]] std::uint32_t* FillPackedAdapterModeRangeAndReturnEnd(
            std::uint32_t* const destinationBegin,
            const std::uint32_t count,
            const std::uint32_t* const sourceMode
        )
        {
            FillPackedAdapterModeRangeRuntime(destinationBegin, count, sourceMode);
            const auto destinationAddress = reinterpret_cast<std::uintptr_t>(destinationBegin);
            const auto byteAdvance = static_cast<std::uintptr_t>(count) * sizeof(AdapterModeD3D9);
            return reinterpret_cast<std::uint32_t*>(destinationAddress + byteAdvance);
        }

        struct AdapterVectorCountRuntime final
        {
            void* allocatorProxy = nullptr;   // +0x00
            AdapterD3D9* first = nullptr;     // +0x04
            AdapterD3D9* last = nullptr;      // +0x08
        };
        static_assert(sizeof(AdapterVectorCountRuntime) == 0x0C, "AdapterVectorCountRuntime size must be 0x0C");

        /**
         * Address: 0x008E83A0 (FUN_008E83A0)
         *
         * What it does:
         * Returns element count from one adapter-vector lane (`_Mylast -
         * _Myfirst`) with 0x70-byte element stride, or zero when uninitialized.
         */
        [[nodiscard]] int CountAdapterVectorElements(const AdapterVectorCountRuntime* const vectorLane) noexcept
        {
            const AdapterD3D9* const first = vectorLane->first;
            if (first == nullptr)
            {
                return 0;
            }

            return static_cast<int>(vectorLane->last - first);
        }

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

        const char* GetStringDataRaw(const msvc8::string& text) noexcept
        {
            return (text.myRes < 16U) ? text.bx.buf : text.bx.ptr;
        }

        msvc8::string MakeShortString(const char* const text)
        {
            if (text == nullptr)
            {
                return msvc8::string();
            }

            const std::size_t length = std::strlen(text);
            return msvc8::string(text, length);
        }

        [[noreturn]] void ThrowGalError(const char* const file, const int line, const char* const message)
        {
            throw Error(MakeShortString(file), line, MakeShortString(message));
        }

        [[noreturn]] void ThrowGalErrorFromHresult(const char* const file, const int line, const HRESULT code)
        {
            throw Error(MakeShortString(file), line, MakeShortString(::gpg::D3DErrorToString(static_cast<long>(code))));
        }

        /**
         * Makes `call`; when it fails, makes it a second time and throws with
         * the second result's text. Part of the backend checks its calls this
         * way rather than keeping the first HRESULT - `GetTexture2D` repeats
         * every failing call (0x008ECDB7, 0x008ECE6F, 0x008ECFDE, ...) -
         * which the repeat preserves.
         */
        template <class Call>
        void CheckD3DCall(const char* const file, const int line, Call&& call)
        {
            if (FAILED(call()))
            {
                ThrowGalErrorFromHresult(file, line, call());
            }
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
         * Address: 0x009411D0 (FUN_009411D0, msvc8::vector<AdapterModeD3D9>::push_back)
         *
         * What it does:
         * Per-T named helper binding the engine-instantiated
         * `msvc8::vector<gpg::gal::AdapterModeD3D9>::push_back` slow-path body.
         * Rewriting the inline `modes.push_back(...)` call site in
         * `CollectAllAdaptersForSetup` through this helper preserves the
         * MSVC8 1:1 symbol shape for the per-T template emission even when
         * the modern compiler would otherwise inline the natural form.
         */
        void PushBackAdapterModeD3D9(
            msvc8::vector<AdapterModeD3D9>& modes,
            const AdapterModeD3D9& mode)
        {
            modes.push_back(mode);
        }

        /**
         * Address: 0x008F1CB0 (FUN_008F1CB0, func_CollectAllAdapters)
         *
         * What it does:
         * Enumerates all Direct3D adapters, captures identity/mode lists, and
         * appends them to the backend adapter storage. Routes each
         * `adapter.modes.push_back(...)` through the per-T named helper
         * `PushBackAdapterModeD3D9` (FUN_009411D0) to preserve the MSVC8
         * `vector<AdapterModeD3D9>::push_back` symbol shape.
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

                const msvc8::string description(
                    adapterIdentifier.Description,
                    std::strlen(adapterIdentifier.Description)
                );
                const msvc8::string deviceName(adapterIdentifier.DeviceName, std::strlen(adapterIdentifier.DeviceName));
                const msvc8::string driver(adapterIdentifier.Driver, std::strlen(adapterIdentifier.Driver));

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

                    PushBackAdapterModeD3D9(
                        adapter.modes,
                        AdapterModeD3D9(displayMode.Width, displayMode.Height, displayMode.RefreshRate)
                    );
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

        /**
         * The lock-and-check every `EffectTechniqueD3D9` entry point opens
         * with: the out-of-line `weak_ptr<EffectD3D9>::lock` emission (cited on
         * `boost::LockWeak`), then "attempt to use invalid effect" from the
         * caller's line when the effect is gone.
         */
        boost::shared_ptr<EffectD3D9> LockEffectOrThrow(
            const boost::weak_ptr<EffectD3D9>& weakEffect,
            const int line
        )
        {
            boost::shared_ptr<EffectD3D9> effect = boost::LockWeak(weakEffect);
            if (!effect)
            {
                ThrowGalError("EffectTechniqueD3D9.cpp", line, "attempt to use invalid effect");
            }

            return effect;
        }

        /**
         * The same lock-and-check for the `EffectVariableD3D9` entry points.
         */
        boost::shared_ptr<EffectD3D9> LockEffectVariableOrThrow(
            const boost::weak_ptr<EffectD3D9>& weakEffect,
            const int line
        )
        {
            boost::shared_ptr<EffectD3D9> effect = boost::LockWeak(weakEffect);
            if (!effect)
            {
                ThrowGalError("EffectVariableD3D9.cpp", line, "attempt to use invalid effect");
            }

            return effect;
        }

        unsigned int ToIndexBufferLockFlags(const MohoD3DLockFlags flags)
        {
            const auto raw = static_cast<unsigned int>(flags);

            unsigned int converted = 0U;
            if ((raw & static_cast<unsigned int>(MohoD3DLockFlags::ReadOnly)) != 0U)
            {
                converted |= D3DLOCK_READONLY;
            }

            if ((raw & static_cast<unsigned int>(MohoD3DLockFlags::Discard)) != 0U)
            {
                converted |= D3DLOCK_DISCARD;
            }

            return converted;
        }

        unsigned int ToVertexBufferLockFlags(const MohoD3DLockFlags flags)
        {
            const auto raw = static_cast<unsigned int>(flags);

            unsigned int converted = 0U;
            if ((raw & static_cast<unsigned int>(MohoD3DLockFlags::ReadOnly)) != 0U)
            {
                converted |= D3DLOCK_READONLY;
            }

            if ((raw & static_cast<unsigned int>(MohoD3DLockFlags::Discard)) != 0U)
            {
                converted |= D3DLOCK_DISCARD;
            }

            if ((raw & static_cast<unsigned int>(MohoD3DLockFlags::NoOverwrite)) != 0U)
            {
                converted |= D3DLOCK_NOOVERWRITE;
            }

            return converted;
        }

        unsigned int ToTextureLockFlags(const int flags)
        {
            const auto raw = static_cast<unsigned int>(flags);

            unsigned int converted = 0U;
            if ((raw & static_cast<unsigned int>(MohoD3DLockFlags::ReadOnly)) != 0U)
            {
                converted |= D3DLOCK_READONLY;
            }

            if ((raw & static_cast<unsigned int>(MohoD3DLockFlags::Discard)) != 0U)
            {
                converted |= D3DLOCK_DISCARD;
            }

            return converted;
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

        [[nodiscard]] msvc8::string ReadD3DXErrorText(ID3DXBuffer* const errors)
        {
            const char* const errorText =
                (errors != nullptr) ? static_cast<const char*>(errors->GetBufferPointer()) : "unknown error";

            msvc8::string reason{};
            reason.assign_owned(errorText);
            return reason;
        }

        [[nodiscard]]
        msvc8::string BuildEffectCreationMessage(
            const char* const prefix,
            const EffectContext& context,
            const msvc8::string& reason
        )
        {
            msvc8::string message(prefix != nullptr ? prefix : "");
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
        [[nodiscard]] D3DXMACRO* BuildD3DXMacroDefines(const msvc8::vector<EffectMacro>& macros)
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

        /**
         * Address: 0x0094AA90 (FUN_0094AA90)
         * Mangled: ??1TextureD3D9@gal@gpg@@QAE@XZ
         *
         * What it does:
         * Routes texture-destruction body behavior through the reset helper path.
         */
        void DestroyTextureD3D9Body(TextureD3D9* const texture)
        {
            texture->Reset();
        }
    }

    /**
     * Address: 0x00940820 (FUN_00940820)
     *
     * What it does:
     * Reports whether runtime mesh instancing is enabled in both global and
     * device-context capability lanes.
     */
    BOOL func_AllowMeshInstancing()
    {
        const DeviceContext* const deviceContext = ActiveDeviceD3D9().GetDeviceContext();
        return (sMeshAllowInstancing != 0U) && deviceContext->mHWBasedInstancing;
    }

    /**
     * Address: 0x009407F0 (FUN_009407F0)
     *
     * What it does:
     * Reports whether float16 mesh formatting is enabled in both global and
     * device-context capability lanes.
     */
    BOOL func_AllowMeshFloat16()
    {
        const DeviceContext* const deviceContext = ActiveDeviceD3D9().GetDeviceContext();
        return (sMeshAllowFloat16 != 0U) && deviceContext->mSupportsFloat16;
    }

    namespace
    {
        // Process-wide cache of the selected hardware vertex formatter
        // (mirrors the binary global `sCurHardwareVertexFormatter`,
        // 0x00F8E288). Resolved lazily on first request and reused thereafter.
        MeshFormatter* sCurrentHardwareVertexFormatter = nullptr;

        // The D3D9 device-type formatter candidates, most-capable first
        // (mirrors the binary `HardwareVertexFormattersD3D9` table,
        // 0x00F2E3D8): the float16 formatter is preferred; the plain
        // hardware formatter is the fallback. The first candidate whose
        // `AllowMeshInstancing()` gate passes for the current device wins.
        [[nodiscard]] MeshFormatter* SelectFirstInstancingCapableFormatter(
            MeshFormatter* const* const candidates
        )
        {
            MeshFormatter* selected = candidates[0];
            sCurrentHardwareVertexFormatter = selected;
            if (selected == nullptr) {
                return nullptr;
            }

            MeshFormatter* const* cursor = &candidates[1];
            while (!selected->AllowMeshInstancing()) {
                selected = *cursor++;
                sCurrentHardwareVertexFormatter = selected;
                if (selected == nullptr) {
                    return nullptr;
                }
            }

            return sCurrentHardwareVertexFormatter;
        }
    } // namespace

    /**
     * Address: 0x008E7550 (FUN_008E7550, func_GetHardwareVertexFormatter)
     *
     * What it does:
     * Returns the process-wide hardware vertex formatter for the active
     * device. Throws a GAL error for any device type other than D3D9/D3D10.
     * On the first call it walks the device-type candidate list and caches the
     * first formatter whose `AllowMeshInstancing()` gate passes; later calls
     * return the cached formatter. The construction/fill/draw paths of
     * `HardwareMeshBatch` all resolve their formatter through this accessor.
     */
    MeshFormatter* GetHardwareVertexFormatter()
    {
        const DeviceContext* const deviceContext = ActiveDeviceD3D9().GetDeviceContext();
        const std::int32_t deviceTypeSelector = deviceContext->mDeviceType - 1;

        if (sCurrentHardwareVertexFormatter != nullptr) {
            return sCurrentHardwareVertexFormatter;
        }

        // Device type 1 (D3D9) uses the D3D9 formatter list; device type 2
        // (D3D10) uses the D3D10 list. The two D3D9 singletons below are the
        // float16 (preferred) and plain hardware formatters.
        static Float16HardwareVertexFormatterD3D9 sFloat16FormatterD3D9;
        static HardwareVertexFormatterD3D9 sHardwareFormatterD3D9;
        static MeshFormatter* const kHardwareVertexFormattersD3D9[] = {
            &sFloat16FormatterD3D9,
            &sHardwareFormatterD3D9,
            nullptr,
        };

        if (deviceTypeSelector == 0) {
            return SelectFirstInstancingCapableFormatter(kHardwareVertexFormattersD3D9);
        }

        if (deviceTypeSelector == 1) {
            // The D3D10 device path selects from the D3D10 formatter table,
            // which is owned by the D3D10 backend; the D3D9 backend build does
            // not construct those singletons, so no candidate is available here.
            return SelectFirstInstancingCapableFormatter(kHardwareVertexFormattersD3D9);
        }

        ThrowGalError("MeshVertex.cpp", 92, "unknown graphics API");
    }

    /**
     * Address: 0x00945160 (FUN_00945160)
     *
     * What it does:
     * Copies rows `(0,1,2)`, `(4,5,6)`, `(8,9,10)`, `(12,13,14)` from a
     * source 4x4 matrix into four contiguous 3-float destination rows.
     */
    static void CopyMatrix4x3Rows(
        float* const outRow0,
        float* const outRow1,
        float* const outRow2,
        float* const outRow3,
        const Matrix& matrix
    )
    {
        float* const outRows[4] = {outRow0, outRow1, outRow2, outRow3};
        for (int row = 0; row < 4; ++row)
        {
            outRows[row][0] = matrix.r[row].x;
            outRows[row][1] = matrix.r[row].y;
            outRows[row][2] = matrix.r[row].z;
        }
    }

    /**
     * Address: 0x00945080 (FUN_00945080)
     *
     * What it does:
     * Packs two input float lanes into two float16 lanes.
     */
    static void PackFloat2ToHalf2(std::uint16_t* const outHalf2, const float* const inFloat2)
    {
        D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&outHalf2[0]), &inFloat2[0], 1U);
        D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&outHalf2[1]), &inFloat2[1], 1U);
    }

    /**
     * Address: 0x009450E0 (FUN_009450E0)
     *
     * What it does:
     * Packs three input float lanes into three float16 lanes.
     */
    static void PackFloat3ToHalf3(std::uint16_t* const outHalf3, const float* const inFloat3)
    {
        D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&outHalf3[0]), &inFloat3[0], 1U);
        D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&outHalf3[1]), &inFloat3[1], 1U);
        D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&outHalf3[2]), &inFloat3[2], 1U);
    }

    /**
     * Address: 0x009456C0 (FUN_009456C0)
     *
     * What it does:
     * Writes one 4x4 identity matrix (`float[16]`) into caller storage.
     */
    float* InitializeIdentityMatrix4x4Lane(float* const matrix4x4) noexcept
    {
        matrix4x4[14] = 0.0f;
        matrix4x4[13] = 0.0f;
        matrix4x4[12] = 0.0f;
        matrix4x4[11] = 0.0f;
        matrix4x4[9] = 0.0f;
        matrix4x4[8] = 0.0f;
        matrix4x4[7] = 0.0f;
        matrix4x4[6] = 0.0f;
        matrix4x4[4] = 0.0f;
        matrix4x4[3] = 0.0f;
        matrix4x4[2] = 0.0f;
        matrix4x4[1] = 0.0f;
        matrix4x4[15] = 1.0f;
        matrix4x4[10] = 1.0f;
        matrix4x4[5] = 1.0f;
        matrix4x4[0] = 1.0f;
        return matrix4x4;
    }

    /**
     * Address: 0x009451C0 (FUN_009451C0, ??0HardwareVertexFormatterD3D9@gal@gpg@@QAE@@Z)
     *
     * What it does:
     * Initializes one D3D9 hardware-vertex formatter wrapper.
     */
    HardwareVertexFormatterD3D9::HardwareVertexFormatterD3D9() = default;

    /**
     * Address: 0x009451D0 (FUN_009451D0)
     *
     * What it does:
     * Runs the non-deleting teardown body and restores the base
     * `MeshFormatter` vtable lane.
     */
    HardwareVertexFormatterD3D9::~HardwareVertexFormatterD3D9() = default;

    /**
     * Address: 0x00C09610 (FUN_00C09610, ??1HardwareVertexFormatterD3D9@gal@gpg@@QAE@@Z)
     *
     * What it does:
     * Preserves one startup-registered shutdown thunk lane by constructing one
     * typed adapter object and forwarding teardown into
     * `HardwareVertexFormatterD3D9::~HardwareVertexFormatterD3D9`
     * (`FUN_009451D0`).
     */
    void ShutdownHardwareVertexFormatterD3D9Adapter()
    {
        alignas(HardwareVertexFormatterD3D9) unsigned char formatterStorage[sizeof(HardwareVertexFormatterD3D9)]{};
        auto* const formatter = new (static_cast<void*>(formatterStorage)) HardwareVertexFormatterD3D9();
        formatter->~HardwareVertexFormatterD3D9();
    }

    /**
     * Address: 0x00945600 (FUN_00945600)
     *
     * What it does:
     * Owns the scalar-deleting destroy thunk for hardware-vertex formatter instances.
     */
    MeshFormatter* HardwareVertexFormatterD3D9::Destroy(const std::uint8_t deleteFlags)
    {
        this->~HardwareVertexFormatterD3D9();
        auto* const formatter = static_cast<MeshFormatter*>(this);
        if ((deleteFlags & 1U) != 0U)
        {
            ::operator delete(formatter);
        }

        return formatter;
    }

    /**
     * Address: 0x009451E0 (FUN_009451E0)
     *
     * What it does:
     * Reports whether the hardware formatter can use mesh instancing.
     */
    bool HardwareVertexFormatterD3D9::AllowMeshInstancing()
    {
        return func_AllowMeshInstancing() != FALSE;
    }

    /**
     * Address: 0x00945680 (FUN_00945680)
     *
     * What it does:
     * Creates vertex format 14 on the active device (slot 14, `[vtbl+0x38]`).
     */
    boost::shared_ptr<VertexFormat> HardwareVertexFormatterD3D9::CreateVertexFormat(
        const std::int32_t /*layoutVariant*/
    )
    {
        return Device::GetInstance()->CreateVertexFormat(14U);
    }

    /**
     * Address: 0x009451F0 (FUN_009451F0)
     *
     * What it does:
     * Returns packed hardware-vertex stride for the requested stream class.
     */
    std::uint32_t HardwareVertexFormatterD3D9::GetVertexStride(
        const std::int32_t streamClass,
        const std::int32_t /*sizeVariant*/
    )
    {
        return static_cast<std::uint32_t>(0x48 + ((streamClass != 0) ? 4 : 0));
    }

    /**
     * Address: 0x00945380 (FUN_00945380, ??0Float16HardwareVertexFormatterD3D9@gal@gpg@@QAE@@Z)
     *
     * What it does:
     * Initializes one D3D9 float16 hardware-vertex formatter wrapper.
     */
    Float16HardwareVertexFormatterD3D9::Float16HardwareVertexFormatterD3D9() = default;

    /**
     * Address: 0x00945390 (FUN_00945390)
     *
     * What it does:
     * Runs the non-deleting teardown body and restores the base
     * `MeshFormatter` vtable lane.
     */
    Float16HardwareVertexFormatterD3D9::~Float16HardwareVertexFormatterD3D9() = default;

    /**
     * Address: 0x00C09620 (FUN_00C09620, ??1Float16HardwareVertexFormatterD3D9@gal@gpg@@QAE@@Z)
     *
     * What it does:
     * Preserves one startup-registered shutdown thunk lane by constructing one
     * typed adapter object and forwarding teardown into
     * `Float16HardwareVertexFormatterD3D9::~Float16HardwareVertexFormatterD3D9`
     * (`FUN_00945390`).
     */
    void ShutdownFloat16HardwareVertexFormatterD3D9Adapter()
    {
        alignas(Float16HardwareVertexFormatterD3D9)
            unsigned char formatterStorage[sizeof(Float16HardwareVertexFormatterD3D9)]{};
        auto* const formatter = new (static_cast<void*>(formatterStorage)) Float16HardwareVertexFormatterD3D9();
        formatter->~Float16HardwareVertexFormatterD3D9();
    }

    /**
     * Address: 0x00945620 (FUN_00945620)
     *
     * What it does:
     * Owns the scalar-deleting destroy thunk for float16 hardware-vertex formatter instances.
     */
    MeshFormatter* Float16HardwareVertexFormatterD3D9::Destroy(const std::uint8_t deleteFlags)
    {
        this->~Float16HardwareVertexFormatterD3D9();
        auto* const formatter = static_cast<MeshFormatter*>(this);
        if ((deleteFlags & 1U) != 0U)
        {
            ::operator delete(formatter);
        }

        return formatter;
    }

    /**
     * Address: 0x009453A0 (FUN_009453A0)
     *
     * What it does:
     * Reports whether float16 formatter instancing is allowed by both runtime gates.
     */
    bool Float16HardwareVertexFormatterD3D9::AllowMeshInstancing()
    {
        return (func_AllowMeshInstancing() != FALSE) && (func_AllowMeshFloat16() != FALSE);
    }

    /**
     * Address: 0x00945640 (FUN_00945640)
     *
     * What it does:
     * Creates vertex format 15 on the active device, or 16 (the one with the
     * second per-vertex position stream) when `layoutVariant` is set.
     */
    boost::shared_ptr<VertexFormat> Float16HardwareVertexFormatterD3D9::CreateVertexFormat(
        const std::int32_t layoutVariant
    )
    {
        return Device::GetInstance()->CreateVertexFormat((layoutVariant != 0) ? 16U : 15U);
    }

    /**
     * Address: 0x009453C0 (FUN_009453C0)
     *
     * What it does:
     * Returns float16 packed stride from runtime stride lookup tables.
     */
    std::uint32_t Float16HardwareVertexFormatterD3D9::GetVertexStride(
        const std::int32_t streamClass,
        const std::int32_t sizeVariant
    )
    {
        const auto* const table = (sizeVariant != 0) ? kFloat16VertexStrideTableCompact : kFloat16VertexStrideTableDefault;
        return table[static_cast<std::size_t>(streamClass)];
    }

    /**
     * Address: 0x00945210 (FUN_00945210)
     *
     * What it does:
     * Packs one mesh vertex into vertex format 14: the geometry record for
     * stream class 0 (position with w = 1), the instance record otherwise.
     */
    void HardwareVertexFormatterD3D9::WriteFormattedVertex(
        const std::int32_t streamClass,
        void* const destinationVertex,
        const MeshVertex& source,
        const std::int32_t /*writeVariant*/
    )
    {
        if (streamClass != 0)
        {
            auto& destination = *static_cast<HardwareVertexInstance*>(destinationVertex);
            destination.instanceIndex = source.instanceIndex;
            destination.meshColor = source.meshColor;
            destination.color = source.color;
            destination.shaderTime = source.shaderTime;
            CopyMatrix4x3Rows(
                destination.transform[0], destination.transform[1], destination.transform[2], destination.transform[3],
                source.transform
            );
            destination.bonePaletteBase = source.bonePaletteBase;
            destination.secondaryDataMask = (source.useSecondaryData != 0U) ? static_cast<std::uint8_t>(0xFFU) : 0U;
            destination.scroll[0] = source.scroll[0];
            destination.scroll[1] = source.scroll[1];
            destination.dissolve = source.dissolve;
            destination.parameter = source.parameter;
            return;
        }

        auto& destination = *static_cast<HardwareVertex*>(destinationVertex);
        destination.boneIndices[0] = source.boneIndices[0];
        destination.boneIndices[1] = source.boneIndices[1];
        destination.boneIndices[2] = source.boneIndices[2];
        destination.boneIndices[3] = source.boneIndices[3];

        destination.position[0] = source.position[0];
        destination.position[1] = source.position[1];
        destination.position[2] = source.position[2];
        destination.position[3] = 1.0f;
        destination.normal[0] = source.normal[0];
        destination.normal[1] = source.normal[1];
        destination.normal[2] = source.normal[2];
        destination.binormal[0] = source.binormal[0];
        destination.binormal[1] = source.binormal[1];
        destination.binormal[2] = source.binormal[2];
        destination.tangent[0] = source.tangent[0];
        destination.tangent[1] = source.tangent[1];
        destination.tangent[2] = source.tangent[2];
        destination.texCoords[0] = source.texCoord0[0];
        destination.texCoords[1] = source.texCoord0[1];
        destination.texCoords[2] = source.texCoord1[0];
        destination.texCoords[3] = source.texCoord1[1];
    }

    /**
     * Address: 0x009453F0 (FUN_009453F0)
     *
     * What it does:
     * Packs one mesh vertex into vertex format 15/16 with half-precision
     * scalars. Stream class 0 gets the geometry record; with `writeVariant`
     * set, stream class 1 is format 16 second per-vertex position stream and
     * gets `position1` as three halves; any other stream class gets the
     * instance record.
     */
    void Float16HardwareVertexFormatterD3D9::WriteFormattedVertex(
        const std::int32_t streamClass,
        void* const destinationVertex,
        const MeshVertex& source,
        const std::int32_t writeVariant
    )
    {
        if (streamClass != 0)
        {
            if ((writeVariant != 0) && (streamClass == 1))
            {
                PackFloat3ToHalf3(static_cast<std::uint16_t*>(destinationVertex), source.position1);
                return;
            }

            auto& destination = *static_cast<Float16HardwareVertexInstance*>(destinationVertex);
            destination.instanceIndex = source.instanceIndex;
            destination.meshColor = source.meshColor;
            destination.color = source.color;
            D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&destination.shaderTime), &source.shaderTime, 1U);
            CopyMatrix4x3Rows(
                destination.transform[0], destination.transform[1], destination.transform[2], destination.transform[3],
                source.transform
            );
            destination.bonePaletteBase = source.bonePaletteBase;
            destination.secondaryDataMask = (source.useSecondaryData != 0U) ? static_cast<std::uint8_t>(0xFFU) : 0U;
            PackFloat2ToHalf2(destination.scroll, source.scroll);
            destination.dissolve = source.dissolve;
            D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&destination.parameter), &source.parameter, 1U);
            return;
        }

        auto& destination = *static_cast<Float16HardwareVertex*>(destinationVertex);
        destination.boneIndices[0] = source.boneIndices[0];
        destination.boneIndices[1] = source.boneIndices[1];
        destination.boneIndices[2] = source.boneIndices[2];
        destination.boneIndices[3] = source.boneIndices[3];

        PackFloat3ToHalf3(destination.position, source.position);
        PackFloat3ToHalf3(destination.normal, source.normal);
        PackFloat3ToHalf3(destination.binormal, source.binormal);
        PackFloat3ToHalf3(destination.tangent, source.tangent);

        D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&destination.texCoords[0]), &source.texCoord0[0], 1U);
        D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&destination.texCoords[1]), &source.texCoord0[1], 1U);
        D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&destination.texCoords[2]), &source.texCoord1[0], 1U);
        D3DXFloat32To16Array(reinterpret_cast<D3DXFLOAT16*>(&destination.texCoords[3]), &source.texCoord1[1], 1U);
    }

    /**
     * Address: 0x00941040 (FUN_00941040, gpg::gal::AdapterD3D9::AdapterD3D9)
     * Mangled: ??0AdapterD3D9@gal@gpg@@QAE@@Z
     *
     * What it does:
     * Initializes one empty adapter descriptor with zeroed identifiers,
     * empty strings, and an empty mode vector.
     */
    AdapterD3D9::AdapterD3D9()
        : vendorId(0U)
        , deviceId(0U)
        , driver()
        , deviceName()
        , description()
        , modes()
    {
    }

    /**
     * Address: 0x009410A0 (FUN_009410A0, gpg::gal::AdapterD3D9::AdapterD3D9)
     * Mangled: ??0AdapterD3D9@gal@gpg@@QAE@@Z
     *
     * What it does:
     * Initializes adapter identifier lanes and copies driver/device/description
     * strings into this adapter instance.
     */
    AdapterD3D9::AdapterD3D9(
        const std::uint32_t vendorIdValue,
        const std::uint32_t deviceIdValue,
        const msvc8::string& driverName,
        const msvc8::string& deviceNameText,
        const msvc8::string& descriptionText
    )
        : vendorId(vendorIdValue)
        , deviceId(deviceIdValue)
        , driver()
        , deviceName()
        , description()
        , modes()
    {
        driver.assign(driverName, 0U, msvc8::string::npos);
        deviceName.assign(deviceNameText, 0U, msvc8::string::npos);
        description.assign(descriptionText, 0U, msvc8::string::npos);
    }

    /**
     * Address: 0x008EFF80 (FUN_008EFF80, gpg::gal::AdapterD3D9::AdapterD3D9 copy)
     *
     * What it does:
     * Copy-constructs one adapter descriptor by cloning identifier lanes,
     * descriptive strings, and the adapter mode vector.
     */
    AdapterD3D9::AdapterD3D9(const AdapterD3D9& other)
        : vendorId(other.vendorId)
        , deviceId(other.deviceId)
        , driver()
        , deviceName()
        , description()
        , modes()
    {
        driver.assign(other.driver, 0U, msvc8::string::npos);
        deviceName.assign(other.deviceName, 0U, msvc8::string::npos);
        description.assign(other.description, 0U, msvc8::string::npos);
        modes = other.modes;
    }

    /**
     * Address: 0x00940C90 (FUN_00940C90)
     * Address: 0x008F0040 (FUN_008F0040, the scalar-deleting wrapper for the
     * destructor above)
     *
     * What it does:
     * Destroys adapter mode list and all descriptive string lanes.
     */
    AdapterD3D9::~AdapterD3D9() = default;

    /**
     * Address: 0x00940990 (FUN_00940990, ??0AdapterModeD3D9@gal@gpg@@QAE@@Z)
     *
     * What it does:
     * Initializes one adapter-mode lane with width/height/refresh-rate scalar values.
     */
    AdapterModeD3D9::AdapterModeD3D9(
        const std::uint32_t widthValue,
        const std::uint32_t heightValue,
        const std::uint32_t refreshRateValue
    )
        : width_(widthValue)
        , height_(heightValue)
        , refreshRate_(refreshRateValue)
    {
    }

    /**
     * Address: 0x008E8E10 (FUN_008E8E10)
     *
     * What it does:
     * Copy-constructs one adapter-mode lane by cloning width/height/
     * refresh-rate scalar values.
     */
    AdapterModeD3D9::AdapterModeD3D9(const AdapterModeD3D9& other)
        : width_(other.width_)
        , height_(other.height_)
        , refreshRate_(other.refreshRate_)
    {
    }

    /**
     * Address: 0x009409B0 (FUN_009409B0, ??1AdapterModeD3D9@gal@gpg@@QAE@@Z)
     * Address: 0x008E8E40 (FUN_008E8E40, the scalar-deleting wrapper for the
     * destructor above)
     *
     * What it does:
     * Restores AdapterModeD3D9 vftable ownership; deleting-thunk lanes route
     * through this destructor body.
     */
    AdapterModeD3D9::~AdapterModeD3D9() = default;

    /**
     * Address: 0x008EFD50 (FUN_008EFD50)
     *
     * What it does:
     * Builds an empty device: every member has its initializer, so the body
     * is empty (the stores at 0x008EFD84..0x008EFDB5 are those
     * initializers, `DeviceContext(0)` included). `Device::Create` then
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
     * Preserves the currently unresolved adapter-mode projection slot.
     */
    void DeviceD3D9::GetModesForAdapter(msvc8::vector<AdapterModeD3D9>& outModes, const int adapterIndex)
    {
      // The binary rewinds the output rather than releasing it, so the caller
      // keeps whatever capacity it already paid for across repeated queries.
      outModes.clear();

      if (adapterIndex >= static_cast<int>(mAdapters.size())) {
        return;
      }

      // Copied field-by-field rather than element-wise: the source modes carry a
      // vptr this output does not reproduce, and only the three scalars matter.
      for (const AdapterModeD3D9& mode : mAdapters[static_cast<std::size_t>(adapterIndex)].modes) {
        PushBackAdapterModeD3D9(outModes, AdapterModeD3D9(mode.width_, mode.height_, mode.refreshRate_));
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
                sourceData, sourceBytes, defines, nullptr, D3DXSHADER_DEBUG | D3DXSHADER_USE_LEGACY_D3DX9_31_DLL,
                &effectCompiler, &errors
            );
            if (FAILED(result))
            {
                const msvc8::string message =
                    BuildEffectCreationMessage("unable to compile effect: ", context, ReadD3DXErrorText(errors));
                ThrowGalError("DeviceD3D9.cpp", 1549, message.c_str());
            }
            SafeRelease(errors);

            result = effectCompiler->CompileEffect(D3DXSHADER_DEBUG, &compiledEffect, &errors);
            if (FAILED(result))
            {
                const msvc8::string message =
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
                const msvc8::string message =
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
                const msvc8::string message =
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
        delete[] mHeads;
        mHeads = nullptr;

        mPipelineState.reset();

        SafeRelease(mFrameEventQuery);
        SafeRelease(mDevice);
        SafeRelease(mDirect3D);

        mDeviceContext = DeviceContext(0);
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
                if (mAdapters[adapterIndex].description.find("NVPerfHUD", 0U, 9U) != msvc8::string::npos)
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

        OutputContext* const heads = new OutputContext[headCount];
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
     * Address: 0x008EFDD0 (FUN_008EFDD0)
     *
     * What it does:
     * Appends one adapter-mode projection entry (`width/height/refresh`) to the
     * destination head-mode vector and returns the inserted slot.
     */
    HeadAdapterMode* AppendHeadAdapterMode(
        msvc8::vector<HeadAdapterMode>& adapterModes,
        const HeadAdapterMode& mode
    )
    {
        adapterModes.push_back(mode);
        return &adapterModes.back();
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
                HeadAdapterMode mappedMode{};
                mappedMode.width = mode.width_;
                mappedMode.height = mode.height_;
                mappedMode.refreshRate = mode.refreshRate_;
                static_cast<void>(AppendHeadAdapterMode(head.adapterModes, mappedMode));
            }

            head.validFormats1.clear();
            for (int formatToken = 1; formatToken < 8; ++formatToken)
            {
                const HRESULT result = mDirect3D->CheckDeviceFormat(adapterIndex, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 1U, D3DRTYPE_TEXTURE, static_cast<D3DFORMAT>(GetD3DFormat(static_cast<std::uint32_t>(formatToken))));
                if (result >= 0)
                {
                    // MSVC8 inlines the fast in-place append and, when the vector is
                    // at capacity, calls the out-of-line grow lane
                    // msvc8::vector<std::int32_t>::_Insert_n (FUN_008EF500) as
                    // _Insert_n(_Mylast, 1, &formatToken). Mirror that shape so the
                    // front-end emits that per-T insert symbol.
                    if (head.validFormats1.size() < head.validFormats1.capacity())
                    {
                        head.validFormats1.push_back(formatToken);
                    }
                    else
                    {
                        static_cast<void>(head.validFormats1.insert(
                            head.validFormats1.end(), static_cast<std::size_t>(1), formatToken));
                    }
                }
            }

            head.validFormats2.clear();
            for (int formatToken = 1; formatToken < 20; ++formatToken)
            {
                const HRESULT result = mDirect3D->CheckDeviceFormat(adapterIndex, D3DDEVTYPE_HAL, D3DFMT_X8R8G8B8, 0U, D3DRTYPE_TEXTURE, static_cast<D3DFORMAT>(FormatGalToD3D(static_cast<std::uint32_t>(formatToken))));
                if (result >= 0)
                {
                    // MSVC8 inlines the fast in-place append and, when the vector is
                    // at capacity, calls the out-of-line grow lane
                    // msvc8::vector<std::int32_t>::_Insert_n (FUN_008EF2B0) as
                    // _Insert_n(_Mylast, 1, &formatToken). Mirror that shape so the
                    // front-end emits that per-T insert symbol.
                    if (head.validFormats2.size() < head.validFormats2.capacity())
                    {
                        head.validFormats2.push_back(formatToken);
                    }
                    else
                    {
                        static_cast<void>(head.validFormats2.insert(
                            head.validFormats2.end(), static_cast<std::size_t>(1), formatToken));
                    }
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

        delete[] mHeads;
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

    namespace
    {

        static constexpr std::uint32_t kVertexFormatCount = 24U;

        static constexpr D3DVERTEXELEMENT9 kVertexElementEndSentinel = D3DDECL_END();

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_0[2] = {
            {0, 0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_1[2] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_2[3] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_3[3] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_4[4] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 20, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_5[4] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0},
            {0, 24, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_6[4] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_D3DCOLOR, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_COLOR, 0},
            {0, 16, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_7[3] = {
            {0, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITIONT, 0},
            {0, 16, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_8[4] = {
            {0, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITIONT, 0},
            {0, 16, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 24, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_9[8] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0},
            {0, 24, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {1, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {1, 16, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            {1, 32, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 3},
            {1, 48, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 4},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_10[2] = {
            {0, 0, D3DDECLTYPE_SHORT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_11[7] = {
            {0, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 16, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 32, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {0, 48, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            {0, 60, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 3},
            {0, 76, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 4},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_12[5] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 24, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {0, 36, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_13[5] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 28, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {0, 44, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_14[15] = {
            {0, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 16, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0},
            {0, 28, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TANGENT, 0},
            {0, 40, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BINORMAL, 0},
            {0, 52, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 68, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0},
            {1, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {1, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            {1, 24, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 3},
            {1, 36, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 4},
            {1, 48, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 5},
            {1, 52, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 6},
            {1, 68, D3DDECLTYPE_D3DCOLOR, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_COLOR, 0},
            {1, 72, D3DDECLTYPE_FLOAT1, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 7},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_15[15] = {
            {0, 0, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 8, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0},
            {0, 16, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TANGENT, 0},
            {0, 24, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BINORMAL, 0},
            {0, 32, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 40, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0},
            {1, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {1, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            {1, 24, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 3},
            {1, 36, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 4},
            {1, 48, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 5},
            {1, 52, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 6},
            {1, 60, D3DDECLTYPE_D3DCOLOR, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_COLOR, 0},
            {1, 64, D3DDECLTYPE_FLOAT1, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 7},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_16[16] = {
            {0, 0, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 8, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_NORMAL, 0},
            {0, 16, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TANGENT, 0},
            {0, 24, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BINORMAL, 0},
            {0, 32, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {0, 40, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_BLENDINDICES, 0},
            {1, 0, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 1},
            {2, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {2, 12, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            {2, 24, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 3},
            {2, 36, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 4},
            {2, 48, D3DDECLTYPE_UBYTE4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 5},
            {2, 52, D3DDECLTYPE_FLOAT16_4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 6},
            {2, 60, D3DDECLTYPE_D3DCOLOR, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_COLOR, 0},
            {2, 64, D3DDECLTYPE_FLOAT1, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 7},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_17[5] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {0, 12, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {1, 0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 1},
            {1, 8, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_18[4] = {
            {0, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {1, 0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 1},
            {1, 8, D3DDECLTYPE_FLOAT1, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_19[9] = {
            {0, 0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {1, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 1},
            {1, 16, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {1, 24, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {1, 40, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            {1, 52, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 3},
            {1, 68, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 4},
            {1, 80, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 5},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_20[5] = {
            {0, 0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {1, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 1},
            {1, 16, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {1, 24, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_21[7] = {
            {0, 0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {1, 0, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 1},
            {1, 16, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {1, 28, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            {1, 36, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 2},
            {1, 44, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 3},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_22[5] = {
            {0, 0, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 0},
            {1, 0, D3DDECLTYPE_FLOAT3, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_POSITION, 1},
            {1, 12, D3DDECLTYPE_FLOAT2, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 0},
            {1, 20, D3DDECLTYPE_FLOAT4, D3DDECLMETHOD_DEFAULT, D3DDECLUSAGE_TEXCOORD, 1},
            D3DDECL_END(),
        };

        static constexpr D3DVERTEXELEMENT9 kVertexFormat_23[1] = {
            D3DDECL_END(),
        };

        static constexpr const D3DVERTEXELEMENT9* kVertexFormatsByCode[kVertexFormatCount] = {
            kVertexFormat_0,  kVertexFormat_1,  kVertexFormat_2,  kVertexFormat_3,  kVertexFormat_4,  kVertexFormat_5,
            kVertexFormat_6,  kVertexFormat_7,  kVertexFormat_8,  kVertexFormat_9,  kVertexFormat_10, kVertexFormat_11,
            kVertexFormat_12, kVertexFormat_13, kVertexFormat_14, kVertexFormat_15, kVertexFormat_16, kVertexFormat_17,
            kVertexFormat_18, kVertexFormat_19, kVertexFormat_20, kVertexFormat_21, kVertexFormat_22, kVertexFormat_23,
        };

        [[nodiscard]] bool IsVertexElementEndSentinel(const D3DVERTEXELEMENT9& element) noexcept
        {
            return (element.Stream == kVertexElementEndSentinel.Stream) &&
                   (element.Offset == kVertexElementEndSentinel.Offset) &&
                   (element.Type == kVertexElementEndSentinel.Type) &&
                   (element.Method == kVertexElementEndSentinel.Method) &&
                   (element.Usage == kVertexElementEndSentinel.Usage) &&
                   (element.UsageIndex == kVertexElementEndSentinel.UsageIndex);
        }

        /**
         * Address: 0x0094AE10 (FUN_0094AE10, func_GetVertexFormat)
         *
         * What it does:
         * Validates one vertex-format code and returns the recovered D3D vertex
         * element declaration table pointer for that format.
         */
        const D3DVERTEXELEMENT9* GetVertexFormatElementsOrThrow(const std::uint32_t formatCode)
        {
            if (formatCode >= kVertexFormatCount)
            {
                ThrowGalError("VertexFormatD3D9.cpp", 389, "invalid vertex format specified");
            }

            return kVertexFormatsByCode[formatCode];
        }

        void ClearTextureContextData(TextureContext& context) noexcept
        {
            if (context.dataCount_ != nullptr)
            {
                context.dataCount_->release();
            }

            context.dataArray_ = nullptr;
            context.dataCount_ = nullptr;
            context.dataBegin_ = 0U;
            context.dataEnd_ = 0U;
        }
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
        ClearTextureContextData(textureContext);

        const auto* const sourceData = reinterpret_cast<const void*>(static_cast<std::uintptr_t>(context->dataBegin_));
        const unsigned int sourceBytes = context->dataEnd_ - context->dataBegin_;

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
            if (context->dataEnd_ == context->dataBegin_)
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
                { static int sDevBudget = 60; if (sDevBudget > 0) { --sDevBudget; ::gpg::Warnf("[TEXCREATE] tid=%lu device=%p bytes=%u skip=%u mipFilter=%08X w=%u h=%u loc=%s", ::GetCurrentThreadId(), mDevice, static_cast<unsigned>(sourceBytes), context->reserved0x44_, mipFilter, context->width_, context->height_, context->location_.c_str()); } } // TEMPORARY PROBE (do not commit)
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
        const msvc8::string& filePath
    )
    {
        Func1();

        // `!*(_DWORD *)(a3 + 20)` - string+0x14 is mySize, not myRes: msvc8::string
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
        const msvc8::string& filePath,
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
        const msvc8::string& filePath,
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
            std::memcpy(outBuffer->GetPtr(0U, 0U), fileBuffer->GetBufferPointer(), fileBuffer->GetBufferSize());
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

        *outWidth = sourceDesc.Width;
        *outHeight = static_cast<int>(sourceDesc.Height);

        // Anything that is not already DXT5 is converted through a DXT5
        // system-memory copy, which then stands in for the source surface.
        IDirect3DTexture9* decodeTexture = nullptr;
        if (sourceDesc.Format != D3DFMT_DXT5)
        {
            CheckD3DCall("DeviceD3D9.cpp", 801, [&] {
                return mDevice->CreateTexture(
                    AlignToDword(sourceDesc.Width), AlignToDword(sourceDesc.Height), 1U, 0U, D3DFMT_DXT5,
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
            std::memcpy(destinationBytes, sourceBytesPtr, totalBytes);
        }
        else
        {
            for (std::size_t rowIndex = 0; rowIndex < rowCount; ++rowIndex)
            {
                std::memcpy(
                    destinationBytes + (rowIndex * bytesPerRow),
                    sourceBytesPtr + (rowIndex * static_cast<std::size_t>(lockedRect.Pitch)),
                    bytesPerRow
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

        { // TEMPORARY PROBE (do not commit): per-frame sequence + framediag.on arming
            ++gProbeFrameSeq;
            if (gProbeFrameDiagLeft > 0) { ::gpg::Warnf("[FD] present f=%d", gProbeFrameSeq); --gProbeFrameDiagLeft; }
            else { char dirF[512] = {}; std::size_t lenF = 0;
              if (::getenv_s(&lenF, dirF, sizeof(dirF), "FAF_TOGGLE_DIR") == 0 && lenF != 0u) {
                char fpath[600]; (void)std::snprintf(fpath, sizeof(fpath), "%s/framediag.on", dirF);
                if (::GetFileAttributesA(fpath) != INVALID_FILE_ATTRIBUTES) { gProbeFrameDiagLeft = 8; ::DeleteFileA(fpath); }
              } }
        }
        { // TEMPORARY PROBE (do not commit): dump two consecutive presents while dumpframe2.on exists
            static int sPairState = 0;
            char dir2[512] = {}; std::size_t len2 = 0;
            if (::getenv_s(&len2, dir2, sizeof(dir2), "FAF_TOGGLE_DIR") == 0 && len2 != 0u) {
                char tpath[600]; (void)std::snprintf(tpath, sizeof(tpath), "%s/dumpframe2.on", dir2);
                const bool armed = ::GetFileAttributesA(tpath) != INVALID_FILE_ATTRIBUTES;
                if (armed && sPairState < 2) {
                    IDirect3DSurface9* bb = nullptr;
                    if (mDevice->GetBackBuffer(0U, 0U, D3DBACKBUFFER_TYPE_MONO, &bb) >= 0 && bb != nullptr) {
                        char out[600]; (void)std::snprintf(out, sizeof(out), "%s/frame_%c.bmp", dir2, sPairState == 0 ? 'A' : 'B');
                        const HRESULT sh = D3DXSaveSurfaceToFileA(out, D3DXIFF_BMP, bb, nullptr, nullptr);
                        bb->Release();
                        ::gpg::Warnf("[FRAMEDUMP2] %d hr=%08lX %s", sPairState, static_cast<long>(sh), out);
                    }
                    ++sPairState;
                    if (sPairState == 2) { ::DeleteFileA(tpath); }
                } else if (!armed) {
                    sPairState = 0;
                }
            }
        }
        { // TEMPORARY PROBE (do not commit): dump the back buffer while dumpframe.on exists
            static unsigned sPresentCalls = 0;
            if ((sPresentCalls++ % 64u) == 0u) {
                char dir[512] = {}; std::size_t length = 0;
                if (::getenv_s(&length, dir, sizeof(dir), "FAF_TOGGLE_DIR") == 0 && length != 0u) {
                    char path[600]; (void)std::snprintf(path, sizeof(path), "%s/dumpframe.on", dir);
                    if (::GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
                        IDirect3DSurface9* bb = nullptr;
                        if (mDevice->GetBackBuffer(0U, 0U, D3DBACKBUFFER_TYPE_MONO, &bb) >= 0 && bb != nullptr) {
                            char out[600]; (void)std::snprintf(out, sizeof(out), "%s/frame.bmp", dir);
                            const HRESULT sh = D3DXSaveSurfaceToFileA(out, D3DXIFF_BMP, bb, nullptr, nullptr);
                            bb->Release();
                            ::gpg::Warnf("[FRAMEDUMP] hr=%08lX %s", static_cast<long>(sh), out);
                        }
                    }
                }
            }
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
    int DeviceD3D9::DrawPrimitive(const DrawContext* const context)
    {
        Func1();

        if (context->topology_ == 0)
        {
            ThrowGalError("DeviceD3D9.cpp", 1149, "invalid topology specified");
        }

        const D3DPRIMITIVETYPE primitiveType = kTopologyPrimitiveTypes[context->topology_];
        const HRESULT result = mDevice->DrawPrimitive(primitiveType, context->startVertex_, context->GetPrimitiveCount());
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1152, result);
        }

        return result;
    }

    /**
     * Address: 0x008EE850 (FUN_008EE850)
     *
     * What it does:
     * Validates the topology and issues one indexed draw, converting the
     * context's index count into a primitive count.
     */
    int DeviceD3D9::DrawIndexedPrimitive(const DrawIndexedContext* const context)
    {
        Func1();

        if (context->topology_ == 0)
        {
            ThrowGalError("DeviceD3D9.cpp", 1159, "invalid topology specified");
        }

        const D3DPRIMITIVETYPE primitiveType = kTopologyPrimitiveTypes[context->topology_];
        const HRESULT result = mDevice->DrawIndexedPrimitive(
            primitiveType,
            context->baseVertexIndex_,
            context->minVertexIndex_,
            context->vertexCount_,
            context->startIndex_,
            context->GetPrimitiveCount()
        );
        if (result < 0)
        {
            ThrowGalErrorFromHresult("DeviceD3D9.cpp", 1162, result);
        }

        return result;
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

    /**
     * Address: 0x009460A0 (FUN_009460A0)
     *
     * bool,void const *,float,float,int
     *
     * What it does:
     * Applies fog enable/disable state and projection-fog payload lanes on the
     * retained state manager.
     */
    void PipelineStateD3D9::SetFogState(
        const bool enable,
        const Matrix* const projection,
        const float fogStart,
        const float fogEnd,
        const int fogColor
    )
    {
        StateManagerD3D9* const stateManager = GetStateManager();
        if (enable)
        {
            static_cast<void>(stateManager->SetTransform(D3DTS_PROJECTION, reinterpret_cast<const D3DMATRIX*>(projection)));
            static_cast<void>(stateManager->SetRenderState(
                D3DRS_FOGENABLE,
                1U
            ));
            static_cast<void>(stateManager->SetRenderState(
                D3DRS_RANGEFOGENABLE,
                1U
            ));
            static_cast<void>(stateManager->SetRenderState(
                D3DRS_FOGCOLOR,
                static_cast<unsigned int>(fogColor)
            ));
            static_cast<void>(stateManager->SetRenderState(
                D3DRS_FOGTABLEMODE,
                D3DFOG_LINEAR
            ));
            static_cast<void>(stateManager->SetRenderState(
                D3DRS_FOGSTART,
                std::bit_cast<unsigned int>(fogStart)
            ));
            static_cast<void>(stateManager->SetRenderState(
                D3DRS_FOGEND,
                std::bit_cast<unsigned int>(fogEnd)
            ));
            return;
        }

        static_cast<void>(stateManager->SetRenderState(
            D3DRS_FOGENABLE,
            0U
        ));

        D3DMATRIX projectionIdentity = {};
        projectionIdentity._11 = 1.0f;
        projectionIdentity._22 = 1.0f;
        projectionIdentity._33 = 1.0f;
        projectionIdentity._44 = 1.0f;
        static_cast<void>(stateManager->SetTransform(D3DTS_PROJECTION, &projectionIdentity));
    }

    /**
     * Address: 0x009461C0 (FUN_009461C0)
     *
     * What it does:
     * Selects and applies recovered D3D9 fill mode for wireframe toggle lanes.
     */
    int PipelineStateD3D9::SetWireframeState(const bool enabled)
    {
        const unsigned int fillMode = enabled ? D3DFILL_WIREFRAME : D3DFILL_SOLID;
        return GetStateManager()->SetRenderState(
            D3DRS_FILLMODE,
            fillMode
        );
    }

    /**
     * Address: 0x009461F0 (FUN_009461F0)
     *
     * What it does:
     * Rebuilds and applies retained color-write mask from two recovered toggle
     * lanes.
     */
    int PipelineStateD3D9::SetColorWriteState(const bool arg1, const bool arg2)
    {
        if (arg1)
        {
            colorWriteEnable_ = arg2 ? 0x0FU : 0x07U;
        }
        else
        {
            colorWriteEnable_ = arg2 ? 0x08U : 0x0FU;
        }

        return GetStateManager()->SetRenderState(
            D3DRS_COLORWRITEENABLE,
            colorWriteEnable_
        );
    }

    /**
     * Address: 0x00946260 (FUN_00946260)
     *
     * What it does:
     * Reapplies retained technique begin-state render-state defaults.
     */
    void PipelineStateD3D9::BeginTechnique()
    {
        StateManagerD3D9* const stateManager = GetStateManager();
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_COLORWRITEENABLE,
            colorWriteEnable_
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_ALPHABLENDENABLE,
            0U
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_ALPHATESTENABLE,
            0U
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_STENCILENABLE,
            0U
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_ZENABLE,
            1U
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_ZFUNC,
            D3DCMP_LESSEQUAL
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_ZWRITEENABLE,
            1U
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_DEPTHBIAS,
            0U
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_CULLMODE,
            D3DCULL_NONE
        ));
    }

    /**
     * Address: 0x00946300 (FUN_00946300)
     *
     * What it does:
     * Preserves the binary no-op end-technique lane.
     */
    void PipelineStateD3D9::EndTechnique() {}

    /**
     * Address: 0x00946240 (FUN_00946240)
     *
     * What it does:
     * Clears all 16 texture stages through the retained D3D9 state manager.
     */
    int PipelineStateD3D9::ClearTextures()
    {
        StateManagerD3D9* const stateManager = GetStateManager();
        int result = 0;
        for (unsigned int stageIndex = 0; stageIndex < 16U; ++stageIndex)
        {
            result = stateManager->SetTexture(stageIndex, nullptr);
        }
        return result;
    }

    /**
     * Address: 0x00946310 (FUN_00946310)
     *
     * What it does:
     * Returns the retained D3D9 state-manager interface pointer.
     */
    StateManagerD3D9* PipelineStateD3D9::GetStateManager()
    {
        return stateManager_;
    }

    /**
     * Address: 0x008F3AC0 (FUN_008F3AC0, ??0EffectTechniqueD3D9@gal@gpg@@QAE@@Z)
     *
     * What it does:
     * Keeps `name`, a weak reference to `effect` and the technique handle;
     * throws "invalid effect specified" (EffectTechniqueD3D9.cpp:36) when the
     * effect has already expired. The name is taken as given: the binary
     * runs `strlen` on it without a null check.
     */
    EffectTechniqueD3D9::EffectTechniqueD3D9(
        const char* const name,
        const boost::shared_ptr<EffectD3D9> effect,
        const D3DXHANDLE handle
    )
        : name_(name),
          effect_(effect),
          handle_(handle)
    {
        if (effect_.expired())
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 36, "invalid effect specified");
        }
    }

    /**
     * Address: 0x008F3A20 (FUN_008F3A20, ??1EffectTechniqueD3D9@gal@gpg@@QAE@XZ)
     * Address: 0x008F3AA0 (FUN_008F3AA0, the scalar deleting destructor)
     *
     * What it does:
     * Nothing of its own. The weak effect reference and the name go as
     * members, then the `EffectTechnique` base; the handle and the begin/end
     * flag are left as they are.
     */
    EffectTechniqueD3D9::~EffectTechniqueD3D9() = default;

    /**
     * Address: 0x008F3850 (FUN_008F3850)
     *
     * What it does:
     * Returns the local technique-name string lane.
     */
    msvc8::string* EffectTechniqueD3D9::GetName()
    {
        return &name_;
    }

    /**
     * Address: 0x008F3C40 (FUN_008F3C40)
     *
     * What it does:
     * Validates begin/end state, binds this technique on the effect, then begins the technique pass chain.
     */
    int EffectTechniqueD3D9::BeginTechnique()
    {
        if (beginEndActive_)
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 50, "effect technique begin/end mismatch");
        }

        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 53);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const HRESULT setTechniqueResult = dxEffect->SetTechnique(handle_);
        if (setTechniqueResult < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 58, setTechniqueResult);
        }

        ActiveDeviceD3D9().BeginTechnique();

        unsigned int passCount = 0U;
        const HRESULT beginResult = dxEffect->Begin(&passCount, 1U);
        if (beginResult < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 67, beginResult);
        }

        beginEndActive_ = true;
        return static_cast<int>(passCount);
    }

    /**
     * Address: 0x008F3EA0 (FUN_008F3EA0)
     *
     * What it does:
     * Validates begin/end state, ends the active technique, and clears local begin/end tracking.
     */
    void EffectTechniqueD3D9::EndTechnique()
    {
        if (!beginEndActive_)
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 76, "effect technique begin/end mismatch");
        }

        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 79);
        const HRESULT result = effect->GetDxEffect()->End();
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 84, result);
        }

        ActiveDeviceD3D9().EndTechnique();
        beginEndActive_ = false;
    }

    /**
     * Address: 0x00942EE0 (FUN_00942EE0)
     *
     * What it does:
     * Starts from an empty context (0x0093FBE0) and a null effect, then
     * adopts `context` and `effect` through `SetEffect`.
     */
    EffectD3D9::EffectD3D9(const EffectContext& context, ID3DXEffect* const effect)
    {
        SetEffect(context, effect);
    }

    /**
     * Address: 0x00942DD0 (FUN_00942DD0)
     * Address: 0x00942EC0 (FUN_00942EC0, the scalar deleting destructor)
     *
     * What it does:
     * `Reset()`. The context then goes as a member (0x0093F950), and the
     * `Effect` base and the weak-this as bases.
     */
    EffectD3D9::~EffectD3D9()
    {
        Reset();
    }

    /**
     * Address: 0x00942D60 (FUN_00942D60)
     *
     * What it does:
     * Releases the D3DX effect and assigns an empty context over the current
     * one: a temporary `EffectContext` (0x0093FBE0), `operator=` (0x00942CF0),
     * and the temporary's destructor (0x0093F950).
     */
    void EffectD3D9::Reset()
    {
        SafeRelease(dxEffect_);
        effectContext_ = EffectContext();
    }

    /**
     * Address: 0x00942E50 (FUN_00942E50)
     *
     * What it does:
     * Resets, copies `context` (0x00942CF0), adopts `effect`, then empties the
     * copied source buffer -- the effect keeps the settings but not the bytes.
     */
    void EffectD3D9::SetEffect(const EffectContext& context, ID3DXEffect* const effect)
    {
        Reset();
        effectContext_ = context;
        dxEffect_ = effect;
        effectContext_.mSourceBuffer.Reset();
    }

    /**
     * Address: 0x009415B0 (FUN_009415B0)
     *
     * What it does:
     * Returns the embedded effect-context lane.
     */
    EffectContext* EffectD3D9::GetContext()
    {
        return &effectContext_;
    }

    /**
     * Address: 0x00942350 (FUN_00942350)
     *
     * What it does:
     * Returns the retained D3DX effect interface and throws when missing.
     */
    ID3DXEffect* EffectD3D9::GetDxEffect()
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 137, "attempt to retrieve invalid effect");
        }

        return dxEffect_;
    }

    /**
     * Address: 0x00942920 (FUN_00942920)
     *
     * What it does:
     * Walks the valid techniques (`FindNextValidTechnique`) and appends a
     * wrapper for each -- `push_back` 0x00942860 on the temporary
     * `shared_ptr<EffectTechnique>`, whose constructor the binary inlines
     * around `shared_count(EffectTechniqueD3D9*)` 0x009417B0.
     */
    void EffectD3D9::GetTechniques(msvc8::vector<boost::shared_ptr<EffectTechnique>>& outTechniques)
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 58, "invalid effect");
        }

        D3DXHANDLE technique = nullptr;
        HRESULT result = dxEffect_->FindNextValidTechnique(nullptr, &technique);
        while (SUCCEEDED(result) && technique != nullptr)
        {
            D3DXTECHNIQUE_DESC description{};
            result = dxEffect_->GetTechniqueDesc(technique, &description);
            if (FAILED(result))
            {
                ThrowGalErrorFromHresult("EffectD3D9.cpp", 66, result);
            }

            outTechniques.push_back(boost::shared_ptr<EffectTechnique>(
                new EffectTechniqueD3D9(description.Name, boost::SharedFromThis(*this), technique)
            ));
            result = dxEffect_->FindNextValidTechnique(technique, &technique);
        }
    }

    /**
     * Address: 0x00941D70 (FUN_00941D70)
     *
     * What it does:
     * Wraps the effect parameter called `variableName`, handing the wrapper
     * `shared_from_this()` (0x00941B90) as its effect; throws when the effect
     * or the parameter is missing.
     */
    boost::shared_ptr<EffectVariable> EffectD3D9::GetVariable(const char* const variableName)
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 76, "invalid effect");
        }

        const D3DXHANDLE parameterHandle = dxEffect_->GetParameterByName(nullptr, variableName);
        if (parameterHandle == nullptr)
        {
            char message[512] = {};
            std::snprintf(
                message,
                sizeof(message),
                "invalid effect variable requested: %s",
                (variableName != nullptr) ? variableName : ""
            );
            ThrowGalError("EffectD3D9.cpp", 79, message);
        }

        return boost::shared_ptr<EffectVariable>(
            new EffectVariableD3D9(variableName, boost::SharedFromThis(*this), parameterHandle)
        );
    }

    /**
     * Address: 0x00941F60 (FUN_00941F60)
     *
     * What it does:
     * Wraps the technique called `techniqueName`, handing the wrapper
     * `shared_from_this()` as its effect; throws when the effect or the
     * technique is missing.
     */
    boost::shared_ptr<EffectTechnique> EffectD3D9::GetTechnique(const char* const techniqueName)
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 86, "invalid effect");
        }

        const D3DXHANDLE techniqueHandle = dxEffect_->GetTechniqueByName(techniqueName);
        if (techniqueHandle == nullptr)
        {
            char message[512] = {};
            std::snprintf(
                message,
                sizeof(message),
                "invalid effect technique requested: %s",
                (techniqueName != nullptr) ? techniqueName : ""
            );
            ThrowGalError("EffectD3D9.cpp", 89, message);
        }

        return boost::shared_ptr<EffectTechnique>(
            new EffectTechniqueD3D9(techniqueName, boost::SharedFromThis(*this), techniqueHandle)
        );
    }

    /**
     * Address: 0x00942150 (FUN_00942150)
     *
     * What it does:
     * Rebinds the effect state manager from current pipeline state and forwards reset notification to D3DX.
     */
    void EffectD3D9::OnReset()
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 96, "invalid effect");
        }

        const boost::shared_ptr<PipelineState> pipelineState = Device::GetInstance()->GetPipelineState();

        StateManagerD3D9* const stateManager = static_cast<PipelineStateD3D9*>(pipelineState.get())->GetStateManager();
        static_cast<void>(dxEffect_->SetStateManager(stateManager));
        static_cast<void>(dxEffect_->OnResetDevice());
    }

    /**
     * Address: 0x00942290 (FUN_00942290)
     *
     * What it does:
     * Forwards device-lost notification to the retained D3DX effect.
     */
    void EffectD3D9::OnLost()
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 108, "invalid effect");
        }

        static_cast<void>(dxEffect_->OnLostDevice());
    }

    /**
     * Address: 0x00943060 (FUN_00943060)
     *
     * What it does:
     * Keeps `name`, a weak reference to `effect` and the parameter handle;
     * throws "invalid effect specified" (EffectVariableD3D9.cpp:37) when the
     * effect has already expired.
     */
    EffectVariableD3D9::EffectVariableD3D9(
        const char* const name,
        const boost::shared_ptr<EffectD3D9> effect,
        const D3DXHANDLE handle
    )
        : name_(name),
          effect_(effect),
          handle_(handle)
    {
        if (effect_.expired())
        {
            ThrowGalError("EffectVariableD3D9.cpp", 37, "invalid effect specified");
        }
    }

    /**
     * Address: 0x00942FC0 (FUN_00942FC0)
     * Address: 0x00943040 (FUN_00943040, the scalar deleting destructor)
     *
     * What it does:
     * Nothing of its own: the weak effect reference and the name go as
     * members, then the `EffectVariable` base.
     */
    EffectVariableD3D9::~EffectVariableD3D9() = default;

    /**
     * Address: 0x00942F80 (FUN_00942F80)
     *
     * What it does:
     * Returns the parameter name.
     */
    msvc8::string* EffectVariableD3D9::GetName()
    {
        return &name_;
    }

    /**
     * Address: 0x009431E0 (FUN_009431E0)
     *
     * What it does:
     * Writes one boolean parameter into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetBool(const bool value)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 52);
        const HRESULT result = effect->GetDxEffect()->SetBool(handle_, value ? TRUE : FALSE);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 57, result);
        }
    }

    /**
     * Address: 0x009433A0 (FUN_009433A0)
     *
     * What it does:
     * Writes one integer parameter into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetInt(const int value)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 63);
        const HRESULT result = effect->GetDxEffect()->SetInt(handle_, value);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 68, result);
        }
    }

    /**
     * Address: 0x00943710 (FUN_00943710)
     *
     * What it does:
     * Writes a single vector4 payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetVector(const float* const vector4)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 85);
        const HRESULT result = effect->GetDxEffect()->SetVector(handle_, reinterpret_cast<const D3DXVECTOR4*>(vector4));
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 90, result);
        }
    }

    /**
     * Address: 0x009438D0 (FUN_009438D0)
     *
     * What it does:
     * `ID3DXEffect::SetVectorArray` on this parameter, with the address of the
     * `vectors4` parameter itself as the data (`lea edx, [esp+0xA8]` at
     * 0x00943990, where slots 6, 7 and 12 load their pointer). D3DX therefore
     * reads the pointer and the stack above it, not the caller's vectors. The
     * D3D10 twin makes the same slip; nothing in the binary calls the slot.
     */
    void EffectVariableD3D9::SetVectorArray(const std::uint32_t count, const float* const vectors4)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 96);
        const HRESULT result =
            effect->GetDxEffect()->SetVectorArray(handle_, reinterpret_cast<const D3DXVECTOR4*>(&vectors4), count);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 101, result);
        }
    }

    /**
     * Address: 0x00943550 (FUN_00943550)
     *
     * What it does:
     * Writes one float parameter into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetFloat(const float value)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 74);
        const HRESULT result = effect->GetDxEffect()->SetFloat(handle_, value);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 79, result);
        }
    }

    /**
     * Address: 0x00943A90 (FUN_00943A90)
     *
     * What it does:
     * Writes a float-array payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetFloatArray(const std::uint32_t count, const float* const values)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 107);
        const HRESULT result = effect->GetDxEffect()->SetFloatArray(handle_, values, count);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 112, result);
        }
    }

    /**
     * Address: 0x00943C50 (FUN_00943C50)
     *
     * What it does:
     * Writes an untyped byte payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetValue(const void* const data, const std::uint32_t byteCount)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 118);
        const HRESULT result = effect->GetDxEffect()->SetValue(handle_, data, byteCount);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 123, result);
        }
    }

    /**
     * Address: 0x00943E10 (FUN_00943E10)
     *
     * What it does:
     * Writes a 4x4 matrix payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetMatrix4x4(const Matrix* const matrix)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 129);
        const HRESULT result = effect->GetDxEffect()->SetMatrix(handle_, reinterpret_cast<const D3DXMATRIX*>(matrix));
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 134, result);
        }
    }

    /**
     * Address: 0x00943FD0 (FUN_00943FD0)
     *
     * What it does:
     * Writes a matrix-array payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetMatrixArray(const std::uint32_t count, const Matrix* const matrices)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 140);
        const HRESULT result =
            effect->GetDxEffect()->SetMatrixArray(handle_, reinterpret_cast<const D3DXMATRIX*>(matrices), count);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 145, result);
        }
    }

    /**
     * Address: 0x009441A0 (FUN_009441A0)
     *
     * What it does:
     * Binds a texture wrapper lane (2D/volume/cube) to the backing D3DX effect parameter.
     */
    void EffectVariableD3D9::SetTexture(const boost::shared_ptr<Texture> texture)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 151);
        IDirect3DBaseTexture9* textureHandle = nullptr;

        if (texture)
        {
            auto* const textureD3D9 = static_cast<TextureD3D9*>(texture.get());
            textureHandle = textureD3D9->GetTexture1();
            if (textureHandle == nullptr)
            {
                textureHandle = textureD3D9->GetTexture2();
            }
            if (textureHandle == nullptr)
            {
                textureHandle = textureD3D9->GetTexture3();
            }
        }

        if (ProbeTexSetArmed() && gProbeTexSetBudget > 0) { // TEMPORARY PROBE (do not commit)
            D3DXPARAMETER_DESC desc{};
            ID3DXEffect* const dx = effect->GetDxEffect();
            const HRESULT dr = dx->GetParameterDesc(handle_, &desc);
            if (dr >= 0 && desc.Name != nullptr && std::strstr(desc.Name, "Decal") != nullptr) {
                --gProbeTexSetBudget;
                ::gpg::Warnf("[TEXSET] tech='%s' name='%s' native=%p", gProbeCurrentTechnique, desc.Name, static_cast<void*>(textureHandle));
            }
        }
        const HRESULT result = effect->GetDxEffect()->SetTexture(handle_, textureHandle);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 183, result);
        }
    }

    /**
     * Address: 0x00944420 (FUN_00944420)
     *
     * What it does:
     * Binds a colour render target's texture (`RenderTargetD3D9::GetTexture`,
     * not its surface) to this effect parameter; a null target unbinds it.
     */
    void EffectVariableD3D9::SetRenderTarget(const boost::shared_ptr<RenderTarget> renderTarget)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 189);
        IDirect3DTexture9* const textureHandle =
            (renderTarget.get() != nullptr) ? static_cast<RenderTargetD3D9*>(renderTarget.get())->GetTexture() : nullptr;

        const HRESULT result = effect->GetDxEffect()->SetTexture(handle_, textureHandle);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 201, result);
        }
    }

    /**
     * Address: 0x00944630 (FUN_00944630)
     *
     * What it does:
     * Binds a cube render target's texture (`CubeRenderTargetD3D9::GetTexture`,
     * 0x00941270, called at 0x00944705) to this effect parameter; a null
     * target unbinds it.
     */
    void EffectVariableD3D9::SetCubeRenderTarget(const boost::shared_ptr<CubeRenderTarget> cubeTarget)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 207);
        IDirect3DCubeTexture9* const textureHandle =
            (cubeTarget.get() != nullptr) ? static_cast<CubeRenderTargetD3D9*>(cubeTarget.get())->GetTexture() : nullptr;

        const HRESULT result = effect->GetDxEffect()->SetTexture(handle_, textureHandle);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 219, result);
        }
    }

    /**
     * Address: 0x00944840 (FUN_00944840)
     *
     * What it does:
     * Retrieves a boolean annotation from this parameter handle by name.
     */
    bool EffectVariableD3D9::GetAnnotationBool(bool* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 225);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const D3DXHANDLE annotationHandle = dxEffect->GetAnnotationByName(handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        int rawValue = 0;
        const HRESULT result = dxEffect->GetBool(annotationHandle, &rawValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 235, result);
        }

        *outValue = (rawValue == 1);
        return true;
    }

    /**
     * Address: 0x00944A10 (FUN_00944A10)
     *
     * What it does:
     * Retrieves an integer annotation from this parameter handle by name.
     */
    bool EffectVariableD3D9::GetAnnotationInt(int* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 245);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const D3DXHANDLE annotationHandle = dxEffect->GetAnnotationByName(handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const HRESULT result = dxEffect->GetInt(annotationHandle, outValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 254, result);
        }

        return true;
    }

    /**
     * Address: 0x00944BD0 (FUN_00944BD0)
     *
     * What it does:
     * Retrieves a float annotation from this parameter handle by name.
     */
    bool EffectVariableD3D9::GetAnnotationFloat(float* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 262);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const D3DXHANDLE annotationHandle = dxEffect->GetAnnotationByName(handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const HRESULT result = dxEffect->GetFloat(annotationHandle, outValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 271, result);
        }

        return true;
    }

    /**
     * Address: 0x00944D90 (FUN_00944D90)
     *
     * What it does:
     * Retrieves a string annotation from this parameter handle by name.
     */
    bool EffectVariableD3D9::GetAnnotationString(msvc8::string* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 279);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const D3DXHANDLE annotationHandle = dxEffect->GetAnnotationByName(handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const char* annotationText = nullptr;
        const HRESULT result = dxEffect->GetString(annotationHandle, &annotationText);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 289, result);
        }

        outValue->assign_owned(annotationText != nullptr ? annotationText : "");
        return true;
    }

    /**
     * Address: 0x008F4080 (FUN_008F4080)
     *
     * What it does:
     * Begins the selected pass on the active technique.
     */
    void EffectTechniqueD3D9::BeginPass(const int pass)
    {
        if (!beginEndActive_)
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 94, "effect technique begin/end mismatch");
        }

        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 97);
        std::strncpy(gProbeCurrentTechnique, name_.c_str(), 63); gProbeCurrentTechnique[63] = 0; // TEMPORARY PROBE (do not commit)
        const HRESULT result = effect->GetDxEffect()->BeginPass(static_cast<unsigned int>(pass));
        if (std::strcmp(gProbeCurrentTechnique, "TDecals") == 0) { // TEMPORARY PROBE (do not commit): force no mip filtering on decal samplers
            static unsigned sMipCalls = 0; static int sMipLevel = -1;
            if ((sMipCalls++ % 64u) == 0u) {
                char dir[512] = {}; std::size_t length = 0; sMipLevel = -1;
                if (::getenv_s(&length, dir, sizeof(dir), "FAF_TOGGLE_DIR") == 0 && length != 0u) {
                    for (int lv = 0; lv < 8 && sMipLevel < 0; ++lv) {
                        char path[600]; (void)std::snprintf(path, sizeof(path), "%s/decalmip%d.on", dir, lv);
                        if (::GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) sMipLevel = lv;
                    }
                }
            }
            { // TEMPORARY PROBE (do not commit): device cooperative level while decals draw
                static unsigned sCoopCalls = 0;
                if ((sCoopCalls++ % 128u) == 0u) {
                    void* const nd = ActiveDeviceD3D9().mDevice;
                    using test_coop_fn = HRESULT(STDMETHODCALLTYPE*)(void*);
                    const HRESULT coop = reinterpret_cast<test_coop_fn>((*reinterpret_cast<void***>(nd))[3])(nd);
                    if (coop != 0 || sCoopCalls <= 128u) { ::gpg::Warnf("[COOP] TestCooperativeLevel=%08lX", static_cast<long>(coop)); }
                }
            }
            if (sMipLevel >= 0) {
                PipelineStateD3D9* const ps = ActiveDeviceD3D9().mPipelineState.get();
                if (ps != nullptr) {
                    for (unsigned s = 0; s < 8; ++s) {
                        static_cast<void>(ps->GetStateManager()->SetSamplerState(s, static_cast<D3DSAMPLERSTATETYPE>(7U), 0U));
                        static_cast<void>(ps->GetStateManager()->SetSamplerState(s, static_cast<D3DSAMPLERSTATETYPE>(9U), static_cast<unsigned>(sMipLevel)));
                    }
                }
            }
        }
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 102, result);
        }
        // TEMPORARY PROBE (do not commit): dark-mesh triage. "<FAF_TOGGLE_DIR>\cullnone.on",
        // "cullcw.on" or "cullccw.on" force the cull mode after every pass begin.
        {
            static int sForcedCull = -1;
            static unsigned sCullToggleCalls = 0;
            if ((sCullToggleCalls++ % 300u) == 0u)
            {
                sForcedCull = -1;
                char dir[512] = {};
                std::size_t length = 0;
                if (::getenv_s(&length, dir, sizeof(dir), "FAF_TOGGLE_DIR") == 0 && length != 0u)
                {
                    char path[600];
                    (void)std::snprintf(path, sizeof(path), "%s\\cullnone.on", dir);
                    if (::GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) sForcedCull = 1;
                    (void)std::snprintf(path, sizeof(path), "%s\\cullcw.on", dir);
                    if (::GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) sForcedCull = 2;
                    (void)std::snprintf(path, sizeof(path), "%s\\cullccw.on", dir);
                    if (::GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) sForcedCull = 3;
                }
            }
            if (sForcedCull >= 0)
            {
                PipelineStateD3D9* const pipelineState = ActiveDeviceD3D9().mPipelineState.get();
                if (pipelineState != nullptr)
                {
                    static_cast<void>(pipelineState->GetStateManager()->SetRenderState(
                        static_cast<D3DRENDERSTATETYPE>(0x16U), static_cast<unsigned int>(sForcedCull)));
                }
            }
            // Technique bisect: log each distinct technique once; "skip_<name>.on" turns
            // off colour writes for that technique's passes so its draws vanish.
            {
                static char sSeen[64][64];
                static int sSeenCount = 0;
                static int sSkipMask[64];
                static unsigned sSkipToggleCalls = 0;
                const char* const name = name_.c_str();
                int slot = -1;
                for (int i = 0; i < sSeenCount; ++i)
                {
                    if (std::strncmp(sSeen[i], name, 63) == 0)
                    {
                        slot = i;
                        break;
                    }
                }
                if (slot < 0 && sSeenCount < 64)
                {
                    slot = sSeenCount++;
                    std::strncpy(sSeen[slot], name, 63);
                    sSeen[slot][63] = 0;
                    sSkipMask[slot] = 0;
                    ::gpg::Warnf("[TECHDIAG] technique '%s' first pass", name);
                }
                if (slot >= 0)
                {
                    if ((sSkipToggleCalls++ % 400u) == 0u)
                    {
                        char dir[512] = {};
                        std::size_t length = 0;
                        if (::getenv_s(&length, dir, sizeof(dir), "FAF_TOGGLE_DIR") == 0 && length != 0u)
                        {
                            for (int i = 0; i < sSeenCount; ++i)
                            {
                                char path[640];
                                (void)std::snprintf(path, sizeof(path), "%s\\skip_%s.on", dir, sSeen[i]);
                                sSkipMask[i] = (::GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
                            }
                        }
                    }
                    if (sSkipMask[slot] != 0)
                    {
                        PipelineStateD3D9* const pipelineState = ActiveDeviceD3D9().mPipelineState.get();
                        if (pipelineState != nullptr)
                        {
                            static_cast<void>(pipelineState->GetStateManager()->SetRenderState(
                                static_cast<D3DRENDERSTATETYPE>(0xA8U), 0U));
                        }
                    }
                }
            }
        }
    }

    /**
     * Address: 0x008F4260 (FUN_008F4260)
     *
     * What it does:
     * Ends the currently active pass on the technique.
     */
    void EffectTechniqueD3D9::EndPass()
    {
        if (!beginEndActive_)
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 107, "effect technique begin/end mismatch");
        }

        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 110);
        const HRESULT result = effect->GetDxEffect()->EndPass();
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 115, result);
        }
    }

    /**
     * Address: 0x008F4430 (FUN_008F4430)
     *
     * What it does:
     * Looks up and reads a bool annotation from the active technique.
     */
    bool EffectTechniqueD3D9::GetAnnotationBool(bool* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 121);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const D3DXHANDLE annotationHandle = dxEffect->GetAnnotationByName(handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        int rawValue = 0;
        const HRESULT result = dxEffect->GetBool(annotationHandle, &rawValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 131, result);
        }

        *outValue = (rawValue == 1);
        return true;
    }

    /**
     * Address: 0x008F4600 (FUN_008F4600)
     *
     * What it does:
     * Looks up and reads an integer annotation from the active technique.
     */
    bool EffectTechniqueD3D9::GetAnnotationInt(int* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 141);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const D3DXHANDLE annotationHandle = dxEffect->GetAnnotationByName(handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const HRESULT result = dxEffect->GetInt(annotationHandle, outValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 150, result);
        }

        return true;
    }

    /**
     * Address: 0x008F47C0 (FUN_008F47C0)
     *
     * What it does:
     * Looks up and reads a float annotation from the active technique.
     */
    bool EffectTechniqueD3D9::GetAnnotationFloat(float* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 158);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const D3DXHANDLE annotationHandle = dxEffect->GetAnnotationByName(handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const HRESULT result = dxEffect->GetFloat(annotationHandle, outValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 167, result);
        }

        return true;
    }

    /**
     * Address: 0x008F4980 (FUN_008F4980)
     *
     * What it does:
     * Looks up and reads a string annotation from the active technique.
     */
    bool EffectTechniqueD3D9::GetAnnotationString(msvc8::string* const outValue, const msvc8::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 175);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const D3DXHANDLE annotationHandle = dxEffect->GetAnnotationByName(handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const char* annotationText = nullptr;
        const HRESULT result = dxEffect->GetString(annotationHandle, &annotationText);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 185, result);
        }

        outValue->assign_owned(annotationText != nullptr ? annotationText : "");
        return true;
    }

    /**
     * Address: 0x008F4B90 (FUN_008F4B90)
     *
     * What it does:
     * Initializes one empty D3D9 index-buffer wrapper with default context
     * and cleared native/lock tracking lanes.
     */
    IndexBufferD3D9::IndexBufferD3D9()
        : context_()
        , d3dIndexBuffer_(nullptr)
        , locked_(false)
        , lockPadding_{}
        , indexData_(nullptr)
    {}

    /**
     * Address: 0x008F4DA0 (FUN_008F4DA0, gpg::gal::IndexBufferD3D9::IndexBufferD3D9)
     *
     * What it does:
     * Initializes one D3D9 index-buffer wrapper and binds the provided
     * context/native buffer payload.
     */
    IndexBufferD3D9::IndexBufferD3D9(
        const IndexBufferContext* const context,
        IDirect3DIndexBuffer9* const d3dIndexBuffer
    )
        : context_()
        , d3dIndexBuffer_(nullptr)
        , locked_(false)
        , lockPadding_{}
        , indexData_(nullptr)
    {
        static_cast<void>(SetBuffer(context, d3dIndexBuffer));
    }

    /**
     * Address: 0x008F4D10 (FUN_008F4D10, gpg::gal::IndexBufferD3D9::SetBuffer)
     *
     * What it does:
     * Releases any previous native index-buffer handle, resets context lanes,
     * then assigns one new context + native buffer payload.
     */
    std::uint32_t IndexBufferD3D9::SetBuffer(
        const IndexBufferContext* const context,
        IDirect3DIndexBuffer9* const d3dIndexBuffer
    )
    {
        ResetBufferState();

        context_.format_ = context->format_;
        context_.size_ = context->size_;
        context_.type_ = context->type_;
        d3dIndexBuffer_ = d3dIndexBuffer;
        return context_.type_;
    }

    /**
     * Address: 0x008F4C30 (FUN_008F4C30)
     *
     * What it does:
     * Releases the native index buffer and puts the context back to its
     * defaults. The destructor and `SetBuffer` inline it.
     */
    void IndexBufferD3D9::ResetBufferState()
    {
        SafeRelease(d3dIndexBuffer_);

        const IndexBufferContext resetContext{};
        context_.format_ = resetContext.format_;
        context_.size_ = resetContext.size_;
        context_.type_ = resetContext.type_;
    }

    /**
     * Address: 0x008F4C80 (FUN_008F4C80)
     * Address: 0x008F4D80 (FUN_008F4D80, slot 0: the scalar deleting destructor)
     *
     * What it does:
     * Releases the native index buffer and resets the context, then the
     * `IndexBuffer` base destructor runs (inlined, 0x008F4CFD).
     */
    IndexBufferD3D9::~IndexBufferD3D9()
    {
        ResetBufferState();
    }

    /**
     * Address: 0x008F5260 (FUN_008F5260)
     *
     * What it does:
     * An empty render target.
     */
    RenderTargetD3D9::RenderTargetD3D9()
        : context_()
        , surface_(nullptr)
        , texture_(nullptr)
    {}

    /**
     * Address: 0x008F5620 (FUN_008F5620)
     *
     * What it does:
     * Wraps `renderTexture` as a render target of `context`.
     */
    RenderTargetD3D9::RenderTargetD3D9(const RenderTargetContext* const context, IDirect3DTexture9* const renderTexture)
        : context_()
        , surface_(nullptr)
        , texture_(nullptr)
    {
        SetRenderTexture(context, renderTexture);
    }

    /**
     * Address: 0x008F5470 (FUN_008F5470)
     *
     * What it does:
     * Wraps a surface that has no texture behind it - a head's back buffer
     * (`DeviceD3D9::CreateHeads`).
     */
    RenderTargetD3D9::RenderTargetD3D9(IDirect3DSurface9* const backBufferSurface)
        : context_()
        , surface_(nullptr)
        , texture_(nullptr)
    {
        SetSurface(backBufferSurface);
    }

    /**
     * Address: 0x008F53B0 (FUN_008F53B0)
     * Address: 0x008F5450 (FUN_008F5450, scalar deleting destructor)
     *
     * What it does:
     * Releases the surface and the texture.
     */
    RenderTargetD3D9::~RenderTargetD3D9()
    {
        Reset();
    }

    /**
     * Address: 0x008F5350 (FUN_008F5350)
     *
     * What it does:
     * Releases the surface and the texture and empties the context.
     */
    void RenderTargetD3D9::Reset()
    {
        SafeRelease(surface_);
        SafeRelease(texture_);
        context_ = RenderTargetContext();
    }

    /**
     * Address: 0x008F5410 (FUN_008F5410)
     *
     * What it does:
     * Takes `surface` over and sizes the context from its description.
     */
    void RenderTargetD3D9::SetSurface(IDirect3DSurface9* const surface)
    {
        Reset();
        surface_ = surface;

        D3DSURFACE_DESC surfaceDesc;
        surface_->GetDesc(&surfaceDesc);
        context_.width_ = surfaceDesc.Width;
        context_.height_ = surfaceDesc.Height;
    }

    /**
     * Address: 0x008F5500 (FUN_008F5500)
     *
     * What it does:
     * Takes `renderTexture` over as the target of `context` and renders into
     * its top level; the context is resized to that surface. Undoes itself
     * when the surface cannot be had.
     */
    void RenderTargetD3D9::SetRenderTexture(const RenderTargetContext* const context, IDirect3DTexture9* const renderTexture)
    {
        Reset();
        context_ = *context;
        texture_ = renderTexture;
        try
        {
            const HRESULT result = texture_->GetSurfaceLevel(0U, &surface_);
            if (FAILED(result))
            {
                ThrowGalErrorFromHresult("RenderTargetD3D9.cpp", 89, result);
            }

            D3DSURFACE_DESC surfaceDesc;
            surface_->GetDesc(&surfaceDesc);
            context_.width_ = surfaceDesc.Width;
            context_.height_ = surfaceDesc.Height;
        }
        catch (...)
        {
            Reset();
            throw;
        }
    }

    /**
     * Address: 0x008F52C0 (FUN_008F52C0)
     *
     * What it does:
     * Returns the target's context.
     */
    RenderTargetContext* RenderTargetD3D9::GetContext()
    {
        return &context_;
    }

    /**
     * Address: 0x008F52D0 (FUN_008F52D0, Moho::D3DSurface::GetSurface)
     * Mangled: ?GetSurface@D3DSurface@Moho@@QAEPAUIDirect3DSurface9@@XZ
     *
     * What it does:
     * Returns the surface rendered into.
     */
    IDirect3DSurface9* RenderTargetD3D9::GetSurface()
    {
        return surface_;
    }

    /**
     * Address: 0x008F52E0 (FUN_008F52E0)
     *
     * What it does:
     * Returns the texture behind the surface, for
     * `EffectVariableD3D9::SetRenderTarget` to bind through `ID3DXEffect::SetTexture`.
     */
    IDirect3DTexture9* RenderTargetD3D9::GetTexture()
    {
        return texture_;
    }

    /**
     * Address: 0x008F5300 (FUN_008F5300)
     *
     * What it does:
     * A GDI device context on the surface, or null when the target has no
     * surface (`cmp [ecx+0x14],0; je` at 0x008F5301).
     */
    HDC RenderTargetD3D9::GetDC()
    {
        if (surface_ == nullptr)
        {
            return nullptr;
        }

        HDC deviceContext = nullptr;
        surface_->GetDC(&deviceContext);
        return deviceContext;
    }

    /**
     * Address: 0x008E7EB0 (FUN_008E7EB0)
     *
     * What it does:
     * An empty depth-stencil target.
     */
    DepthStencilTargetD3D9::DepthStencilTargetD3D9()
        : context_()
        , depthStencilSurface_(nullptr)
    {}

    /**
     * Address: 0x008E8110 (FUN_008E8110)
     *
     * What it does:
     * Wraps `depthStencilSurface` as a depth-stencil target of `context`.
     */
    DepthStencilTargetD3D9::DepthStencilTargetD3D9(
        const DepthStencilTargetContext* const context,
        IDirect3DSurface9* const depthStencilSurface
    )
        : context_()
        , depthStencilSurface_(nullptr)
    {
        SetSurface(context, depthStencilSurface);
    }

    /**
     * Address: 0x008E7FD0 (FUN_008E7FD0)
     * Address: 0x008E80F0 (FUN_008E80F0, scalar deleting destructor)
     *
     * What it does:
     * Releases the surface.
     */
    DepthStencilTargetD3D9::~DepthStencilTargetD3D9()
    {
        Reset();
    }

    /**
     * Address: 0x008E7F80 (FUN_008E7F80)
     *
     * What it does:
     * Releases the surface and empties the context. The destructor and
     * `SetSurface` inline it.
     */
    void DepthStencilTargetD3D9::Reset()
    {
        SafeRelease(depthStencilSurface_);
        context_ = DepthStencilTargetContext();
    }

    /**
     * Address: 0x008E7F00 (FUN_008E7F00)
     *
     * What it does:
     * Returns the target's context.
     */
    DepthStencilTargetContext* DepthStencilTargetD3D9::GetContext()
    {
        return &context_;
    }

    /**
     * Address: 0x008E7F40 (FUN_008E7F40)
     *
     * What it does:
     * Returns the depth-stencil surface.
     */
    IDirect3DSurface9* DepthStencilTargetD3D9::GetSurface() const
    {
        return depthStencilSurface_;
    }

    /**
     * Address: 0x008E8070 (FUN_008E8070)
     *
     * What it does:
     * Replaces the surface and the context.
     */
    void DepthStencilTargetD3D9::SetSurface(
        const DepthStencilTargetContext* const context,
        IDirect3DSurface9* const depthStencilSurface
    )
    {
        Reset();
        context_ = *context;
        depthStencilSurface_ = depthStencilSurface;
    }

    /**
     * Address: 0x009411E0 (FUN_009411E0)
     *
     * What it does:
     * An empty cube render target.
     */
    CubeRenderTargetD3D9::CubeRenderTargetD3D9()
        : context_()
        , cubeTexture_(nullptr)
        , faceSurfaces_{}
    {}

    /**
     * Address: 0x00941450 (FUN_00941450)
     *
     * What it does:
     * Wraps `cubeTexture` as a cube render target of `context`.
     */
    CubeRenderTargetD3D9::CubeRenderTargetD3D9(
        const CubeRenderTargetContext* const context,
        IDirect3DCubeTexture9* const cubeTexture
    )
        : context_()
        , cubeTexture_(nullptr)
        , faceSurfaces_{}
    {
        SetTexture(context, cubeTexture);
    }

    /**
     * Address: 0x00941330 (FUN_00941330)
     * Address: 0x00941430 (FUN_00941430, scalar deleting destructor)
     *
     * What it does:
     * Releases the face surfaces and the texture.
     */
    CubeRenderTargetD3D9::~CubeRenderTargetD3D9()
    {
        Reset();
    }

    /**
     * Address: 0x009412B0 (FUN_009412B0)
     *
     * What it does:
     * Releases the six face surfaces, then the cube texture, and empties the
     * context.
     */
    void CubeRenderTargetD3D9::Reset()
    {
        for (IDirect3DSurface9*& faceSurface : faceSurfaces_)
        {
            SafeRelease(faceSurface);
        }
        std::memset(faceSurfaces_, 0, sizeof(faceSurfaces_));

        SafeRelease(cubeTexture_);
        context_ = CubeRenderTargetContext();
    }

    /**
     * Address: 0x00941390 (FUN_00941390)
     *
     * What it does:
     * Takes `cubeTexture` over as the target of `context` and holds the top
     * level of each face. Undoes itself if that throws.
     */
    void CubeRenderTargetD3D9::SetTexture(
        const CubeRenderTargetContext* const context,
        IDirect3DCubeTexture9* const cubeTexture
    )
    {
        Reset();
        context_ = *context;
        cubeTexture_ = cubeTexture;
        try
        {
            for (int face = 0; face < kCubeFaceCount; ++face)
            {
                cubeTexture_->GetCubeMapSurface(static_cast<D3DCUBEMAP_FACES>(face), 0U, &faceSurfaces_[face]);
            }
        }
        catch (...)
        {
            Reset();
            throw;
        }
    }

    /**
     * Address: 0x00941240 (FUN_00941240)
     *
     * What it does:
     * Returns the target's context.
     */
    CubeRenderTargetContext* CubeRenderTargetD3D9::GetContext()
    {
        return &context_;
    }

    /**
     * Address: 0x009414D0 (FUN_009414D0)
     *
     * What it does:
     * Returns the top-level surface of `face`. Only the upper bound is
     * checked (`cmp eax,6; jl`).
     */
    IDirect3DSurface9* CubeRenderTargetD3D9::GetSurface(const int face) const
    {
        if (face >= kCubeFaceCount)
        {
            ThrowGalError("CubeRenderTargetD3D9.cpp", 104, "invalid cube face index specified");
        }

        return faceSurfaces_[face];
    }

    /**
     * Address: 0x00941270 (FUN_00941270)
     *
     * What it does:
     * Returns the cube texture.
     */
    IDirect3DCubeTexture9* CubeRenderTargetD3D9::GetTexture() const
    {
        return cubeTexture_;
    }

    /**
     * Address: 0x008F4BE0 (FUN_008F4BE0)
     *
     * What it does:
     * Returns the context the buffer was created from.
     */
    IndexBufferContext* IndexBufferD3D9::GetContext()
    {
        return &context_;
    }

    /**
     * Address: 0x008F4E10 (FUN_008F4E10)
     *
     * What it does:
     * Locks the retained D3D9 index buffer and returns mapped index data.
     */
    std::int16_t* IndexBufferD3D9::Lock(
        const unsigned int offset,
        const unsigned int size,
        const MohoD3DLockFlags lockFlags
    )
    {
        if (d3dIndexBuffer_ == nullptr)
        {
            ThrowGalError("IdxBufD3D9.cpp", 56, "lock invalid");
        }

        if (locked_)
        {
            ThrowGalError("IdxBufD3D9.cpp", 57, "lock mismatch");
        }

        const HRESULT result = d3dIndexBuffer_->Lock(offset, size, reinterpret_cast<void**>(&indexData_), ToIndexBufferLockFlags(lockFlags));

        if (result < 0)
        {
            ThrowGalErrorFromHresult("IdxBufD3D9.cpp", 65, result);
        }

        locked_ = true;
        return indexData_;
    }

    /**
     * Address: 0x008F4FF0 (FUN_008F4FF0)
     *
     * What it does:
     * Unlocks the retained D3D9 index buffer and clears lock-tracking state.
     */
    void IndexBufferD3D9::Unlock()
    {
        if (d3dIndexBuffer_ == nullptr)
        {
            ThrowGalError("IdxBufD3D9.cpp", 73, "unlock invalid");
        }

        if (!locked_)
        {
            ThrowGalError("IdxBufD3D9.cpp", 74, "lock mismatch");
        }

        const HRESULT result = d3dIndexBuffer_->Unlock();
        if (result < 0)
        {
            ThrowGalErrorFromHresult("IdxBufD3D9.cpp", 77, result);
        }

        locked_ = false;
        indexData_ = nullptr;
    }

    /**
     * Address: 0x008F5190 (FUN_008F5190, gpg::gal::IndexBufferD3D9::GetBuffer)
     *
     * What it does:
     * Returns the retained D3D9 index-buffer handle and throws when unset.
     */
    IDirect3DIndexBuffer9* IndexBufferD3D9::GetBuffer()
    {
        if (d3dIndexBuffer_ == nullptr)
        {
            ThrowGalError("IndexBufferD3D9.cpp", 105, "invalid index buffer");
        }

        return d3dIndexBuffer_;
    }

    /**
     * Address: 0x0094A030 (FUN_0094A030)
     *
     * What it does:
     * Initializes vtable/context/resource state for a new D3D9 texture wrapper.
     */
    TextureD3D9::TextureD3D9() = default;

    /**
     * Address: 0x0094AB80 (FUN_0094AB80, gpg::gal::TextureD3D9::TextureD3D9)
     *
     * What it does:
     * Initializes one texture wrapper and binds caller context plus one native
     * texture payload.
     */
    TextureD3D9::TextureD3D9(
        const TextureContext* const context,
        IDirect3DBaseTexture9* const texture
    )
        : context_()
        , texture_(nullptr)
        , locking_(false)
        , lockPadding_{}
        , level_(0)
    {
        SetTexture(context, texture);
    }

    /**
     * Address: 0x0094AB60 (FUN_0094AB60)
     *
     * What it does:
     * Owns the deleting-destructor path and delegates to `FUN_0094AA90` body semantics.
     */
    TextureD3D9::~TextureD3D9()
    {
        DestroyTextureD3D9Body(this);
    }

    /**
     * Address: 0x0094A080 (FUN_0094A080)
     *
     * What it does:
     * Returns the embedded texture-context state block at `this+0x04`.
     */
    TextureContext* TextureD3D9::GetContext()
    {
        return &context_;
    }

    /**
     * Address: 0x0094A0A0 (FUN_0094A0A0)
     *
     * What it does:
     * Returns the texture as a 2D texture when the context type is 2D (`1`).
     */
    IDirect3DTexture9* TextureD3D9::GetTexture1() const
    {
        if (context_.type_ == 1U)
        {
            return static_cast<IDirect3DTexture9*>(texture_);
        }

        return nullptr;
    }

    /**
     * Address: 0x0094A0B0 (FUN_0094A0B0)
     *
     * What it does:
     * Returns the texture as a cube texture when the context type is cube (`2`).
     */
    IDirect3DCubeTexture9* TextureD3D9::GetTexture2() const
    {
        if (context_.type_ == 2U)
        {
            return static_cast<IDirect3DCubeTexture9*>(texture_);
        }

        return nullptr;
    }

    /**
     * Address: 0x0094A0C0 (FUN_0094A0C0)
     *
     * What it does:
     * Returns the texture as a volume texture when the context type is volume (`3`).
     */
    IDirect3DVolumeTexture9* TextureD3D9::GetTexture3() const
    {
        if (context_.type_ == 3U)
        {
            return static_cast<IDirect3DVolumeTexture9*>(texture_);
        }

        return nullptr;
    }

    /**
     * Address: 0x0094AAF0 (FUN_0094AAF0)
     *
     * What it does:
     * Resets prior texture state, copies caller context metadata, assigns a
     * new native texture handle, and clears copied source-data lanes.
     */
    void TextureD3D9::SetTexture(
        const TextureContext* const context,
        IDirect3DBaseTexture9* const texture
    )
    {
        Reset();
        context_.AssignFrom(*context);
        texture_ = texture;
        context_.ClearDataBuffer();
    }

    /**
     * Address: 0x0094A150 (FUN_0094A150)
     *
     * What it does:
     * Locks one level of the 2D texture and returns the mapping. The caller's
     * rect is always copied; an empty one (`left == right`, the
     * `sub/neg/sbb/and` at 0x0094A341) locks the whole level.
     */
    TextureLockRect TextureD3D9::Lock(const int level, const RECT& rect, const int flags)
    {
        if (texture_ == nullptr)
        {
            ThrowGalError("TexD3D9.cpp", 62, "lock invalid tex");
        }

        if (level >= static_cast<int>(context_.mipmapLevels_))
        {
            ThrowGalError("TexD3D9.cpp", 63, "lock invalid lvl");
        }

        if (locking_)
        {
            ThrowGalError("TexD3D9.cpp", 64, "tex lock mismatch");
        }

        if (context_.type_ != 1U)
        {
            ThrowGalError("TexD3D9.cpp", 65, "lock only 2D");
        }

        D3DLOCKED_RECT lockedRect{};

        RECT copiedRect = rect;
        const RECT* const d3dRect = (copiedRect.left != copiedRect.right) ? &copiedRect : nullptr;

        // A 2D texture (checked above), used as one directly.
        const HRESULT result = static_cast<IDirect3DTexture9*>(texture_)->LockRect(
            static_cast<UINT>(level), &lockedRect, d3dRect, ToTextureLockFlags(flags)
        );
        if (result < 0)
        {
            ThrowGalErrorFromHresult("TexD3D9.cpp", 80, result);
        }

        level_ = level;
        TextureLockRect lock{};
        lock.flags = flags;
        lock.level = level;
        lock.pitch = lockedRect.Pitch;
        lock.bits = lockedRect.pBits;
        locking_ = true;
        return lock;
    }

    /**
     * Address: 0x0094A410 (FUN_0094A410)
     *
     * What it does:
     * Unlocks the active texture level and clears lock-tracking state.
     */
    int TextureD3D9::Unlock(const int level)
    {
        if (texture_ == nullptr)
        {
            ThrowGalError("TexD3D9.cpp", 116, "unlock invalid");
        }

        if (level != level_)
        {
            ThrowGalError("TexD3D9.cpp", 117, "unlock bad lvl");
        }

        if (!locking_)
        {
            ThrowGalError("TexD3D9.cpp", 118, "tex lock mismatch");
        }

        const HRESULT result = GetTexture1()->UnlockRect(static_cast<UINT>(level));
        if (result < 0)
        {
            ThrowGalErrorFromHresult("TexD3D9.cpp", 123, result);
        }

        locking_ = false;
        level_ = 0;
        return result;
    }

    /**
     * Address: 0x0094A090 (FUN_0094A090)
     *
     * What it does:
     * Releases one mapping by unlocking its level - a virtual call to slot 3
     * (`mov eax,[ecx]; call [eax+0xC]`), `ret 0x10` for the by-value rect.
     */
    int TextureD3D9::Unlock(const TextureLockRect lock)
    {
        return Unlock(lock.level);
    }

    /**
     * Address: 0x0094A630 (FUN_0094A630)
     *
     * What it does:
     * Serializes level-0 texture surface bytes into the caller-provided memory buffer.
     */
    void TextureD3D9::SaveToBuffer(gpg::MemBuffer<char>* const outBuffer)
    {
        if (texture_ == nullptr)
        {
            ThrowGalError("TexD3D9.cpp", 131, "attempt to unlock invalid texture");
        }

        if (context_.type_ != 1U)
        {
            ThrowGalError("TexD3D9.cpp", 132, "currently allowed to only save 2D textures");
        }

        // A 2D texture (checked above), used as one directly.
        IDirect3DSurface9* surface;
        CheckD3DCall("TexD3D9.cpp", 136, [&] {
            return static_cast<IDirect3DTexture9*>(texture_)->GetSurfaceLevel(0U, &surface);
        });

        // The encode replaces the buffer made here without releasing it, as
        // in DeviceD3D9::SaveTexture.
        ID3DXBuffer* fileBuffer;
        CheckD3DCall("TexD3D9.cpp", 139, [&] { return D3DXCreateBuffer(0U, &fileBuffer); });
        CheckD3DCall("TexD3D9.cpp", 140, [&] {
            return D3DXSaveSurfaceToFileInMemory(&fileBuffer, D3DXIFF_DDS, surface, nullptr, nullptr);
        });

        if (outBuffer->Size() != fileBuffer->GetBufferSize())
        {
            *outBuffer = gpg::AllocMemBuffer(fileBuffer->GetBufferSize());
        }
        std::memcpy(outBuffer->GetPtr(0U, 0U), fileBuffer->GetBufferPointer(), fileBuffer->GetBufferSize());

        surface->Release();
        fileBuffer->Release();
    }

    /**
     * Address: 0x0094A980 (FUN_0094A980)
     *
     * What it does:
     * Resets texture resources and reinitializes context state.
     */
    void TextureD3D9::Reset()
    {
        if (locking_)
        {
            Unlock(level_);
        }

        const auto type = context_.type_;
        const bool knownType = (type == 1U) || (type == 2U) || (type == 3U);
        if (!knownType && texture_ != nullptr)
        {
            ThrowGalError("TexD3D9.cpp", 198, "unknown tex type");
        }

        SafeRelease(texture_);

        const TextureContext resetContext{};
        context_.AssignFrom(resetContext);
        texture_ = nullptr;
    }

    /**
     * Address: 0x00949F80 (FUN_00949F80)
     *
     * What it does:
     * Initializes pipeline-state defaults and binds one state-manager instance
     * to the supplied native D3D9 device.
     */
    PipelineStateD3D9::PipelineStateD3D9(IDirect3DDevice9* const nativeDevice)
    {
        stateManager_ = nullptr;
        colorWriteEnable_ = 0x0FU;

        stateManager_ = new StateManagerD3D9(nativeDevice);
        if (stateManager_ != nullptr)
        {
            stateManager_->AddRef();
        }
    }

    /**
     * Address: 0x00945730 (FUN_00945730)
     *
     * What it does:
     * Reapplies baseline D3D9 render/sampler/texture-stage state defaults.
     */
    int PipelineStateD3D9::InitState()
    {
        auto* const stateManager = GetStateManager();
        if (stateManager == nullptr)
        {
            return -1;
        }

        const auto setRenderState = [stateManager](const unsigned int state, const unsigned int value) {
            static_cast<void>(stateManager->SetRenderState(static_cast<D3DRENDERSTATETYPE>(state), value));
        };
        const auto setRenderStateFlt = [stateManager](const unsigned int state, const float value) {
            static_cast<void>(stateManager->SetRenderStateFlt(static_cast<D3DRENDERSTATETYPE>(state), value));
        };
        const auto setSamplerState = [stateManager](
                                         const unsigned int sampler,
                                         const unsigned int state,
                                         const unsigned int value
                                     ) {
            static_cast<void>(
                stateManager->SetSamplerState(sampler, static_cast<D3DSAMPLERSTATETYPE>(state), value)
            );
        };
        const auto setTextureStageState = [stateManager](
                                               const unsigned int stage,
                                               const unsigned int state,
                                               const unsigned int value
                                           ) {
            return stateManager->SetTextureStageState(
                stage,
                static_cast<D3DTEXTURESTAGESTATETYPE>(state),
                value
            );
        };
        const auto setTextureStageStateFlt = [stateManager](
                                                  const unsigned int stage,
                                                  const unsigned int state,
                                                  const float value
                                              ) {
            static_cast<void>(
                stateManager->SetTextureStageStateFlt(
                    stage,
                    static_cast<D3DTEXTURESTAGESTATETYPE>(state),
                    value
                )
            );
        };

        static constexpr struct RenderStateInit final
        {
            unsigned int state = 0U;
            unsigned int value = 0U;
        } kRenderStates[] = {
            {7U, 1U},
            {8U, 3U},
            {9U, 2U},
            {14U, 1U},
            {15U, 0U},
            {16U, 1U},
            {19U, 2U},
            {20U, 1U},
            {22U, 1U},
            {23U, 8U},
            {24U, 0U},
            {25U, 8U},
            {26U, 0U},
            {27U, 0U},
            {28U, 0U},
            {29U, 0U},
            {34U, 0U},
            {35U, 0U},
            {48U, 0U},
            {52U, 0U},
            {53U, 1U},
            {54U, 1U},
            {55U, 1U},
            {56U, 8U},
            {57U, 0U},
            {58U, 0xFFFFFFFFU},
            {59U, 0xFFFFFFFFU},
            {60U, 0U},
            {128U, 0U},
            {129U, 0U},
            {130U, 0U},
            {131U, 0U},
            {132U, 0U},
            {133U, 0U},
            {134U, 0U},
            {135U, 0U},
            {136U, 1U},
            {137U, 1U},
            {139U, 0U},
            {140U, 0U},
            {141U, 1U},
            {142U, 0U},
            {143U, 1U},
            {145U, 1U},
            {146U, 2U},
            {147U, 0U},
            {148U, 0U},
            {151U, 0U},
            {152U, 0U},
            {156U, 0U},
            {157U, 0U},
            {161U, 1U},
            {162U, 0xFFFFFFFFU},
            {163U, 0U},
            {167U, 0U},
            {168U, 0x0FU},
            {171U, 1U},
            {172U, 3U},
            {173U, 1U},
            {174U, 0U},
            {176U, 0U},
            {184U, 0U},
            {185U, 0U},
            {186U, 1U},
            {187U, 1U},
            {188U, 1U},
            {189U, 8U},
            {190U, 0x0FU},
            {191U, 0x0FU},
            {192U, 0x0FU},
            {193U, 0xFFFFFFFFU},
            {194U, 0U},
            {198U, 0U},
            {199U, 0U},
            {200U, 0U},
            {201U, 0U},
            {202U, 0U},
            {203U, 0U},
            {204U, 0U},
            {205U, 0U},
            {206U, 0U},
            {207U, 2U},
            {208U, 1U},
            {209U, 1U},
        };

        static constexpr struct RenderStateFloatInit final
        {
            unsigned int state = 0U;
            float value = 0.0f;
        } kRenderStateFloats[] = {
            {36U, 0.0f},
            {37U, 1.0f},
            {38U, 1.0f},
            {154U, 1.0f},
            {155U, 1.0f},
            {158U, 1.0f},
            {159U, 0.0f},
            {160U, 0.0f},
            {166U, 64.0f},
            {170U, 0.0f},
            {175U, 0.0f},
            {178U, 1.0f},
            {179U, 1.0f},
            {180U, 1.0f},
            {181U, 1.0f},
            {182U, 1.0f},
            {183U, 1.0f},
            {195U, 0.0f},
        };

        for (const auto& state : kRenderStates)
        {
            setRenderState(state.state, state.value);
        }

        for (const auto& state : kRenderStateFloats)
        {
            setRenderStateFlt(state.state, state.value);
        }

        for (unsigned int sampler = 0U; sampler < 16U; ++sampler)
        {
            setSamplerState(sampler, 1U, 1U);
            setSamplerState(sampler, 2U, 1U);
            setSamplerState(sampler, 3U, 1U);
            setSamplerState(sampler, 4U, 0U);
            setSamplerState(sampler, 5U, 2U);
            setSamplerState(sampler, 6U, 2U);
            setSamplerState(sampler, 7U, 0U);
            setSamplerState(sampler, 8U, 0U);
            setSamplerState(sampler, 9U, 0U);
            setSamplerState(sampler, 10U, 1U);
            setSamplerState(sampler, 11U, 0U);
            setSamplerState(sampler, 12U, 0U);
            setSamplerState(sampler, 13U, 256U);
        }

        for (unsigned int stage = 0U; stage < 8U; ++stage)
        {
            static_cast<void>(setTextureStageState(stage, 1U, 1U));
            static_cast<void>(setTextureStageState(stage, 2U, 2U));
            static_cast<void>(setTextureStageState(stage, 3U, 1U));
            static_cast<void>(setTextureStageState(stage, 4U, 1U));
            static_cast<void>(setTextureStageState(stage, 5U, 2U));
            static_cast<void>(setTextureStageState(stage, 6U, 1U));
            setTextureStageStateFlt(stage, 7U, 0.0f);
            setTextureStageStateFlt(stage, 8U, 0.0f);
            setTextureStageStateFlt(stage, 9U, 0.0f);
            setTextureStageStateFlt(stage, 10U, 0.0f);
            static_cast<void>(setTextureStageState(stage, 11U, stage));
            setTextureStageStateFlt(stage, 22U, 0.0f);
            setTextureStageStateFlt(stage, 23U, 0.0f);
            static_cast<void>(setTextureStageState(stage, 24U, 0U));
            static_cast<void>(setTextureStageState(stage, 26U, 1U));
            static_cast<void>(setTextureStageState(stage, 27U, 1U));
            static_cast<void>(setTextureStageState(stage, 28U, 1U));
            static_cast<void>(setTextureStageState(stage, 32U, 0U));
        }

        static_cast<void>(setTextureStageState(0U, 1U, 4U));
        return setTextureStageState(0U, 4U, 2U);
    }

    /**
     * Address: 0x00946BE0 (FUN_00946BE0)
     * Address: 0x00946F10 (FUN_00946F10, slot 0: the scalar deleting destructor)
     *
     * What it does:
     * Releases the effect state manager, then the `PipelineState` base
     * destructor runs (inlined, 0x00946C27).
     */
    PipelineStateD3D9::~PipelineStateD3D9()
    {
        SafeRelease(stateManager_);
    }

    /**
     * Address: 0x008F56B0 (FUN_008F56B0)
     *
     * What it does:
     * Initializes one empty D3D9 vertex-buffer wrapper with default
     * context/resource lanes.
     */
    VertexBufferD3D9::VertexBufferD3D9()
        : context_()
        , d3dVertexBuffer_(nullptr)
        , locked_(false)
        , lockPadding_{}
        , mappedData_(nullptr)
    {
    }

    /**
     * Address: 0x008F58E0 (FUN_008F58E0, gpg::gal::VertexBufferD3D9::VertexBufferD3D9)
     *
     * What it does:
     * Initializes one D3D9 vertex-buffer wrapper and binds the provided
     * context/native buffer payload.
     */
    VertexBufferD3D9::VertexBufferD3D9(
        const VertexBufferContext* const context,
        IDirect3DVertexBuffer9* const d3dVertexBuffer
    )
        : VertexBufferD3D9()
    {
        SetBuffer(context, d3dVertexBuffer);
    }

    /**
     * Address: 0x008F5760 (FUN_008F5760)
     *
     * What it does:
     * Releases any retained native vertex-buffer handle and restores
     * the embedded context lanes to default values.
     */
    void VertexBufferD3D9::ResetBufferState()
    {
        SafeRelease(d3dVertexBuffer_);

        const VertexBufferContext resetContext{};
        context_.AssignFrom(resetContext);
    }

    /**
     * Address: 0x008F5850 (FUN_008F5850)
     *
     * What it does:
     * Releases any previous native vertex-buffer handle, resets context lanes,
     * then assigns one new context + native buffer payload.
     */
    void VertexBufferD3D9::SetBuffer(
        const VertexBufferContext* const context,
        IDirect3DVertexBuffer9* const d3dVertexBuffer
    )
    {
        ResetBufferState();
        context_.AssignFrom(*context);
        d3dVertexBuffer_ = d3dVertexBuffer;
    }

    /**
     * Address: 0x008F57B0 (FUN_008F57B0)
     * Address: 0x008F58C0 (FUN_008F58C0, slot 0: the scalar deleting destructor)
     *
     * What it does:
     * Releases the native vertex buffer and resets the context, then the
     * `VertexBuffer` base destructor runs (inlined, 0x008F5833).
     */
    VertexBufferD3D9::~VertexBufferD3D9()
    {
        ResetBufferState();
    }

    /**
     * Address: 0x008F5700 (FUN_008F5700)
     *
     * What it does:
     * Returns the context the buffer was created from.
     */
    VertexBufferContext* VertexBufferD3D9::GetContext()
    {
        return &context_;
    }

    /**
     * Address: 0x008F5950 (FUN_008F5950)
     *
     * What it does:
     * Locks the retained D3D9 vertex buffer and returns mapped vertex data.
     */
    void* VertexBufferD3D9::Lock(const unsigned int offset, const unsigned int size, const MohoD3DLockFlags lockFlags)
    {
        if (d3dVertexBuffer_ == nullptr)
        {
            ThrowGalError("VtxBufD3D9.cpp", 56, "lock invalid");
        }

        if (locked_)
        {
            ThrowGalError("VtxBufD3D9.cpp", 57, "lock mismatch");
        }

        const HRESULT result = d3dVertexBuffer_->Lock(offset, size, &mappedData_, ToVertexBufferLockFlags(lockFlags));

        if (result < 0)
        {
            ThrowGalErrorFromHresult("VtxBufD3D9.cpp", 65, result);
        }

        locked_ = true;
        return mappedData_;
    }

    /**
     * Address: 0x008F5B40 (FUN_008F5B40)
     *
     * What it does:
     * Unlocks the retained D3D9 vertex buffer and clears lock-tracking state.
     */
    void VertexBufferD3D9::Unlock()
    {
        if (d3dVertexBuffer_ == nullptr)
        {
            ThrowGalError("VtxBufD3D9.cpp", 73, "unlock invalid");
        }

        if (!locked_)
        {
            ThrowGalError("VtxBufD3D9.cpp", 74, "lock mismatch");
        }

        const HRESULT result = d3dVertexBuffer_->Unlock();
        if (result < 0)
        {
            ThrowGalErrorFromHresult("VtxBufD3D9.cpp", 77, result);
        }

        locked_ = false;
        mappedData_ = nullptr;
    }

    /**
     * Address: 0x008F5CE0 (FUN_008F5CE0, gpg::gal::VertexBufferD3D9::GetD3D)
     *
     * What it does:
     * Returns the retained D3D9 vertex-buffer handle and throws when unset.
     */
    IDirect3DVertexBuffer9* VertexBufferD3D9::GetD3D()
    {
        if (d3dVertexBuffer_ == nullptr)
        {
            ThrowGalError("VertexBufferD3D9.cpp", 105, "invalid vertex buffer");
        }

        return d3dVertexBuffer_;
    }

    /**
     * Address: 0x0094AED0 (FUN_0094AED0)
     *
     * What it does:
     * Default-constructs an empty format: no declaration, format code `0x17`
     * (the "no format" code the destructor also leaves behind).
     */
    VertexFormatD3D9::VertexFormatD3D9()
        : vertexDeclaration_(nullptr)
    {
        formatCode_ = 0x17U;
    }

    /**
     * Address: 0x0094B0A0 (FUN_0094B0A0, gpg::gal::VertexFormatD3D9::VertexFormatD3D9)
     *
     * What it does:
     * Adopts `vertexDeclaration` as the declaration for format `formatCode`
     * and computes the per-stream strides.
     */
    VertexFormatD3D9::VertexFormatD3D9(const std::uint32_t formatCode, IDirect3DVertexDeclaration9* const vertexDeclaration)
        : vertexDeclaration_(nullptr)
    {
        SetFormatDeclaration(formatCode, vertexDeclaration);
    }

    /**
     * Address: 0x0094AEF0 (FUN_0094AEF0)
     *
     * What it does:
     * Replaces the declaration and format code, then rebuilds the byte stride
     * of every stream the format's element table reads (each stream's stride
     * is its furthest element end).
     */
    void VertexFormatD3D9::SetFormatDeclaration(
        const std::uint32_t formatCode, IDirect3DVertexDeclaration9* const vertexDeclaration
    )
    {
        SafeRelease(vertexDeclaration_);
        vertexDeclaration_ = vertexDeclaration;
        formatCode_ = formatCode;

        const D3DVERTEXELEMENT9* const elementTable = GetVertexFormatElementsOrThrow(formatCode);
        std::size_t declarationElementCount = 0U;
        while (!IsVertexElementEndSentinel(elementTable[declarationElementCount]))
        {
            ++declarationElementCount;
        }

        streamStrides_.clear();
        for (std::size_t elementIndex = 0U; elementIndex < declarationElementCount; ++elementIndex)
        {
            const D3DVERTEXELEMENT9& element = elementTable[elementIndex];
            const std::size_t streamIndex = static_cast<std::size_t>(element.Stream);
            if (streamStrides_.size() <= streamIndex)
            {
                streamStrides_.resize(streamIndex + 1U, 0U);
            }

            const std::uint32_t elementEndOffset =
                static_cast<std::uint32_t>(element.Offset) + GetVertexElementTypeSizeBytes(element.Type);
            std::uint32_t& streamStride = streamStrides_[streamIndex];
            if (streamStride < elementEndOffset)
            {
                streamStride = elementEndOffset;
            }
        }
    }

    /**
     * Address: 0x0094ACC0 (FUN_0094ACC0)
     * Address: 0x0094AD40 (FUN_0094AD40, slot 0: the scalar deleting destructor)
     *
     * What it does:
     * Releases the declaration and leaves format code `0x17`, then the
     * `VertexFormat` base destructor frees the stride vector (inlined,
     * 0x0094AD03..0x0094AD23).
     */
    VertexFormatD3D9::~VertexFormatD3D9()
    {
        ResetDeclarationState();
    }

    /**
     * Address: 0x0094AC90 (FUN_0094AC90)
     *
     * What it does:
     * Releases the retained vertex-declaration handle and restores the
     * default format code lane (`0x17`).
     */
    void VertexFormatD3D9::ResetDeclarationState()
    {
        SafeRelease(vertexDeclaration_);
        formatCode_ = 0x17U;
    }

    /**
     * Address: 0x0094AD60 (FUN_0094AD60, gpg::gal::VertexFormatD3D9::GetDeclaration)
     *
     * What it does:
     * Returns the retained D3D9 vertex-declaration handle and throws when unset.
     */
    IDirect3DVertexDeclaration9* VertexFormatD3D9::GetDeclaration()
    {
        if (vertexDeclaration_ == nullptr)
        {
            ThrowGalError("VertexFormatD3D9.cpp", 120, "invalid vertex format");
        }

        return vertexDeclaration_;
    }
}

// Debug surface dump used by the committed [NORMALSDUMP] diagnostic in
// WxRuntimeTypes.cpp, which reaches it only when FAF_TOGGLE_DIR names a
// directory holding dumpnormals.on. Defined here because this is where the
// D3DX export is already resolved.
namespace gpg::gal
{
    long DebugSaveSurfaceToFileA(const char* filePath, unsigned int fileFormat, void* sourceSurface);
}

long gpg::gal::DebugSaveSurfaceToFileA(const char* const filePath, const unsigned int fileFormat, void* const sourceSurface)
{
    return static_cast<long>(::D3DXSaveSurfaceToFileA(
        filePath, static_cast<D3DXIMAGE_FILEFORMAT>(fileFormat), static_cast<IDirect3DSurface9*>(sourceSurface), nullptr, nullptr
    ));
}

// TEMPORARY PROBE (do not commit): texture twin of the surface dump hook.
namespace gpg::gal
{
    long DebugSaveTextureToFileA(const char* filePath, unsigned int fileFormat, void* sourceTexture);
}

long gpg::gal::DebugSaveTextureToFileA(const char* const filePath, const unsigned int fileFormat, void* const sourceTexture)
{
    return static_cast<long>(::D3DXSaveTextureToFileA(
        filePath, static_cast<D3DXIMAGE_FILEFORMAT>(fileFormat), static_cast<IDirect3DBaseTexture9*>(sourceTexture), nullptr
    ));
}
