#include "CubeRenderTargetContext.hpp"
#include "DepthStencilTargetContext.hpp"
#include "DeviceContext.hpp"
#include "DrawContext.hpp"
#include "EffectContext.hpp"
#include "EffectMacro.hpp"
#include "IndexBufferContext.hpp"
#include "OutputContext.hpp"
#include "RenderTargetContext.hpp"
#include "TextureContext.hpp"
#include "VertexBufferContext.hpp"

namespace gpg::gal
{
    namespace
    {
        struct EffectMacroVectorRuntime final
        {
            void* proxy = nullptr;        // +0x00
            EffectMacro* first = nullptr; // +0x04
            EffectMacro* last = nullptr;  // +0x08
            EffectMacro* end = nullptr;   // +0x0C
        };

        struct EffectContextRuntimeView final
        {
            void* vftable = nullptr;                                 // +0x00
            std::uint32_t sourceType = 0U;                           // +0x04
            std::uint8_t useCache = 0U;                              // +0x08
            std::uint8_t pad09_0B[3]{};                              // +0x09 .. +0x0B
            msvc8::string sourcePath;                                // +0x0C
            msvc8::string cachePath;                                 // +0x28
            std::uint32_t sourceBufferBytes = 0U;                    // +0x44
            boost::detail::sp_counted_base* sourceBufferCount = nullptr; // +0x48
            std::uint32_t sourceBufferBegin = 0U;                    // +0x4C
            std::uint32_t sourceBufferEnd = 0U;                      // +0x50
            EffectMacroVectorRuntime macros;                         // +0x54
        };

        static_assert(offsetof(EffectContextRuntimeView, sourcePath) == 0x0C, "EffectContextRuntimeView::sourcePath offset must be 0x0C");
        static_assert(offsetof(EffectContextRuntimeView, cachePath) == 0x28, "EffectContextRuntimeView::cachePath offset must be 0x28");
        static_assert(
            offsetof(EffectContextRuntimeView, sourceBufferCount) == 0x48,
            "EffectContextRuntimeView::sourceBufferCount offset must be 0x48"
        );
        static_assert(offsetof(EffectContextRuntimeView, macros) == 0x54, "EffectContextRuntimeView::macros offset must be 0x54");
        static_assert(sizeof(EffectMacroVectorRuntime) == 0x10, "EffectMacroVectorRuntime size must be 0x10");
        static_assert(sizeof(EffectContextRuntimeView) == 0x64, "EffectContextRuntimeView size must be 0x64");

        void DestroyEffectMacroRange(EffectMacro* first, EffectMacro* last) noexcept
        {
            while (first != last)
            {
                first->~EffectMacro();
                ++first;
            }
        }

        void DestroyEffectMacroStorage(EffectMacroVectorRuntime& runtime) noexcept
        {
            if (runtime.first != nullptr)
            {
                DestroyEffectMacroRange(runtime.first, runtime.last);
                ::operator delete(static_cast<void*>(runtime.first));
            }

            runtime.first = nullptr;
            runtime.last = nullptr;
            runtime.end = nullptr;
            runtime.proxy = nullptr;
        }

        void AssignSharedCount(
            boost::detail::sp_counted_base*& target,
            boost::detail::sp_counted_base* const source
        ) noexcept
        {
            if (source != nullptr)
            {
                source->add_ref_copy();
            }

            if (target != nullptr)
            {
                target->release();
            }

            target = source;
        }
    }

    /**
     * Address: 0x009405F0 (FUN_009405F0)
     *
     * What it does:
     * Initializes index-buffer context metadata lanes to zero.
     */
    IndexBufferContext::IndexBufferContext()
        : format_(0),
          size_(0),
          type_(0)
    {
    }

    /**
     * Address: 0x00940610 (FUN_00940610)
     *
     * What it does:
     * Initializes index-buffer size/format/type lanes from explicit payload values.
     */
    IndexBufferContext::IndexBufferContext(
        const std::uint32_t size,
        const std::uint32_t format,
        const std::uint32_t type
    )
        : format_(format),
          size_(size),
          type_(type)
    {
    }

    /**
     * Address: 0x00940850 (FUN_00940850)
     *
     * What it does:
     * Initializes vertex-buffer context metadata lanes to zero.
     */
    VertexBufferContext::VertexBufferContext()
        : type_(0),
          usage_(0),
          width_(0),
          height_(0)
    {
    }

    /**
     * Address: 0x00940870 (FUN_00940870)
     *
     * What it does:
     * Initializes vertex-buffer width/height/type/usage lanes from explicit payload values.
     */
    VertexBufferContext::VertexBufferContext(
        const std::uint32_t width,
        const std::uint32_t height,
        const std::uint32_t type,
        const std::uint32_t usage
    )
        : type_(type),
          usage_(usage),
          width_(width),
          height_(height)
    {
    }

    /**
     * Address: 0x008E7C80 (FUN_008E7C80)
     *
     * What it does:
     * Initializes texture-context metadata and string/control lanes to zero.
     */
    TextureContext::TextureContext()
        : source_(0),
          location_(),
          dataArray_(nullptr),
          dataCount_(nullptr),
          dataBegin_(0),
          dataEnd_(0),
          type_(0),
          usage_(0),
          format_(0),
          mipmapLevels_(0),
          reserved0x44_(0),
          width_(0),
          height_(0),
          reserved0x50_(0)
    {
    }

    /**
     * Address: 0x00903B60 (FUN_00903B60)
     *
     * What it does:
     * Copies texture-context payload fields and shared-count ownership lanes.
     */
    void TextureContext::AssignFrom(const TextureContext& other)
    {
        source_ = other.source_;
        location_.assign(other.location_, 0U, msvc8::string::npos);
        dataArray_ = other.dataArray_;
        AssignSharedCount(dataCount_, other.dataCount_);
        dataBegin_ = other.dataBegin_;
        dataEnd_ = other.dataEnd_;
        type_ = other.type_;
        usage_ = other.usage_;
        format_ = other.format_;
        mipmapLevels_ = other.mipmapLevels_;
        reserved0x44_ = other.reserved0x44_;
        width_ = other.width_;
        height_ = other.height_;
        reserved0x50_ = other.reserved0x50_;
    }

    /**
     * Address: 0x008E6550 (FUN_008E6550)
     *
     * What it does:
     * Initializes cube render-target context dimensions/format lanes to zero.
     */
    CubeRenderTargetContext::CubeRenderTargetContext()
        : dimension_(0),
          format_(0)
    {
    }

    /**
     * Address: 0x008E6570 (FUN_008E6570)
     *
     * What it does:
     * Initializes cube render-target context with explicit dimension and format.
     */
    CubeRenderTargetContext::CubeRenderTargetContext(const std::uint32_t dimension, const std::uint32_t format)
        : dimension_(dimension),
          format_(format)
    {
    }

    /**
     * Address: 0x0093EF90 (FUN_0093EF90)
     *
     * What it does:
     * Initializes depth-stencil context dimensions/format/flag lanes to zero.
     */
    DepthStencilTargetContext::DepthStencilTargetContext()
        : width_(0),
          height_(0),
          format_(0),
          field0x10_(false)
    {
    }

    /**
     * Address: 0x0093EFB0 (FUN_0093EFB0)
     *
     * What it does:
     * Initializes depth-stencil context with explicit dimensions, format, and flag.
     */
    DepthStencilTargetContext::DepthStencilTargetContext(
        const std::uint32_t width,
        const std::uint32_t height,
        const std::uint32_t format,
        const bool field0x10
    )
        : width_(width),
          height_(height),
          format_(format),
          field0x10_(field0x10)
    {
    }

    /**
     * Address: 0x008E79C0 (FUN_008E79C0)
     *
     * What it does:
     * Initializes render-target context dimensions/format lanes to zero.
     */
    RenderTargetContext::RenderTargetContext()
        : width_(0),
          height_(0),
          format_(0)
    {
    }

    /**
     * Address: 0x00442050 (FUN_00442050, sub_442050)
     *
     * What it does:
     * Copies render-target width/height/format lanes from another context.
     */
    RenderTargetContext::RenderTargetContext(const RenderTargetContext& other)
        : width_(other.width_),
          height_(other.height_),
          format_(other.format_)
    {
    }

    /**
     * Address: 0x008E65A0 (FUN_008E65A0)
     *
     * What it does:
     * Scalar-deleting destructor thunk owner for cube render-target context handles.
     */
    CubeRenderTargetContext::~CubeRenderTargetContext() = default;

    /**
     * Address: 0x0093EFF0 (FUN_0093EFF0)
     *
     * What it does:
     * Scalar-deleting destructor thunk owner for depth-stencil target context handles.
     */
    DepthStencilTargetContext::~DepthStencilTargetContext() = default;

    /**
     * Address: 0x00430570 (FUN_00430570)
     *
     * What it does:
     * Scalar-deleting destructor thunk owner for device-context interface instances.
     */
    DeviceContext::~DeviceContext() = default;

    /**
     * Address: 0x0093F060 (FUN_0093F060, gpg::gal::DrawContext::DrawContext)
     *
     * What it does:
     * Initializes non-indexed draw payload lanes for topology token,
     * primitive-count input, and start-vertex offset.
     */
    DrawContext::DrawContext(
        const std::uint32_t topologyToken,
        const std::uint32_t primitiveCountInput,
        const std::uint32_t startVertex
    )
        : topologyToken_(topologyToken),
          primitiveCountInput_(primitiveCountInput),
          startVertex_(startVertex)
    {
    }

    /**
     * Address: 0x0093F080 (FUN_0093F080, gpg::gal::DrawContext::~DrawContext)
     * Address: 0x0093F140 (FUN_0093F140)
     *
     * What it does:
     * Restores DrawContext vftable ownership and services deleting
     * destructor thunk teardown.
     */
    DrawContext::~DrawContext() = default;

    /**
     * Address: 0x0093F950 (FUN_0093F950, gpg::gal::EffectContext::~EffectContext)
     * Address: 0x008FE8B0 (FUN_008FE8B0, scalar deleting destructor thunk owner)
     *
     * What it does:
     * Releases effect-macro vector storage, decrements source-buffer shared
     * count ownership, and resets both path string lanes to empty state.
     */
    EffectContext::~EffectContext()
    {
        auto* const runtime = reinterpret_cast<EffectContextRuntimeView*>(this);

        DestroyEffectMacroStorage(runtime->macros);

        if (runtime->sourceBufferCount != nullptr)
        {
            runtime->sourceBufferCount->release();
            runtime->sourceBufferCount = nullptr;
        }

        runtime->cachePath.tidy(true, 0U);
        runtime->sourcePath.tidy(true, 0U);
    }

    /**
     * Address: 0x00940630 (FUN_00940630)
     * Address: 0x00940640 (FUN_00940640, scalar deleting destructor thunk)
     *
     * What it does:
     * Restores index-buffer context vftable ownership and services deleting-destructor teardown.
     */
    IndexBufferContext::~IndexBufferContext() = default;

    /**
     * Address: 0x008E77B0 (FUN_008E77B0, gpg::gal::OutputContextInit)
     *
     * IDA signature:
     * gpg::gal::OutputContext *__thiscall gpg::gal::OutputContextInit(gpg::gal::OutputContext *this);
     *
     * What it does:
     * Initializes one output-context payload with null shared-handle lanes;
     * the scalar `face` lane remains intentionally uninitialized.
     */
    OutputContext::OutputContext()
        : cubeTarget(),
          surface(),
          texture()
    {
    }

    /**
     * Address: 0x008E77D0 (FUN_008E77D0, gpg::gal::OutputContext::OutputContext)
     *
     * SurfaceHandle,TextureHandle
     *
     * IDA signature:
     * gpg::gal::OutputContext *__userpurge gpg::gal::OutputContext::OutputContext@<eax>(
     *     gpg::gal::OutputContext *this@<ecx>,
     *     boost::shared_ptr_D3DSurface a2,
     *     boost::weak_ptr a3);
     *
     * What it does:
     * Initializes one output-context payload, clears cube-target handles, and
     * copies caller-provided surface/texture handles with retained ownership.
     */
    OutputContext::OutputContext(SurfaceHandle surfaceHandle, TextureHandle textureHandle)
        : cubeTarget(),
          surface(surfaceHandle),
          texture(textureHandle)
    {
    }

    /**
     * Address: 0x00430160 (FUN_00430160)
     *
     * OutputContext const &
     *
     * What it does:
     * Copies one output-context payload and retains shared-handle ownership.
     */
    OutputContext::OutputContext(const OutputContext& other)
        : cubeTarget(other.cubeTarget),
          face(other.face),
          surface(other.surface),
          texture(other.texture)
    {
    }

    /**
     * Address: 0x008E76D0 (FUN_008E76D0, gpg::gal::OutputContext::~OutputContext)
     * Address: 0x008E8250 (FUN_008E8250, scalar/vector deleting-destructor thunk owner)
     *
     * What it does:
     * Releases retained texture/surface/cube-target shared-handle lanes in
     * reverse destruction order.
     */
    OutputContext::~OutputContext() = default;

    /**
     * Address: 0x00442080 (FUN_00442080)
     *
     * What it does:
     * Scalar-deleting destructor thunk owner for render-target context handles.
     */
    RenderTargetContext::~RenderTargetContext() = default;

    /**
     * Address: 0x008E7CC0 (FUN_008E7CC0, __imp_??1TextureContext@gal@gpg@@UAE@XZ)
     * Address: 0x008E7AE0 (FUN_008E7AE0, scalar deleting destructor thunk)
     *
     * What it does:
     * Releases texture payload shared-count ownership before string/member teardown.
     */
    TextureContext::~TextureContext()
    {
        if (dataCount_ != nullptr)
        {
            dataCount_->release();
            dataCount_ = nullptr;
            dataArray_ = nullptr;
        }
    }

    /**
     * Address: 0x009408A0 (FUN_009408A0)
     * Address: 0x009408B0 (FUN_009408B0, scalar deleting destructor thunk)
     *
     * What it does:
     * Restores vertex-buffer context vftable ownership and services deleting-destructor teardown.
     */
    VertexBufferContext::~VertexBufferContext() = default;
}
