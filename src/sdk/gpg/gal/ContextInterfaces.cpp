#include "CubeRenderTargetContext.hpp"
#include "DepthStencilTargetContext.hpp"
#include "DeviceContext.hpp"
#include "DrawContext.hpp"
#include "EffectContext.hpp"
#include "IndexBufferContext.hpp"
#include "OutputContext.hpp"
#include "RenderTargetContext.hpp"
#include "TextureContext.hpp"
#include "VertexBufferContext.hpp"

namespace gpg::gal
{
    namespace
    {
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
     * Address: 0x0093F140 (FUN_0093F140)
     *
     * What it does:
     * Scalar-deleting destructor thunk owner for draw-context interface instances.
     */
    DrawContext::~DrawContext() = default;

    /**
     * Address: 0x008FE8B0 (FUN_008FE8B0)
     *
     * What it does:
     * Scalar-deleting destructor thunk owner for effect-context interface instances.
     */
    EffectContext::~EffectContext() = default;

    /**
     * Address: 0x00940640 (FUN_00940640)
     *
     * What it does:
     * Scalar-deleting destructor thunk owner for index-buffer context handles.
     */
    IndexBufferContext::~IndexBufferContext() = default;

    /**
     * Address: 0x008E8250 (FUN_008E8250)
     *
     * What it does:
     * Scalar/vector deleting-destructor thunk owner for output-target context state.
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
     * Address: 0x008E7AE0 (FUN_008E7AE0)
     *
     * What it does:
     * Scalar-deleting destructor thunk owner for texture context handles.
     */
    TextureContext::~TextureContext() = default;

    /**
     * Address: 0x009408B0 (FUN_009408B0)
     *
     * What it does:
     * Scalar-deleting destructor thunk owner for vertex-buffer context handles.
     */
    VertexBufferContext::~VertexBufferContext() = default;
}
