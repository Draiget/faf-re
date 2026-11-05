#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{
namespace
{

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
}

