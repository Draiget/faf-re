#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{
namespace
{

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
}

