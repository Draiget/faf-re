#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{
namespace
{

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
        // Raw shader/effect blob copy from the D3DX file buffer.
        std::copy_n(static_cast<const char*>(fileBuffer->GetBufferPointer()), fileBuffer->GetBufferSize(), outBuffer->GetPtr(0U, 0U));

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
}

