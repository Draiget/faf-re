#include "moho/render/CDecalBufferSerializer.h"

#include "moho/render/CDecalBuffer.h"

namespace
{
  moho::CDecalBufferSerializer gCDecalBufferSerializer;

  [[nodiscard]] gpg::SerHelperBase* CDecalBufferSerializerSelfNode(moho::CDecalBufferSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  void InitializeCDecalBufferSerializerLinks(moho::CDecalBufferSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = CDecalBufferSerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkCDecalBufferSerializerHelperNode(
    moho::CDecalBufferSerializer& serializer
  ) noexcept
  {
    serializer.mHelperNext->mPrev = serializer.mHelperPrev;
    serializer.mHelperPrev->mNext = serializer.mHelperNext;

    gpg::SerHelperBase* const self = CDecalBufferSerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  struct CDecalBufferSerializerBootstrap
  {
    CDecalBufferSerializerBootstrap()
    {
      InitializeCDecalBufferSerializerLinks(gCDecalBufferSerializer);
      gCDecalBufferSerializer.mLoadCallback = nullptr;
      gCDecalBufferSerializer.mSaveCallback = nullptr;
    }
  };

  CDecalBufferSerializerBootstrap gCDecalBufferSerializerBootstrap;

  /**
   * Address: 0x00779C80 (FUN_00779C80)
   *
   * What it does:
   * Unlinks `CDecalBufferSerializer` helper node from the intrusive helper
   * list, rewires self-links, and returns the helper self node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCDecalBufferSerializerHelperPrimary() noexcept
  {
    return UnlinkCDecalBufferSerializerHelperNode(gCDecalBufferSerializer);
  }

  /**
   * Address: 0x00779CB0 (FUN_00779CB0)
   *
   * What it does:
   * Secondary entrypoint for the same `CDecalBufferSerializer` helper-node
   * intrusive unlink and self-link reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkCDecalBufferSerializerHelperSecondary() noexcept
  {
    return UnlinkCDecalBufferSerializerHelperNode(gCDecalBufferSerializer);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0077AB00 (FUN_0077AB00, gpg::SerSaveLoadHelper_CDecalBuffer::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall gpg::SerSaveLoadHelper_CDecalBuffer::Init(
   *   void (__cdecl **this)(gpg::WriteArchive *, void *obj, int version, const gpg::RRef *a5)))
   * (gpg::ReadArchive *arch, void *obj, int cont, gpg::RRef *res);
   */
  void CDecalBufferSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CDecalBuffer::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
