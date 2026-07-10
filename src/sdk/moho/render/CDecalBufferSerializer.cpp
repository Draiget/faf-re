#include "moho/render/CDecalBufferSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/render/CDecalBuffer.h"
#include "moho/render/CDecalHandle.h"
#include "moho/sim/IdPool.h"

namespace gpg
{
  // Defined in gpg/core/containers/ArchiveSerialization.cpp; builds one reflected
  // reference for a `moho::Sim*` while preserving derived runtime type.
  RRef* RRef_Sim(RRef* outRef, moho::Sim* value);
} // namespace gpg

namespace
{
  moho::CDecalBufferSerializer gCDecalBufferSerializer;

  [[nodiscard]] gpg::RType* CachedIdPoolType()
  {
    gpg::RType* type = moho::IdPool::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IdPool));
      moho::IdPool::sType = type;
    }
    return type;
  }

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

  /**
   * Address: 0x00779C40 (FUN_00779C40, Moho::CDecalBufferSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback lane for `CDecalBuffer`. In the binary this is a
   * calling-convention adapter (`jmp sub_77F160`) that reorders the reflection
   * `(WriteArchive*, objectPtr, ...)` arguments into the `__usercall` save body.
   * Recovered here as the typed callback that forwards to
   * `CDecalBufferSaveCallback`.
   */
  void CDecalBufferSerializeLane(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    auto* const buffer = reinterpret_cast<const moho::CDecalBuffer*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    if (archive != nullptr && buffer != nullptr) {
      moho::CDecalBufferSaveCallback(archive, buffer);
    }
  }

  struct CDecalBufferSerializerBootstrap
  {
    CDecalBufferSerializerBootstrap()
    {
      InitializeCDecalBufferSerializerLinks(gCDecalBufferSerializer);
      gCDecalBufferSerializer.mLoadCallback = nullptr;
      gCDecalBufferSerializer.mSaveCallback = &CDecalBufferSerializeLane;
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
   * Address: 0x00779CE0 (FUN_00779CE0)
   *
   * IDA signature:
   * void __usercall sub_779CE0(Moho::CDecalBuffer *buf@<eax>, BinaryWriteArchive *ar@<ebx>);
   *
   * What it does:
   * Walks the intrusive `CDecalHandle` list (head node at +0xCB8, node link at
   * +0x34 inside each handle) and writes each live handle as an owned tracked
   * pointer, matching the traversal used by `CreateHandle`/`DestroyHandle`.
   * Terminates with a null owned-pointer sentinel so the reader stops.
   */
  void WriteDecalHandles(const CDecalBuffer* const buf, gpg::WriteArchive* const ar)
  {
    const auto* const listHead = static_cast<const CDecalHandleListNode*>(&buf->mHandleListHead);

    for (CDecalHandleListNode* node = buf->mHandleListHead.mNext; node != listHead; node = node->mNext) {
      // Preserve the binary's `ptr != nullptr ? handle : nullptr` guard even
      // though loop nodes are always non-null before the sentinel.
      CDecalHandle* const handle = (node != nullptr) ? CDecalHandle::FromListNode(node) : nullptr;

      gpg::RRef handleRef{};
      gpg::RRef_CDecalHandle(&handleRef, handle);
      gpg::WriteRawPointer(ar, handleRef, gpg::TrackedPointerState::Owned, gpg::RRef{});
    }

    gpg::RRef terminatorRef{};
    gpg::RRef_CDecalHandle_P(&terminatorRef, nullptr);
    gpg::WriteRawPointer(ar, terminatorRef, gpg::TrackedPointerState::Owned, gpg::RRef{});
  }

  /**
   * Address: 0x0077F160 (FUN_0077F160)
   *
   * IDA signature:
   * void __usercall sub_77F160(BinaryWriteArchive *ar@<eax>, Moho::CDecalBuffer *buf@<esi>);
   *
   * What it does:
   * Save body for one `CDecalBuffer`: writes the owning `Sim` (+0x00) as an
   * unowned tracked pointer, the `IdPool` sub-object (+0x08) via reflection with
   * a lazily-resolved `RType`, then the owned decal-handle list.
   */
  void CDecalBufferSaveCallback(gpg::WriteArchive* const ar, const CDecalBuffer* const buf)
  {
    gpg::RRef simRef{};
    gpg::RRef_Sim(&simRef, buf->mSim);
    gpg::WriteRawPointer(ar, simRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    ar->Write(CachedIdPoolType(), &buf->mPool, gpg::RRef{});

    WriteDecalHandles(buf, ar);
  }

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
