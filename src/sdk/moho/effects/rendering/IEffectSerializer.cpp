#include "moho/effects/rendering/IEffectSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/script/CScriptObject.h"

namespace
{
  moho::IEffectSerializer gIEffectSerializer{};

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(moho::IEffectSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(moho::IEffectSerializer& serializer) noexcept
  {
    serializer.mHelperNext->mPrev = serializer.mHelperPrev;
    serializer.mHelperPrev->mNext = serializer.mHelperNext;

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00771240 (FUN_00771240)
   *
   * What it does:
   * Unlinks startup `IEffectSerializer` helper links and rewires the node into
   * one self-linked sentinel lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkIEffectSerializerNodeVariantA() noexcept
  {
    return UnlinkSerializerNode(gIEffectSerializer);
  }

  /**
   * Address: 0x00771270 (FUN_00771270)
   *
   * What it does:
   * Duplicate unlink/reset lane for startup `IEffectSerializer` helper links.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkIEffectSerializerNodeVariantB() noexcept
  {
    return UnlinkSerializerNode(gIEffectSerializer);
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    if (!moho::CScriptObject::sType) {
      moho::CScriptObject::sType = gpg::LookupRType(typeid(moho::CScriptObject));
    }
    return moho::CScriptObject::sType;
  }

  [[nodiscard]] moho::IEffectManager* ReadEffectManagerField(const moho::IEffect* const effect)
  {
    const std::uintptr_t raw = static_cast<std::uintptr_t>(effect->mUnknown3C);
    return reinterpret_cast<moho::IEffectManager*>(raw);
  }

  void WriteEffectManagerField(moho::IEffect* const effect, moho::IEffectManager* const manager)
  {
    const std::uintptr_t raw = reinterpret_cast<std::uintptr_t>(manager);
    effect->mUnknown3C = static_cast<std::uint32_t>(raw);
  }

  /**
   * Address: 0x007713E0 (FUN_007713E0, deserialize body)
   *
   * What it does:
   * Loads `CScriptObject` base payload, then reads one unowned
   * `IEffectManager*` pointer lane and one trailing integer lane.
   */
  void DeserializeIEffectBody_007713E0(moho::IEffect* const effect, gpg::ReadArchive* const archive)
  {
    const gpg::RRef nullOwner{};
    archive->Read(CachedCScriptObjectType(), static_cast<moho::CScriptObject*>(effect), nullOwner);

    moho::IEffectManager* manager = nullptr;
    archive->ReadPointer_IEffectManager(&manager, &nullOwner);
    WriteEffectManagerField(effect, manager);

    int luaObjectValue = static_cast<int>(effect->mUnknown40);
    archive->ReadInt(&luaObjectValue);
    effect->mUnknown40 = static_cast<std::uint32_t>(luaObjectValue);
  }

  /**
   * Address: 0x007714E0 (FUN_007714E0, write manager pointer helper)
   *
   * What it does:
   * Emits one unowned tracked pointer lane for `IEffectManager*`.
   */
  gpg::WriteArchive* SerializeIEffectManagerPointer_007714E0(
    moho::IEffectManager** const managerField, gpg::WriteArchive* const archive
  )
  {
    gpg::RRef managerRef{};
    gpg::RRef_IEffectManager(&managerRef, managerField ? *managerField : nullptr);
    gpg::WriteRawPointer(archive, managerRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    return archive;
  }

  /**
   * Address: 0x00771450 (FUN_00771450, serialize body)
   *
   * What it does:
   * Saves `CScriptObject` base payload, then writes one unowned
   * `IEffectManager*` pointer lane and one trailing integer lane.
   */
  void SerializeIEffectBody_00771450(const moho::IEffect* const effect, gpg::WriteArchive* const archive)
  {
    const gpg::RRef nullOwner{};
    archive->Write(CachedCScriptObjectType(), static_cast<const moho::CScriptObject*>(effect), nullOwner);

    moho::IEffectManager* manager = ReadEffectManagerField(effect);
    (void)SerializeIEffectManagerPointer_007714E0(&manager, archive);

    archive->WriteInt(static_cast<int>(effect->mUnknown40));
  }

  /**
   * Address: 0x007713B0 (FUN_007713B0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards one `IEffect` serializer-save thunk alias into
   * `FUN_00771450` serialize body.
   */
  void SerializeIEffectThunkVariantA(gpg::RRef* const, moho::IEffect* const effect, gpg::WriteArchive* const archive)
  {
    SerializeIEffectBody_00771450(effect, archive);
  }

  /**
   * Address: 0x007713D0 (FUN_007713D0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards a second `IEffect` serializer-save thunk alias into
   * `FUN_00771450` serialize body.
   */
  void SerializeIEffectThunkVariantB(gpg::RRef* const, moho::IEffect* const effect, gpg::WriteArchive* const archive)
  {
    SerializeIEffectBody_00771450(effect, archive);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007711E0 (FUN_007711E0, Moho::IEffectSerializer::Deserialize)
   *
   * What it does:
   * Adapts serializer callback ABI and forwards to `FUN_007713E0` body.
   */
  void IEffectSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    auto* const effect = reinterpret_cast<IEffect*>(objectPtr);
    DeserializeIEffectBody_007713E0(effect, archive);
  }

  /**
   * Address: 0x007711F0 (FUN_007711F0, Moho::IEffectSerializer::Serialize)
   *
   * What it does:
   * Adapts serializer callback ABI and forwards to `FUN_00771450` body.
   */
  void IEffectSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    auto* const effect = reinterpret_cast<IEffect*>(objectPtr);
    SerializeIEffectBody_00771450(effect, archive);
  }

  /**
   * Address: 0x007712D0 (FUN_007712D0, gpg::SerSaveLoadHelper_IEffect::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall gpg::SerSaveLoadHelper_IEffect::Init(_DWORD *this))
   * (gpg::ReadArchive *, int, int, gpg::RRef *);
   */
  void IEffectSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = IEffect::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
