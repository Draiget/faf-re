#include "moho/effects/rendering/IEffectSerializer.h"

#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/script/CScriptObject.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    if (!moho::CScriptObject::sType) {
      moho::CScriptObject::sType = gpg::LookupRType(typeid(moho::CScriptObject));
    }
    return moho::CScriptObject::sType;
  }

  /**
   * Address: 0x007713E0 (FUN_007713E0, deserialize body)
   *
   * What it does:
   * Loads `CScriptObject` base payload, then reads one unowned
   * `IEffectManager*` pointer lane and one trailing integer lane.
   */
  void DeserializeIEffectBody(moho::IEffect* const effect, gpg::ReadArchive* const archive)
  {
    const gpg::RRef nullOwner{};
    archive->Read(CachedCScriptObjectType(), static_cast<moho::CScriptObject*>(effect), nullOwner);

    moho::IEffectManager* manager = nullptr;
    archive->ReadPointer_IEffectManager(&manager, &nullOwner);
    effect->mManager = manager;

    archive->ReadInt(&effect->mScriptObjectToken);
  }

  /**
   * Address: 0x007714E0 (FUN_007714E0, write manager pointer helper)
   *
   * What it does:
   * Emits one unowned tracked pointer lane for `IEffectManager*`.
   */
  gpg::WriteArchive* SerializeIEffectManagerPointer(
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
  void SerializeIEffectBody(const moho::IEffect* const effect, gpg::WriteArchive* const archive)
  {
    const gpg::RRef nullOwner{};
    archive->Write(CachedCScriptObjectType(), static_cast<const moho::CScriptObject*>(effect), nullOwner);

    moho::IEffectManager* manager = effect->mManager;
    (void)SerializeIEffectManagerPointer(&manager, archive);

    archive->WriteInt(effect->mScriptObjectToken);
  }

  // Address: 0x010BB514 -- process-global `IEffectSerializer` singleton.
  // Constructing it runs IEffectSerializer::IEffectSerializer()
  // (0x00BDCF00), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction.
  moho::IEffectSerializer gIEffectSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDCF00 (FUN_00BDCF00, register_IEffectSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  IEffectSerializer::IEffectSerializer()
    : mLoadCallback(&IEffectSerializer::Deserialize)
    , mSaveCallback(&IEffectSerializer::Serialize)
  {}

  /**
   * Address: 0x00C020E0 (FUN_00C020E0, Moho::IEffectSerializer::~IEffectSerializer)
   *
   * What it does:
   * Unlinks this helper node from whatever intrusive list it currently sits
   * in and restores a self-linked sentinel state.
   */
  IEffectSerializer::~IEffectSerializer()
  {
    ResetLinks();
  }

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
    DeserializeIEffectBody(effect, archive);
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
    SerializeIEffectBody(effect, archive);
  }

  /**
   * Address: 0x007712D0 (FUN_007712D0, gpg::SerSaveLoadHelper_IEffect::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall gpg::SerSaveLoadHelper_IEffect::Init(_DWORD *this))
   * (gpg::ReadArchive *, int, int, gpg::RRef *);
   */
  void IEffectSerializer::Init()
  {
    gpg::RType* const type = IEffect::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
