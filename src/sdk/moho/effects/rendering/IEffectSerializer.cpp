
#include <cstddef>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/script/CScriptObject.h"
#include "gpg/core/reflection/Reflection.h"

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
   * Address: 0x007714E0 (FUN_007714E0, write manager pointer helper)
   *
   * What it does:
   * Emits one unowned tracked pointer lane for `IEffectManager*`.
   */
  gpg::WriteArchive* SerializeIEffectManagerPointer(
    moho::IEffectManager** const managerField, gpg::WriteArchive* const archive
  )
  {
    archive->WritePointer<moho::IEffectManager>(managerField ? *managerField : nullptr, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    return archive;
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x007713E0 (FUN_007713E0, deserialize body)
   *
   * What it does:
   * Loads `CScriptObject` base payload, then reads one unowned
   * `IEffectManager*` pointer lane and one trailing integer lane.
   */
  void IEffect::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef nullOwner{};
    archive->Read(CachedCScriptObjectType(), static_cast<moho::CScriptObject*>(this), nullOwner);

    moho::IEffectManager* manager = nullptr;
    archive->ReadPointer(&manager, &nullOwner);
    mManager = manager;

    archive->ReadInt(&mScriptObjectToken);
  }

  /**
   * Address: 0x00771450 (FUN_00771450, serialize body)
   *
   * What it does:
   * Saves `CScriptObject` base payload, then writes one unowned
   * `IEffectManager*` pointer lane and one trailing integer lane.
   */
  void IEffect::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef nullOwner{};
    archive->Write(CachedCScriptObjectType(), static_cast<const moho::CScriptObject*>(this), nullOwner);

    moho::IEffectManager* manager = GetManager();
    (void)SerializeIEffectManagerPointer(&manager, archive);

    archive->WriteInt(mScriptObjectToken);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<IEffect>`, vtable 0x00E36BC4.
   *
   * Address: 0x00BDCF00 (FUN_00BDCF00 -- constructs the global and registers its destructor.)
   * Address: 0x00C020E0 (FUN_00C020E0 -- the global's destructor.)
   * Address: 0x007712D0 (FUN_007712D0 -- `Init`.)
   * Address: 0x007711E0 (FUN_007711E0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x007711F0 (FUN_007711F0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct IEffectSerializer : gpg::SerSaveLoadHelper<IEffect>
  {};
} // namespace moho

namespace
{
  // Address: 0x010BB514 -- process-global `IEffectSerializer` singleton.
  moho::IEffectSerializer gIEffectSerializer;
} // namespace
