#include "moho/serialization/SSavedGameArmyInfo.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00881EA0 / 0x00882620 path (callback lane used by 0x00882090).
   *
   * What it does:
   * Loads one saved-army info row from archive string payload.
   */
  void LoadSavedGameArmyInfo(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const info = reinterpret_cast<moho::SSavedGameArmyInfo*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(info != nullptr);
    if (!archive || !info) {
      return;
    }

    archive->ReadString(&info->mPlayerName);
  }

  /**
   * Address: 0x00881F10 / 0x00882670 path (callback lane used by 0x00882090).
   *
   * What it does:
   * Saves one saved-army info row into archive string payload.
   */
  void SaveSavedGameArmyInfo(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const info = reinterpret_cast<moho::SSavedGameArmyInfo*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(info != nullptr);
    if (!archive || !info) {
      return;
    }

    archive->WriteString(&info->mPlayerName);
  }

  moho::SSavedGameArmyInfoTypeInfo gSavedGameArmyInfoTypeInfo;
  moho::SSavedGameArmyInfoSerializer gSavedGameArmyInfoSerializer;

  [[nodiscard]] gpg::SerHelperBase* SavedGameArmyInfoSerializerSelfNode() noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&gSavedGameArmyInfoSerializer.mNext);
  }

  void InitializeSavedGameArmyInfoSerializerLinks() noexcept
  {
    gpg::SerHelperBase* const self = SavedGameArmyInfoSerializerSelfNode();
    gSavedGameArmyInfoSerializer.mNext = self;
    gSavedGameArmyInfoSerializer.mPrev = self;
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSavedGameArmyInfoSerializerHelperNode() noexcept
  {
    auto* const next = static_cast<gpg::SerHelperBase*>(gSavedGameArmyInfoSerializer.mNext);
    auto* const prev = static_cast<gpg::SerHelperBase*>(gSavedGameArmyInfoSerializer.mPrev);
    next->mPrev = prev;
    prev->mNext = next;

    gpg::SerHelperBase* const self = SavedGameArmyInfoSerializerSelfNode();
    gSavedGameArmyInfoSerializer.mPrev = self;
    gSavedGameArmyInfoSerializer.mNext = self;
    return self;
  }

  /**
   * Address: 0x008800B0 (FUN_008800B0)
   *
   * What it does:
   * Unlinks global `SSavedGameArmyInfoSerializer` helper node from the
   * intrusive helper list, rewires self-links, and returns the helper self
   * node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSavedGameArmyInfoSerializerHelperPrimary() noexcept
  {
    return UnlinkSavedGameArmyInfoSerializerHelperNode();
  }

  /**
   * Address: 0x008800E0 (FUN_008800E0)
   *
   * What it does:
   * Secondary entrypoint for `SSavedGameArmyInfoSerializer` helper-node
   * intrusive unlink + self-link reset.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkSavedGameArmyInfoSerializerHelperSecondary() noexcept
  {
    return UnlinkSavedGameArmyInfoSerializerHelperNode();
  }

  /**
   * Address: 0x0087FF00 (FUN_0087FF00, preregister_SSavedGameArmyInfoTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `moho::SSavedGameArmyInfo`.
   */
  [[nodiscard]] gpg::RType* preregister_SSavedGameArmyInfoTypeInfo()
  {
    gpg::PreRegisterRType(typeid(moho::SSavedGameArmyInfo), &gSavedGameArmyInfoTypeInfo);
    return &gSavedGameArmyInfoTypeInfo;
  }

  void EnsureSavedGameArmyInfoRegistered()
  {
    // Zero-initialised flag, not a magic static: this registration re-enters
    // itself. RegisterSerializeFunctions() resolves the type through
    // SSavedGameArmyInfo::StaticGetClass(), which calls back in here. A
    // function-local static with a dynamic initialiser would make that second
    // entry wait in _Init_thread_header for an initialisation this very thread
    // is still running, deadlocking startup. Setting the guard before the body
    // runs makes the re-entrant call a no-op instead.
    static bool sRegistered = false;
    if (sRegistered) {
      return;
    }
    sRegistered = true;

    (void)preregister_SSavedGameArmyInfoTypeInfo();
    InitializeSavedGameArmyInfoSerializerLinks();
    gSavedGameArmyInfoSerializer.mSerLoadFunc = &LoadSavedGameArmyInfo;
    gSavedGameArmyInfoSerializer.mSerSaveFunc = &SaveSavedGameArmyInfo;
    gSavedGameArmyInfoSerializer.RegisterSerializeFunctions();
  }
} // namespace

namespace moho
{
  gpg::RType* SSavedGameArmyInfo::sType = nullptr;

  gpg::RType* SSavedGameArmyInfo::StaticGetClass()
  {
    EnsureSavedGameArmyInfoRegistered();
    if (!sType) {
      sType = gpg::LookupRType(typeid(SSavedGameArmyInfo));
    }
    return sType;
  }

  /**
   * Address: 0x0087FF80 (FUN_0087FF80)
   */
  const char* SSavedGameArmyInfoTypeInfo::GetName() const
  {
    return "SSavedGameArmyInfo";
  }

  /**
   * Address: 0x0087FF60 (FUN_0087FF60)
   */
  void SSavedGameArmyInfoTypeInfo::Init()
  {
    size_ = sizeof(SSavedGameArmyInfo);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00882090 (FUN_00882090)
   *
   * What it does:
   * Registers load/save callbacks for SSavedGameArmyInfo.
   */
  void SSavedGameArmyInfoSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = SSavedGameArmyInfo::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SSavedGameArmyInfoTypeInfo_ed43fe, preregister_SSavedGameArmyInfoTypeInfo)
