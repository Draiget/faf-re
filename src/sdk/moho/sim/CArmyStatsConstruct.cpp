#include "moho/sim/CArmyStatsConstruct.h"

#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/ai/CAiBrain.h"
#include "moho/sim/CArmyStats.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  gpg::RType* gCAiBrainType = nullptr;
  moho::CArmyStatsConstruct gCArmyStatsConstruct;

  /**
   * Address: 0x0070E140 (FUN_0070E140, sub_70E140)
   */
  void Construct_CArmyStats(
    gpg::ReadArchive* const archive, const int, const int, gpg::SerConstructResult* const result
  )
  {
    moho::CAiBrain* ownerArmy = nullptr;
    if (archive) {
      const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, gpg::RRef{});
      if (tracked.object) {
        gpg::RRef source{};
        source.mObj = tracked.object;
        source.mType = tracked.type;
        const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedType<moho::CAiBrain>(gCAiBrainType));
        ownerArmy = static_cast<moho::CAiBrain*>(upcast.mObj);
      }
    }

    moho::CArmyStats* const object = new (std::nothrow) moho::CArmyStats(ownerArmy);
    if (!result) {
      return;
    }

    gpg::RRef objectRef{};
    objectRef.mObj = object;
    objectRef.mType = moho::CArmyStats::StaticGetClass();
    result->SetUnowned(objectRef, 0u);
  }

  /**
   * Address: 0x00712680 (FUN_00712680, sub_712680)
   */
  void Delete_CArmyStats(void* const objectPtr)
  {
    auto* const object = static_cast<moho::CArmyStats*>(objectPtr);
    if (!object) {
      return;
    }

    object->~CArmyStats();
    ::operator delete(object);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDA1D0 (FUN_00BDA1D0, sub_BDA1D0)
   *
   * What it does:
   * Initializes CArmyStats construct helper callback slots and registers
   * them into reflected RTTI.
   */
  void register_CArmyStatsConstruct()
  {
    gCArmyStatsConstruct.mHelperNext = nullptr;
    gCArmyStatsConstruct.mHelperPrev = nullptr;
    gCArmyStatsConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&Construct_CArmyStats);
    gCArmyStatsConstruct.mDeleteCallback = &Delete_CArmyStats;
    gCArmyStatsConstruct.RegisterConstructFunction();
  }

  /**
   * Address: 0x0070F560 (FUN_0070F560, gpg::SerConstructHelper_CArmyStats::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_70F560(void (__cdecl **this)(void *)))(...);
   */
  void CArmyStatsConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CArmyStats::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho

namespace
{
  struct CArmyStatsConstructBootstrap
  {
    CArmyStatsConstructBootstrap()
    {
      moho::register_CArmyStatsConstruct();
    }
  };

  CArmyStatsConstructBootstrap gCArmyStatsConstructBootstrap;
} // namespace
