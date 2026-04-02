#include "moho/sim/CInfluenceMapConstruct.h"

#include <new>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/sim/CInfluenceMap.h"

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
  moho::CInfluenceMapConstruct gCInfluenceMapConstruct;

  /**
   * Address: 0x00717670 (FUN_00717670, sub_717670)
   */
  void Construct_CInfluenceMap(
    gpg::ReadArchive*, const int, const int, gpg::SerConstructResult* const constructResult
  )
  {
    moho::CInfluenceMap* const object = new (std::nothrow) moho::CInfluenceMap();
    if (!constructResult) {
      return;
    }

    gpg::RRef objectRef{};
    objectRef.mObj = object;
    objectRef.mType = moho::CInfluenceMap::StaticGetClass();
    constructResult->SetUnowned(objectRef, 0u);
  }

  /**
   * Address: 0x00717660 (FUN_00717660, sub_717660)
   */
  int Construct_CInfluenceMapThunk(const int a1, const int a2, const int a3, gpg::SerConstructResult* const result)
  {
    (void)a1;
    (void)a2;
    (void)a3;
    Construct_CInfluenceMap(nullptr, 0, 0, result);
    return 0;
  }

  /**
   * Address: 0x0071CAA0 (FUN_0071CAA0, sub_71CAA0)
   */
  void Delete_CInfluenceMap(void* const objectPtr)
  {
    auto* const object = static_cast<moho::CInfluenceMap*>(objectPtr);
    if (!object) {
      return;
    }

    object->~CInfluenceMap();
    ::operator delete(object);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDA680 (FUN_00BDA680, sub_BDA680)
   *
   * What it does:
   * Initializes CInfluenceMap construct helper callbacks and binds them into
   * CInfluenceMap RTTI.
   */
  void register_CInfluenceMapConstruct()
  {
    gCInfluenceMapConstruct.mHelperNext = nullptr;
    gCInfluenceMapConstruct.mHelperPrev = nullptr;
    gCInfluenceMapConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&Construct_CInfluenceMapThunk);
    gCInfluenceMapConstruct.mDeleteCallback = &Delete_CInfluenceMap;
    gCInfluenceMapConstruct.RegisterConstructFunction();
  }

  /**
   * Address: 0x00718AE0 (FUN_00718AE0, gpg::SerConstructHelper_CInfluenceMap::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_718AE0(void (__cdecl **this)(void *)))(...);
   */
  void CInfluenceMapConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CInfluenceMap::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho

namespace
{
  struct CInfluenceMapConstructBootstrap
  {
    CInfluenceMapConstructBootstrap()
    {
      moho::register_CInfluenceMapConstruct();
    }
  };

  CInfluenceMapConstructBootstrap gCInfluenceMapConstructBootstrap;
} // namespace
