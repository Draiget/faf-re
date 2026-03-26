#include "moho/path/RDebugNavPathTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/path/RDebugNavPath.h"
#include "moho/render/RDebugOverlay.h"

namespace
{
  [[nodiscard]] gpg::RRef MakeTypedRef(moho::RDebugNavPath* const object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = moho::RDebugNavPath::sType ? moho::RDebugNavPath::sType : gpg::LookupRType(typeid(moho::RDebugNavPath));
    if (moho::RDebugNavPath::sType == nullptr) {
      moho::RDebugNavPath::sType = out.mType;
    }
    return out;
  }

  [[nodiscard]] gpg::RType* CachedRDebugOverlayType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::RDebugOverlay));
    }
    return sType;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00650650 (FUN_00650650, scalar deleting destructor thunk)
   */
  RDebugNavPathTypeInfo::~RDebugNavPathTypeInfo() = default;

  /**
   * Address: 0x00650640 (FUN_00650640, Moho::RDebugNavPathTypeInfo::GetName)
   */
  const char* RDebugNavPathTypeInfo::GetName() const
  {
    return "RDebugNavPath";
  }

  /**
   * Address: 0x006505F0 (FUN_006505F0, Moho::RDebugNavPathTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::RDebugNavPathTypeInfo::Register(gpg::RDbgOverlayType *this);
   */
  void RDebugNavPathTypeInfo::Init()
  {
    size_ = sizeof(RDebugNavPath);
    newRefFunc_ = &RDebugNavPathTypeInfo::NewRef;
    ctorRefFunc_ = &RDebugNavPathTypeInfo::CtrRef;
    deleteFunc_ = &RDebugNavPathTypeInfo::Delete;
    dtrFunc_ = &RDebugNavPathTypeInfo::Destruct;
    AddBase_RDebugOverlay(this);
    gpg::RType::Init();

    RegisterOverlayClass("Display the navigator paths", "NavPath");
    Finish();
  }

  /**
   * Address: 0x00650C90 (FUN_00650C90, Moho::RDebugNavPathTypeInfo::NewRef)
   */
  gpg::RRef RDebugNavPathTypeInfo::NewRef()
  {
    RDebugNavPath* const object = new (std::nothrow) RDebugNavPath();
    return MakeTypedRef(object);
  }

  /**
   * Address: 0x00650D00 (FUN_00650D00, Moho::RDebugNavPathTypeInfo::CtrRef)
   */
  gpg::RRef RDebugNavPathTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const object = static_cast<RDebugNavPath*>(objectStorage);
    if (object != nullptr) {
      new (object) RDebugNavPath();
    }
    return MakeTypedRef(object);
  }

  /**
   * Address: 0x00650CE0 (FUN_00650CE0, Moho::RDebugNavPathTypeInfo::Delete)
   */
  void RDebugNavPathTypeInfo::Delete(void* const objectStorage)
  {
    auto* const object = static_cast<RDebugNavPath*>(objectStorage);
    delete object;
  }

  /**
   * Address: 0x00650D40 (FUN_00650D40, Moho::RDebugNavPathTypeInfo::Destruct)
   */
  void RDebugNavPathTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const object = static_cast<RDebugNavPath*>(objectStorage);
    if (object != nullptr) {
      object->~RDebugNavPath();
    }
  }

  /**
   * Address: 0x00651050 (FUN_00651050, Moho::RDebugNavPathTypeInfo::AddBase_RDebugOverlay)
   */
  void RDebugNavPathTypeInfo::AddBase_RDebugOverlay(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedRDebugOverlayType();

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace moho
