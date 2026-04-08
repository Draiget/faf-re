#include "moho/path/IPathTravelerTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/path/IPathTraveler.h"

namespace gpg
{
  class RDListType_IPathTraveler : public RType
  {
  public:
    /**
     * Address: 0x00766ED0 (FUN_00766ED0, gpg::RDListType_IPathTraveler::GetName)
     *
     * What it does:
     * Returns the cached lexical label for the reflected
     * `DList<IPathTraveler,void>` lane.
     */
    [[nodiscard]] const char* GetName() const override;
  };
} // namespace gpg

namespace
{
  msvc8::string gDListIPathTravelerTypeName;
  std::uint32_t gDListIPathTravelerTypeNameInitGuard = 0;
  gpg::RType* gDListVoidType = nullptr;
  gpg::RType* gDListIPathTravelerType = nullptr;

  [[nodiscard]] gpg::RType* ResolveDListVoidType()
  {
    if (gDListVoidType == nullptr) {
      gDListVoidType = gpg::REF_FindTypeNamed("void");
      if (gDListVoidType == nullptr) {
        gDListVoidType = gpg::LookupRType(typeid(void));
      }
    }

    return gDListVoidType;
  }

  [[nodiscard]] gpg::RType* ResolveDListIPathTravelerType()
  {
    if (gDListIPathTravelerType == nullptr) {
      constexpr const char* kTypeNames[] = {
        "IPathTraveler",
        "Moho::IPathTraveler",
        "class Moho::IPathTraveler",
      };

      for (const char* const name : kTypeNames) {
        if (gpg::RType* const type = gpg::REF_FindTypeNamed(name); type != nullptr) {
          gDListIPathTravelerType = type;
          break;
        }
      }

      if (gDListIPathTravelerType == nullptr) {
        gDListIPathTravelerType = gpg::LookupRType(typeid(moho::IPathTraveler));
      }
    }

    return gDListIPathTravelerType;
  }

  /**
   * Address: 0x00C01B70 (FUN_00C01B70, cleanup_RDListType_IPathTraveler_Name)
   *
   * What it does:
   * Releases cached lexical storage for
   * `gpg::RDListType_IPathTraveler::GetName`.
   */
  void cleanup_RDListType_IPathTraveler_Name()
  {
    gDListIPathTravelerTypeName.clear();
    gDListIPathTravelerTypeNameInitGuard = 0;
  }
} // namespace

/**
 * Address: 0x00766ED0 (FUN_00766ED0, gpg::RDListType_IPathTraveler::GetName)
 *
 * What it does:
 * Lazily builds and caches one reflection label for the
 * `DList<IPathTraveler,void>` lane.
 */
const char* gpg::RDListType_IPathTraveler::GetName() const
{
  if ((gDListIPathTravelerTypeNameInitGuard & 1u) == 0u) {
    gDListIPathTravelerTypeNameInitGuard |= 1u;

    const gpg::RType* const keyType = ResolveDListIPathTravelerType();
    const gpg::RType* const valueType = ResolveDListVoidType();
    const char* const keyName = keyType != nullptr ? keyType->GetName() : "IPathTraveler";
    const char* const valueName = valueType != nullptr ? valueType->GetName() : "void";

    gDListIPathTravelerTypeName = gpg::STR_Printf("DList<%s,%s>", keyName, valueName);
    (void)std::atexit(&cleanup_RDListType_IPathTraveler_Name);
  }

  return gDListIPathTravelerTypeName.c_str();
}

namespace moho
{
  /**
   * Address: 0x0076D5F0 (FUN_0076D5F0, Moho::IPathTravelerTypeInfo::dtr)
   */
  IPathTravelerTypeInfo::~IPathTravelerTypeInfo() = default;

  /**
   * Address: 0x0076D5E0 (FUN_0076D5E0, Moho::IPathTravelerTypeInfo::GetName)
   */
  const char* IPathTravelerTypeInfo::GetName() const
  {
    return "IPathTraveler";
  }

  /**
   * Address: 0x0076D5C0 (FUN_0076D5C0, Moho::IPathTravelerTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::IPathTravelerTypeInfo::Init(gpg::RType *this);
   */
  void IPathTravelerTypeInfo::Init()
  {
    size_ = sizeof(IPathTraveler);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
