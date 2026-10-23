#include "moho/path/SNamedFootprintTypeInfo.h"

#include <cstddef>
#include <typeinfo>

#include "gpg/core/reflection/RListType.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "moho/path/SNamedFootprint.h"

namespace moho
{
  static_assert(sizeof(gpg::RListType<SNamedFootprint>) == 0x64, "RListType<SNamedFootprint> size must be 0x64");

  SNamedFootprintTypeInfo::SNamedFootprintTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SNamedFootprint), this);
  }

  /**
   * Address: 0x00513DA0 (FUN_00513DA0, Moho::SNamedFootprintTypeInfo::dtr)
   *
   * What it does:
   * Releases the reflected field and base vector storage.
   */
  SNamedFootprintTypeInfo::~SNamedFootprintTypeInfo() = default;

  /**
   * Address: 0x00513D90 (FUN_00513D90, Moho::SNamedFootprintTypeInfo::GetName)
   *
   * What it does:
   * Returns the reflected type label for `SNamedFootprint`.
   */
  const char* SNamedFootprintTypeInfo::GetName() const
  {
    return "SNamedFootprint";
  }

  /**
   * Address: 0x00513D50 (FUN_00513D50, Moho::SNamedFootprintTypeInfo::Init)
   *
   * What it does:
   * Sets the reflected size, installs the base and fields, and finalizes the
   * type.
   */
  void SNamedFootprintTypeInfo::Init()
  {
    size_ = sizeof(SNamedFootprint);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00514680 (FUN_00514680)
   *
   * What it does:
   * Registers `SFootprint` as this type's reflected base at offset 0, looking
   * its type up once into `SFootprint::sType` (0x010C6D94).
   */
  void SNamedFootprintTypeInfo::AddBase_SFootprint(gpg::RType* const typeInfo)
  {
    if (SFootprint::sType == nullptr) {
      SFootprint::sType = gpg::LookupRType(typeid(SFootprint));
    }

    gpg::RType* const baseType = SFootprint::sType;
    typeInfo->AddBase(gpg::RField{baseType->GetName(), baseType, 0, 0, nullptr});
  }

  /**
   * Address: 0x00513E40 (the out-of-line copy, not an IDA function and with no references in the PE:
   * `Init` 0x00513D50 inlines it)
   *
   * What it does:
   * The `SFootprint` base, then `Name` (`AddField_string` 0x0050E1F0) and
   * `Index` (`AddField_int` 0x004EDC10).
   */
  void SNamedFootprintTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddBase_SFootprint(typeInfo);
    typeInfo->AddField<msvc8::string>("Name", offsetof(SNamedFootprint, mName));
    typeInfo->AddField<int>("Index", offsetof(SNamedFootprint, mIndex));
  }

  /**
   * Address: 0x00513CF0 (FUN_00513CF0, preregister_SNamedFootprintTypeInfo)
   * Address: 0x00BF2820 (FUN_00BF2820, atexit destructor of the SNamedFootprintTypeInfo object)
   *
   * What it does:
   * Constructs the `SNamedFootprintTypeInfo` static at 0x010AA9A8, which
   * preregisters it, and returns it.
   */
  gpg::RType* preregister_SNamedFootprintTypeInfo()
  {
    static SNamedFootprintTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x00BC8360 (FUN_00BC8360, register_SNamedFootprintTypeInfoStartup)
   *
   * What it does:
   * Preregisters `SNamedFootprint` RTTI.
   */
  void register_SNamedFootprintTypeInfoStartup()
  {
    (void)preregister_SNamedFootprintTypeInfo();
  }

  /**
   * Address: 0x005149D0 (FUN_005149D0, preregister_SNamedFootprintListTypeInfo)
   * Address: 0x00BF2910 (FUN_00BF2910, atexit destructor of the list type object)
   *
   * What it does:
   * Constructs the `gpg::RListType<SNamedFootprint>` static at 0x011047E8,
   * which preregisters it for `typeid(msvc8::list<SNamedFootprint>)`, and
   * returns it.
   */
  gpg::RType* preregister_SNamedFootprintListTypeInfo()
  {
    static gpg::RListType<SNamedFootprint> sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x00BC83A0 (FUN_00BC83A0, register_SNamedFootprintListTypeInfoStartup)
   *
   * What it does:
   * Preregisters `msvc8::list<SNamedFootprint>` RTTI.
   */
  void register_SNamedFootprintListTypeInfoStartup()
  {
    (void)preregister_SNamedFootprintListTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SNamedFootprintTypeInfoStartup_dd003b, moho::register_SNamedFootprintTypeInfoStartup)
GPG_PREREGISTER_INIT(register_SNamedFootprintListTypeInfoStartup_dd003b, moho::register_SNamedFootprintListTypeInfoStartup)
