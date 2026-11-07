#include "gpg/core/reflection/ReflectionPrivate.h"

namespace
{
  gpg::RType* gEUIStateRRefType = nullptr;
  thread_local TypeInfoCache3 gEUIStateRRefCache{false, {}};
  gpg::RType* gLuaRawStateRRefType = nullptr;

template <class TValue>
TValue* TryUpcastValueOrThrow(const RRef& source, const std::type_info& targetTypeInfo, RType*& cachedTargetType)
{
    if (!cachedTargetType) {
        cachedTargetType = gpg::LookupRType(targetTypeInfo);
    }

    const RRef upcast = gpg::REF_UpcastPtr(source, cachedTargetType);
    if (!upcast.mObj) {
        if (!cachedTargetType) {
            cachedTargetType = gpg::LookupRType(targetTypeInfo);
        }

        const char* const sourceName = source.mType ? source.mType->GetName() : "null";
        const char* const targetName = cachedTargetType->GetName();
        throw gpg::BadRefCast(nullptr, sourceName, targetName);
    }

    return static_cast<TValue*>(upcast.mObj);
}
}

namespace gpg
{

RType* RType::sType = nullptr;
RType* RType::TObject = nullptr;

RField::RField()
  : mName(nullptr)
  , mType(nullptr)
  , mOffset(0)
  , mFlags(0)
  , mDesc(nullptr)
{}

RField::RField(const char* name, RType* type, const int offset)
  : mName(name)
  , mType(type)
  , mOffset(offset)
  , mFlags(0)
  , mDesc(nullptr)
{}

RField::RField(const char* name, RType* type, const int offset, const int v, const char* desc)
  : mName(name)
  , mType(type)
  , mOffset(offset)
  , mFlags(v)
  , mDesc(desc)
{}

/**
 * Address: 0x00401280 (FUN_00401280)
 *
 * What it does:
 * Initializes an empty reflection reference `{nullptr, nullptr}`.
 */
RRef::RRef() noexcept
  : mObj(nullptr)
  , mType(nullptr)
{}

/**
 * Address: 0x00401290 (FUN_00401290)
 *
 * What it does:
 * Initializes a reflection reference from explicit object/type lanes.
 */
RRef::RRef(void* const ptr, RType* const type) noexcept
  : mObj(ptr)
  , mType(type)
{}

/**
 * Address: 0x009204A0 (FUN_009204A0)
 *
 * What it does:
 * Initializes one reflection reference from Lua `TString*` by routing through
 * `gpg::RRef_TString`.
 */
RRef::RRef(TString* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  staged = gpg::MakeRRef<TString>(value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x009204D0 (FUN_009204D0)
 *
 * What it does:
 * Initializes one reflection reference from a Lua `Table*` by routing through
 * `gpg::RRef_Table`.
 */
RRef::RRef(Table* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  staged = gpg::MakeRRef<Table>(value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x00920670 (FUN_00920670)
 *
 * What it does:
 * Initializes one reflection reference from Lua `LClosure*` by routing
 * through `gpg::RRef_LClosure`.
 */
RRef::RRef(LClosure* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  staged = gpg::MakeRRef<LClosure>(value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x009206A0 (FUN_009206A0)
 *
 * What it does:
 * Initializes one reflection reference from Lua `UpVal*` by routing through
 * `gpg::RRef_UpVal`.
 */
RRef::RRef(UpVal* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  staged = gpg::MakeRRef<UpVal>(value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x00920750 (FUN_00920750)
 *
 * What it does:
 * Initializes one reflection reference from Lua `Proto*` by routing through
 * `gpg::RRef_Proto`.
 */
RRef::RRef(Proto* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  staged = gpg::MakeRRef<Proto>(value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x00920780 (FUN_00920780)
 *
 * What it does:
 * Initializes one reflection reference from raw Lua `lua_State*` by routing
 * through `gpg::RRef_lua_State`.
 */
RRef::RRef(lua_State* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  staged = gpg::MakeRRef<lua_State>(value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x009207B0 (FUN_009207B0)
 *
 * What it does:
 * Initializes one reflection reference from Lua `Udata*` by routing through
 * `gpg::RRef_Udata`.
 */
RRef::RRef(Udata* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  staged = gpg::MakeRRef<Udata>(value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x00950640 (FUN_00950640)
 *
 * What it does:
 * Initializes one reflection reference from `gpg::ArchiveToken*` by routing
 * through `gpg::RRef_ArchiveToken`.
 */
RRef::RRef(ArchiveToken* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  const gpg::RRef staged = gpg::RRef_ArchiveToken(value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x008D6DA0 (FUN_008D6DA0)
 *
 * What it does:
 * Initializes one reflection reference from `moho::RUnitBlueprint*` by
 * routing through `gpg::RRef_RUnitBlueprint`.
 */
RRef::RRef(moho::RUnitBlueprint* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  staged = gpg::MakeRRef<moho::RUnitBlueprint>(value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x008E1580 (FUN_008E1580)
 *
 * What it does:
 * Initializes one reflection reference from `char*` by routing through
 * `gpg::RRef_char`.
 */
RRef::RRef(char* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  staged = gpg::MakeRRef<char>(value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x008E1650 (FUN_008E1650)
 *
 * What it does:
 * Initializes one reflection reference from `short*` by routing through
 * `gpg::RRef_short`.
 */
RRef::RRef(short* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  staged = gpg::MakeRRef<short>(value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x008E17C0 (FUN_008E17C0)
 *
 * What it does:
 * Initializes one reflection reference from `long*` by routing through
 * `gpg::RRef_long`.
 */
RRef::RRef(long* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  staged = gpg::MakeRRef<long>(value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x008E1890 (FUN_008E1890)
 *
 * What it does:
 * Initializes one reflection reference from `signed char*` by routing through
 * `gpg::RRef_schar`.
 */
RRef::RRef(signed char* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  staged = gpg::MakeRRef<signed char>(value);
  mObj = staged.mObj;
  mType = staged.mType;
}

/**
 * Address: 0x008E1A00 (FUN_008E1A00)
 *
 * What it does:
 * Initializes one reflection reference from `unsigned short*` by routing
 * through `gpg::RRef_ushort`.
 */
RRef::RRef(unsigned short* const value) noexcept
  : mObj(nullptr)
  , mType(nullptr)
{
  gpg::RRef staged{};
  staged = gpg::MakeRRef<unsigned short>(value);
  mObj = staged.mObj;
  mType = staged.mType;
}
void* RRef::GetObject() const noexcept
{
  return mObj;
}

/**
 * Address: 0x0084AB10 (FUN_0084AB10, gpg::RRef::CurrentUIState)
 *
 * What it does:
 * Builds one reflected reference bound to global `moho::sUIState`.
 */
RRef* RRef::CurrentUIState(RRef* const out)
{
  return BuildTypedRefWithCache<moho::EUIState>(
    out,
    &moho::sUIState,
    typeid(moho::EUIState),
    gEUIStateRRefType,
    gEUIStateRRefCache
  );
}

/**
 * Address: 0x00920400 (FUN_00920400, gpg::RRef::TryUpcast_lua_State)
 *
 * What it does:
 * Upcasts this reflected reference to one raw `lua_State*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
lua_State* RRef::TryUpcastLuaThreadState() const
{
  if (!gLuaRawStateRRefType) {
    gLuaRawStateRRefType = gpg::LookupRType(typeid(lua_State));
  }

  const gpg::RRef upcast = gpg::REF_UpcastPtr(*this, gLuaRawStateRRefType);
  if (!upcast.mObj) {
    const char* const sourceName = mType ? mType->GetName() : "null";
    const char* const targetName = gLuaRawStateRRefType->GetName();
    throw BadRefCast(nullptr, sourceName, targetName);
  }

  return static_cast<lua_State*>(upcast.mObj);
}

/**
 * Address: 0x008E17F0 (FUN_008E17F0, gpg::RRef::TryUpcast_long)
 *
 * What it does:
 * Upcasts this reflected reference to one `long*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
long* RRef::TryUpcastLong() const
{
  static RType* sLongType = nullptr;
  return TryUpcastValueOrThrow<long>(*this, typeid(long), sLongType);
}

/**
 * Address: 0x008E15B0 (FUN_008E15B0, gpg::RRef::TryUpcast_char)
 *
 * What it does:
 * Upcasts this reflected reference to one plain `char*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
char* RRef::TryUpcastChar() const
{
  static RType* sCharType = nullptr;
  return TryUpcastValueOrThrow<char>(*this, typeid(char), sCharType);
}

/**
 * Address: 0x008E1680 (FUN_008E1680, gpg::RRef::TryUpcast_short)
 *
 * What it does:
 * Upcasts this reflected reference to one `short*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
short* RRef::TryUpcastShort() const
{
  static RType* sShortType = nullptr;
  return TryUpcastValueOrThrow<short>(*this, typeid(short), sShortType);
}

/**
 * Address: 0x008E1720 (FUN_008E1720, gpg::RRef::TryUpcast_int)
 *
 * What it does:
 * Upcasts this reflected reference to one `int*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
int* RRef::TryUpcastInt() const
{
  static RType* sIntType = nullptr;
  return TryUpcastValueOrThrow<int>(*this, typeid(int), sIntType);
}

/**
 * Address: 0x008E18C0 (FUN_008E18C0, gpg::RRef::TryUpcast_schar)
 *
 * What it does:
 * Upcasts this reflected reference to one `signed char*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
signed char* RRef::TryUpcastSignedChar() const
{
  static RType* sSignedCharType = nullptr;
  return TryUpcastValueOrThrow<signed char>(*this, typeid(signed char), sSignedCharType);
}

/**
 * Address: 0x008E1960 (FUN_008E1960, gpg::RRef::TryUpcast_uchar)
 *
 * What it does:
 * Upcasts this reflected reference to one `unsigned char*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
unsigned char* RRef::TryUpcastUnsignedChar() const
{
  static RType* sUnsignedCharType = nullptr;
  return TryUpcastValueOrThrow<unsigned char>(*this, typeid(unsigned char), sUnsignedCharType);
}

/**
 * Address: 0x008E1A30 (FUN_008E1A30, gpg::RRef::TryUpcast_ushort)
 *
 * What it does:
 * Upcasts this reflected reference to one `unsigned short*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
unsigned short* RRef::TryUpcastUnsignedShort() const
{
  static RType* sUnsignedShortType = nullptr;
  return TryUpcastValueOrThrow<unsigned short>(*this, typeid(unsigned short), sUnsignedShortType);
}

/**
 * Address: 0x008E1AD0 (FUN_008E1AD0, gpg::RRef::TryUpcast_uint)
 *
 * What it does:
 * Upcasts this reflected reference to one `unsigned int*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
unsigned int* RRef::TryUpcastUnsignedInt() const
{
  static RType* sUnsignedIntType = nullptr;
  return TryUpcastValueOrThrow<unsigned int>(*this, typeid(unsigned int), sUnsignedIntType);
}

/**
 * Address: 0x008E1BA0 (FUN_008E1BA0, gpg::RRef::TryUpcast_ulong)
 *
 * What it does:
 * Upcasts this reflected reference to one `unsigned long*` lane and throws
 * `BadRefCast` with source/target type names on mismatch.
 */
unsigned long* RRef::TryUpcastUnsignedLong() const
{
  static RType* sUnsignedLongType = nullptr;
  return TryUpcastValueOrThrow<unsigned long>(*this, typeid(unsigned long), sUnsignedLongType);
}

/**
 * Address: 0x006EC5E0 (FUN_006EC5E0, gpg::RRef::TryUpcast_Listener_ECommandEvent)
 *
 * What it does:
 * Upcasts this reflected reference to one `Listener<ECommandEvent>` object
 * lane and throws `BadRefCast` with source/target names on mismatch.
 */
moho::Listener<moho::ECommandEvent>* RRef::TryUpcastListenerECommandEvent() const
{
  static RType* sListenerCommandEventType = nullptr;
  return TryUpcastValueOrThrow<moho::Listener<moho::ECommandEvent>>(
    *this,
    typeid(moho::Listener<moho::ECommandEvent>),
    sListenerCommandEventType
  );
}

/**
 * Address: 0x006F93D0 (FUN_006F93D0, gpg::RRef::TryUpcast_Listener_EUnitCommandQueueStatus)
 *
 * What it does:
 * Upcasts this reflected reference to one `Listener<EUnitCommandQueueStatus>`
 * object lane and throws `BadRefCast` with source/target names on mismatch.
 */
moho::Listener<moho::EUnitCommandQueueStatus>* RRef::TryUpcastListenerEUnitCommandQueueStatus() const
{
  static RType* sListenerQueueStatusType = nullptr;
  return TryUpcastValueOrThrow<moho::Listener<moho::EUnitCommandQueueStatus>>(
    *this,
    typeid(moho::Listener<moho::EUnitCommandQueueStatus>),
    sListenerQueueStatusType
  );
}

/**
 * Address: 0x0054E230 (FUN_0054E230, gpg::RRef::TryUpcast_CAniPose)
 *
 * What it does:
 * Upcasts this reflected reference to one `CAniPose` object lane and throws
 * `BadRefCast` with source/target names on mismatch.
 */
moho::CAniPose* RRef::TryUpcastCAniPose() const
{
  static RType* sCAniPoseType = nullptr;
  return TryUpcastValueOrThrow<moho::CAniPose>(*this, typeid(moho::CAniPose), sCAniPoseType);
}

/**
 * Address: 0x0067FBA0 (FUN_0067FBA0, gpg::RRef::TryUpcast_PositionHistory)
 *
 * What it does:
 * Upcasts this reflected reference to one `PositionHistory` object lane and
 * throws `BadRefCast` with source/target names on mismatch.
 */
moho::PositionHistory* RRef::TryUpcastPositionHistory() const
{
  static RType* sPositionHistoryType = nullptr;
  return TryUpcastValueOrThrow<moho::PositionHistory>(
    *this, typeid(moho::PositionHistory), sPositionHistoryType
  );
}

/**
 * Address: 0x006FD290 (FUN_006FD290, gpg::RRef::TryUpcast_Prop)
 *
 * What it does:
 * Upcasts this reflected reference to one `Prop` object lane and throws
 * `BadRefCast` with source/target names on mismatch.
 */
moho::Prop* RRef::TryUpcastProp() const
{
  static RType* sPropType = nullptr;
  return TryUpcastValueOrThrow<moho::Prop>(*this, typeid(moho::Prop), sPropType);
}

/**
 * Address: 0x004A35D0 (FUN_004A35D0)
 *
 * What it does:
 * Reads this reference as lexical text using the bound reflection type.
 */
fa::string RRef::GetLexical() const
{
  return mType->GetLexical(*this);
}

/**
 * Address: 0x004A3600 (FUN_004A3600)
 *
 * What it does:
 * Writes one lexical text value through the bound reflection type.
 */
bool RRef::SetLexical(const char* name) const
{
  return mType->SetLexical(*this, name);
}

/**
 * Address: 0x00406690 (FUN_00406690)
 *
 * What it does:
 * Returns reflected type name for this reference, or `"null"` when untyped.
 */
const char* RRef::GetName() const
{
  if (!mType) {
    return "null";
  }

  return mType->GetName();
}

/**
 * Address: 0x004A3630 (FUN_004A3630)
 *
 * What it does:
 * Returns indexed element count for this reference, or zero when unindexed.
 */
size_t RRef::GetCount() const
{
  const RIndexed* indexed = mType->IsIndexed();
  if (!indexed) {
    return 0;
  }

  return indexed->GetCount(mObj);
}

/**
 * Address: 0x004A3650 (FUN_004A3650)
 *
 * What it does:
 * Returns the bound runtime reflection type descriptor.
 */
const RType* RRef::GetRType() const
{
  return mType;
}

/**
 * Address: 0x004A3660 (FUN_004A3660)
 *
 * What it does:
 * Returns indexed-view support for the bound type.
 */
const RIndexed* RRef::IsIndexed() const
{
  return mType->IsIndexed();
}

/**
 * Address: 0x004CC9E0 (FUN_004CC9E0, gpg::RRef::IsPointer)
 *
 * What it does:
 * Returns pointer-view support for the bound type.
 */
const RIndexed* RRef::IsPointer() const
{
  return mType->IsPointer();
}

int RRef::GetNumBases() const
{
  const RField* first = mType->bases_.begin();
  if (!first) {
    return 0;
  }

  return static_cast<int>(mType->bases_.end() - first);
}

RRef RRef::GetBase(const int ind) const
{
  const RField* first = mType->bases_.begin();
  const RField& base = first[ind];

  RRef out{};
  out.mObj = static_cast<char*>(mObj) + base.mOffset;
  out.mType = base.mType;
  return out;
}

/**
 * Address: 0x004CC9B0 (FUN_004CC9B0, gpg::RRef::GetNumFields)
 *
 * What it does:
 * Returns reflected field count for the bound type.
 */
int RRef::GetNumFields() const
{
  const RField* first = mType->fields_.begin();
  if (!first) {
    return 0;
  }

  return static_cast<int>(mType->fields_.end() - first);
}

RRef RRef::GetField(const int ind) const
{
  const RField* first = mType->fields_.begin();
  const RField& field = first[ind];

  RRef out{};
  out.mObj = static_cast<char*>(mObj) + field.mOffset;
  out.mType = field.mType;
  return out;
}

/**
 * Address: 0x004A48A0 (FUN_004A48A0 -- an out-of-line copy of this body in the
 * Sim reflection-debug object, `RRef` in `ecx`, index in `eax`; zero callers and
 * no references, a linker-retained copy nothing runs.)
 */
const char* RRef::GetFieldName(const int ind) const
{
  return mType->fields_.begin()[ind].mName;
}

void RRef::Delete()
{
  if (!mObj) {
    return;
  }

  GPG_ASSERT(mType->deleteFunc_);
  mType->deleteFunc_(mObj);
}

/**
 * Address: 0x008DD460 (FUN_008DD460, ?IsA@RObject@gpg@@QBE_NPAVRType@2@@Z_0)
 *
 * What it does:
 * Returns whether this object's dynamic reflected type is derived from one
 * requested target type lane.
 */
bool RObject::IsA(RType* const type) const
{
  return GetClass()->IsDerivedFrom(type, nullptr);
}

/**
 * Address: 0x008DD950 (FUN_008DD950, ??0RType@gpg@@QAE@XZ_0)
 * Demangled: gpg::RType::RType
 *
 * What it does:
 * Initializes one reflection type descriptor to an empty, uninitialized state:
 * callback lanes cleared, vectors empty, and version/size reset to zero.
 */
RType::RType()
  : finished_(false)
  , initFinished_(false)
  , size_(0)
  , version_(0)
  , serSaveConstructArgsFunc_(nullptr)
  , serSaveFunc_(nullptr)
  , serConstructFunc_(nullptr)
  , serLoadFunc_(nullptr)
  , v8(0)
  , v9(0)
  , bases_()
  , fields_()
  , newRefFunc_(nullptr)
  , cpyRefFunc_(nullptr)
  , deleteFunc_(nullptr)
  , ctorRefFunc_(nullptr)
  , movRefFunc_(nullptr)
  , dtrFunc_(nullptr)
  , v24(false)
{}

/**
 * Address: 0x00401350 (FUN_00401350)
 * Demangled: gpg::RType::StaticGetClass
 *
 * What it does:
 * Lazily resolves and caches the reflection descriptor for `RType`.
 */
RType* RType::StaticGetClass()
{
  if (!sType) {
    sType = gpg::RTypeOf<RType>();
  }
  return sType;
}

/**
 * Address: 0x00401370 (FUN_00401370)
 * Demangled: gpg::RType::GetClass
 *
 * What it does:
 * Lazily resolves and caches the family descriptor for `RType`.
 */
RType* RType::GetClass() const
{
  return StaticGetClass();
}

/**
 * Address: 0x00401390 (FUN_00401390)
 * Demangled: gpg::RType::GetDerivedObjectRef
 *
 * What it does:
 * Packs `{this, GetClass()}` into an `RRef` handle.
 */
RRef RType::GetDerivedObjectRef()
{
  RRef out{};
  out.mObj = this;
  out.mType = GetClass();
  return out;
}

/**
 * Address: 0x008DC130 (FUN_008DC130, gpg::RType::NewRef)
 *
 * What it does:
 * Invokes the registered default-constructor callback and returns the
 * produced reference, or throws `BadRefCast` when no constructor callback is
 * registered for this type.
 */
RRef RType::NewRef() const
{
  if (!newRefFunc_) {
    throw BadRefCast("NewRef() on a type without a registered constructor");
  }

  return newRefFunc_();
}

/**
 * Address: 0x008DB100 (FUN_008DB100)
 * Demangled: gpg::RType::GetLexical
 *
 * What it does:
 * Returns default lexical text in the form `"<name> at 0x<ptr>"`.
 */
fa::string RType::GetLexical(const RRef& ref) const
{
  const auto name = GetName();
  return STR_Printf("%s at 0x%p", name, ref.mObj);
}

/**
 * Address: 0x008D86E0 (FUN_008D86E0)
 * Demangled: gpg::RType::SetLexical
 *
 * What it does:
 * Base implementation rejects lexical assignment and returns false.
 */
bool RType::SetLexical(const RRef&, const char*) const
{
  return false;
}

/**
 * Address: 0x004013B0 (FUN_004013B0)
 * Demangled: gpg::RType::IsIndexed
 *
 * What it does:
 * Base implementation reports non-indexed type.
 */
const RIndexed* RType::IsIndexed() const
{
  return nullptr;
}

/**
 * Address: 0x004013C0 (FUN_004013C0)
 * Demangled: gpg::RType::IsPointer
 *
 * What it does:
 * Base implementation reports non-pointer type.
 */
const RIndexed* RType::IsPointer() const
{
  return nullptr;
}

/**
 * Address: 0x004013D0 (FUN_004013D0)
 * Demangled: gpg::RType::IsEnumType
 *
 * What it does:
 * Base implementation reports non-enum type.
 */
const REnumType* RType::IsEnumType() const
{
  return nullptr;
}

void RType::Init() {}

/**
 * Address: 0x008DF4A0
 * SLOT: 10
 *
 * What it does:
 * Finalization: builds indices over 20-byte member records. Sorts `fields_`
 * by `mName` using the binary's own MSVC8 introsort (`fa::sort`, not
 * `std::sort` -- the 2007 implementation's tie-breaking/pivot-selection
 * shape is observably different, see `legacy/algorithms/Sort.h`). This is
 * the real instantiation root for that header's `gpg::RField` sort family:
 * `_Sort` (0x008DD790), `_Unguarded_partition` (0x008DAA00), `_Median`
 * (0x008DA410), `_Med3` (0x008D9EE0), `iter_swap` (0x008D9E20),
 * `_Insertion_sort` (0x008DB430), `make_heap`/`_Adjust_heap`
 * (0x008DB2A0/0x008DAF60), and `sort_heap`/`_Adjust_heap`
 * (0x008DBF60/0x008DB080).
 */
void RType::Finish()
{
  GPG_ASSERT(!initFinished_);

  RField* first = fields_.begin();
  if (!first) {
    return;
  }

  RField* last = fields_.end();
  if (first == last) {
    return;
  }

  fa::sort(first, last, [](const RField& a, const RField& b) {
    return std::strcmp(a.mName, b.mName) < 0;
  });
}

/**
 * Address: 0x008D8640 (FUN_008D8640, gpg::RType::Version)
 *
 * What it does:
 * Sets RTTI version once and asserts on conflicting subsequent writes.
 */
void RType::Version(const int version)
{
  GPG_ASSERT(version_ == 0 || version_ == version);
  version_ = version;
}

/**
 * Address: 0x008DF500 (FUN_008DF500)
 *
 * gpg::RField const &
 *
 * IDA signature:
 * void __thiscall gpg::RType::AddBase(gpg::RType *this, gpg::RField const *field);
 *
 * What it does:
 * Appends one direct base descriptor and flattens all fields from the base
 * type into this type's field table with subobject-offset adjustment.
 */
void RType::AddBase(const RField& field)
{
  GPG_ASSERT(!initFinished_);

  // Register the base link itself.
  bases_.push_back(field);

  // Flatten base fields into this->fields_ with offset adjustment.
  const RType* baseType = field.mType;
  if (!baseType) {
    return;
  }

  // Index by counter and re-read the base's field range every iteration, as
  // the binary does. Caching begin()/end() across the push_back below is only
  // safe while `baseType->fields_` and `fields_` are distinct buffers; the
  // original never assumes that, and a stale pointer here reads freed memory.
  for (std::size_t index = 0;; ++index) {
    const RField* const start = baseType->fields_.begin();
    if (!start) {
      // consistent with original early-exit when start==nullptr
      return;
    }
    if (index >= static_cast<std::size_t>(baseType->fields_.end() - start)) {
      return;
    }

    const RField& source = start[index];

    // Copy-by-value semantics;
    // strings/descriptions are pointer aliases in the original.
    RField out{
      // same literal pointer as in base
      source.mName,
      // same field type
      source.mType,
      // adjust offset by base field offset
      field.mOffset + source.mOffset
    };

    out.mFlags = source.mFlags;
    out.mDesc = source.mDesc;

    fields_.push_back(out);
  }
}

void RType::RegisterType()
{
  // 1) Map name -> type
  // original: this->vtable->GetName(this)
  const char* name = GetName();
  // original: *sub_8DF330(map, &name) = this;
  GetRTypeMap()[name] = this;

  // 2) Append `this` to the global type-index vector.
  //
  // The binary (FUN_008DF960) inlines the fast append and, when the vector
  // is at capacity, calls the out-of-line grow lane
  // `fa::vector<RType*>::insert` (FUN_008DD050) as `_Insert_n(_Mylast, 1, this)`.
  // Mirror that shape so the front-end emits that per-T `insert` symbol: fast
  // path when there is spare capacity, otherwise invoke `insert(end(), 1, this)`.
  TypeVec& typeVec = GetRTypeVec();
  if (typeVec.size() < typeVec.capacity()) {
    typeVec.push_back(this);
  } else {
    (void)typeVec.insert(typeVec.end(), static_cast<std::size_t>(1), this);
  }
}

/**
 * Address: 0x004EA0E0 (FUN_004EA0E0, gpg::RType::AddBlueprintAxisAlignedBox3f)
 *
 * What it does:
 * Appends six float fields for one axis-aligned-box payload:
 * min xyz at offsets 0/4/8 and max xyz at offsets 12/16/20.
 */
void RType::AddBlueprintAxisAlignedBox3f()
{
  AddField<float>("min0", 0x00);
  AddField<float>("min1", 0x04);
  AddField<float>("min2", 0x08);
  AddField<float>("max0", 0x0C);
  AddField<float>("max1", 0x10);
  AddField<float>("max2", 0x14);
}

const RField* RType::GetFieldNamed(const char* name) const
{
  GPG_ASSERT(initFinished_);

  const RField* start = fields_.begin();
  if (!start) {
    return nullptr;
  }

  const RField* finish = fields_.end();
  if (start == finish) {
    return nullptr;
  }

  // Classic binary search over [lo, hi)
  std::size_t lo = 0;
  std::size_t hi = static_cast<std::size_t>(finish - start);

  while (lo < hi) {
    const std::size_t mid = (lo + hi) >> 1;
    const RField* elem = &start[mid];

    const int cmp = std::strcmp(name, elem->mName);
    if (cmp < 0) {
      hi = mid;
    } else if (cmp > 0) {
      lo = mid + 1;
    } else {
      // exact match
      return elem;
    }
  }
  return nullptr;
}

bool RType::IsDerivedFrom(const RType* baseType, int32_t* outOffset) const
{
  if (this == baseType) {
    if (outOffset) {
      *outOffset = 0;
    }

    return true;
  }

  const RField* first = bases_.begin();
  if (!first) {
    return false;
  }

  const RField* last = bases_.end();
  if (first == last) {
    return false;
  }

  bool found = false;

  for (const RField* it = first; it != last; ++it) {
    if (it->mType->IsDerivedFrom(baseType, outOffset)) {
      if (found) {
        throw std::runtime_error("Ambiguous base class");
      }

      if (!outOffset) {
        return true;
      }

      if (outOffset) {
        *outOffset += it->mOffset;
      }

      found = true;
    }
  }

  return found;
}

/**
 * Address: 0x004180A0 (FUN_004180A0, gpg::REnumType::REnumType)
 */
gpg::REnumType::REnumType()
  : gpg::RType()
  , mPrefix(nullptr)
  , mEnumNames()
{}

fa::string REnumType::GetLexical(const RRef& ref) const
{
  const int* enumValue = static_cast<const int*>(ref.mObj);
  const int value = enumValue ? *enumValue : 0;

  const ROptionValue* it = mEnumNames.begin();
  const ROptionValue* end = mEnumNames.end();
  for (; it != end; ++it) {
    if (it->mValue == value) {
      return fa::string(it->mName ? it->mName : "");
    }
  }

  return STR_Printf("%d", value);
}

bool REnumType::SetLexical(const RRef& dest, const char* str) const
{
  if (!str || !dest.mObj) {
    return false;
  }

  int acc = 0;

  while (true) {
    // Find next separator and define token range
    const char* sep = std::strchr(str, '|');
    const char* tokenEnd = sep ? sep : (str + std::strlen(str));

    // Optional, case-sensitive prefix stripping
    const char* tokenBegin = str;
    if (mPrefix) {
      const std::size_t pn = std::strlen(mPrefix);
      if (std::strncmp(str, mPrefix, pn) == 0) {
        tokenBegin = str + pn;
      }
    }

    const std::size_t n = static_cast<std::size_t>(tokenEnd - tokenBegin);

    int num = 0;
    bool matched = false;

    // Try case-insensitive exact name match
    for (const ROptionValue& opt : mEnumNames) {
      const char* name = opt.mName ? opt.mName : "";

      const bool eq = STR_EqualsNoCaseN(tokenBegin, name, n) && name[n] == '\0';

      if (eq) {
        num = opt.mValue;
        matched = true;
        break;
      }
    }

    // Fallback: numeric parse from span [tokenBegin, tokenEnd)
    if (!matched) {
      if (!ParseNum(tokenBegin, tokenEnd, &num)) {
        return false;
      }
    }

    // Accumulate OR
    acc |= num;

    // Commit on last token
    if (!sep) {
      *static_cast<int*>(dest.mObj) = acc;
      return true;
    }

    // Next token
    str = sep + 1;
  }
}

/**
 * Address: 0x008D86F0 (FUN_008D86F0, gpg::REnumType::StripPrefix)
 *
 * What it does:
 * Returns `name` advanced past the configured enum prefix when it matches,
 * otherwise returns `name` unchanged.
 */
const char* REnumType::StripPrefix(const char* name) const
{
  // Fast path: no prefix configured
  if (!mPrefix || !*mPrefix) {
    return name;
  }

  // Compute prefix length once (the original code effectively did strlen twice)
  const std::size_t n = std::strlen(mPrefix);
  if (std::strncmp(name, mPrefix, n) == 0) {
    return name + n;
  }

  return name;
}

/**
 * Address: 0x008D9FD0 (FUN_008D9FD0)
 *
 * What it does:
 * Scans enum options and writes the matched integer value for a
 * case-insensitive enum token name.
 */
bool REnumType::GetEnumValue(const char* name, int* outVal) const
{
  const ROptionValue* it = mEnumNames.begin();
  const ROptionValue* end = mEnumNames.end();
  for (; it != end; ++it) {
    if (STR_EqualsNoCase(it->mName, name)) {
      *outVal = it->mValue;
      return true;
    }
  }
  return false;
}

/**
 * Address: 0x008DF5F0 (FUN_008DF5F0, gpg::REnumType::AddEnum)
 *
 * What it does:
 * Appends one `{value,name}` enum option entry to the reflected enum table.
 */
void REnumType::AddEnum(char const* name, const int index)
{
  const ROptionValue opt{index, name};
  (void)AppendEnumOptionValue(mEnumNames, opt);
}
}

