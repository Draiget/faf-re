#include "Reflection.h"

#include <algorithm>
#include <cstdint>
#include <new>
#include <sstream>
#include <stdexcept>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/String.h"
#include "moho/lua/CLuaConOutputHandler.h"
#include "moho/task/CTaskThread.h"
using namespace gpg;

namespace
{
  RType* CachedRect2iType()
  {
    RType* type = gpg::Rect2i::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::Rect2i));
      gpg::Rect2i::sType = type;
    }
    return type;
  }

  RType* CachedRect2fType()
  {
    RType* type = gpg::Rect2f::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::Rect2f));
      gpg::Rect2f::sType = type;
    }
    return type;
  }

  RType* CachedIntType()
  {
    static RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(int));
    }
    return cached;
  }

RType* CachedFloatType()
{
    static RType* cached = nullptr;
    if (!cached) {
        cached = gpg::LookupRType(typeid(float));
    }
    return cached;
}

RType* CachedCTaskThreadType()
{
    RType* cached = moho::CTaskThread::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CTaskThread));
        moho::CTaskThread::sType = cached;
    }
    return cached;
}

RType* CachedCLuaConOutputHandlerType()
{
    RType* cached = moho::CLuaConOutputHandler::sType;
    if (!cached) {
        cached = gpg::LookupRType(typeid(moho::CLuaConOutputHandler));
        moho::CLuaConOutputHandler::sType = cached;
    }
    return cached;
}

template <class T>
RType* CachedPointerType()
{
    static RType* cached = nullptr;
    if (!cached) {
        cached = gpg::LookupRType(typeid(T*));
    }
    return cached;
}

template <class T>
RRef MakePointerSlotRef(T** const slot)
{
    RRef out{};
    out.mObj = slot;
    out.mType = CachedPointerType<T>();
    return out;
}

template <class T>
T* const* TryUpcastPointerSlotOrThrow(const RRef& source)
{
    const RRef upcast = gpg::REF_UpcastPtr(source, CachedPointerType<T>());
    if (!upcast.mObj) {
        throw std::bad_cast{};
    }

    return static_cast<T* const*>(upcast.mObj);
}

template <class T>
RRef MakePointeeRef(T* const object, RType* const baseType)
{
    RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;

    if (!object || !baseType) {
        return out;
    }

    RType* dynamicType = baseType;
    try {
        dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
        dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType->IsDerivedFrom(baseType, &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
        out.mObj = object;
        out.mType = dynamicType;
        return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
}

template <class T>
msvc8::string BuildPointerLexical(void* const slotObject, RType* const pointeeType)
{
    auto* const slot = static_cast<T**>(slotObject);
    if (!slot || !*slot) {
        return msvc8::string("NULL");
    }

    const RRef pointeeRef = MakePointeeRef<T>(*slot, pointeeType);
    if (!pointeeRef.mObj) {
        return msvc8::string("NULL");
    }

    const msvc8::string inner = pointeeRef.GetLexical();
    return STR_Printf("[%s]", inner.c_str());
}

msvc8::string BuildPointerName(RType* const pointeeType)
{
    const char* pointeeName = pointeeType ? pointeeType->GetName() : "null";
    if (!pointeeName) {
        pointeeName = "null";
    }
    return STR_Printf("%s*", pointeeName);
}

template <class T>
RRef NewPointerSlotRef()
{
    auto* const slot = static_cast<T**>(::operator new(sizeof(T*)));
    return MakePointerSlotRef<T>(slot);
}

template <class T>
RRef CopyPointerSlotRef(RRef* const sourceRef)
{
    auto* const slot = static_cast<T**>(::operator new(sizeof(T*)));
    *slot = nullptr;
    if (sourceRef) {
        T* const* const sourceSlot = TryUpcastPointerSlotOrThrow<T>(*sourceRef);
        *slot = sourceSlot ? *sourceSlot : nullptr;
    }
    return MakePointerSlotRef<T>(slot);
}

template <class T>
RRef ConstructPointerSlotRef(void* const slotObject)
{
    return MakePointerSlotRef<T>(static_cast<T**>(slotObject));
}

template <class T>
RRef MovePointerSlotRef(void* const slotObject, RRef* const sourceRef)
{
    auto* const slot = static_cast<T**>(slotObject);
    if (slot) {
        *slot = nullptr;
        if (sourceRef) {
            T* const* const sourceSlot = TryUpcastPointerSlotOrThrow<T>(*sourceRef);
            *slot = sourceSlot ? *sourceSlot : nullptr;
        }
    }
    return MakePointerSlotRef<T>(slot);
}

template <class T>
void DeletePointerSlot(void* const slotObject)
{
    ::operator delete(slotObject);
}

  void SerializeRect2i(WriteArchive* archive, const int objectPtr, int, RRef*)
  {
    auto* const rect = reinterpret_cast<gpg::Rect2i*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(rect != nullptr);
    if (!archive || !rect) {
      return;
    }

    archive->WriteInt(rect->x0);
    archive->WriteInt(rect->z0);
    archive->WriteInt(rect->x1);
    archive->WriteInt(rect->z1);
  }

  void DeserializeRect2i(ReadArchive* archive, const int objectPtr, int, RRef*)
  {
    auto* const rect = reinterpret_cast<gpg::Rect2i*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(rect != nullptr);
    if (!archive || !rect) {
      return;
    }

    archive->ReadInt(&rect->x0);
    archive->ReadInt(&rect->z0);
    archive->ReadInt(&rect->x1);
    archive->ReadInt(&rect->z1);
  }

  void SerializeRect2f(WriteArchive* archive, const int objectPtr, int, RRef*)
  {
    auto* const rect = reinterpret_cast<gpg::Rect2f*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(rect != nullptr);
    if (!archive || !rect) {
      return;
    }

    archive->WriteFloat(rect->x0);
    archive->WriteFloat(rect->z0);
    archive->WriteFloat(rect->x1);
    archive->WriteFloat(rect->z1);
  }

  void DeserializeRect2f(ReadArchive* archive, const int objectPtr, int, RRef*)
  {
    auto* const rect = reinterpret_cast<gpg::Rect2f*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(rect != nullptr);
    if (!archive || !rect) {
      return;
    }

    archive->ReadFloat(&rect->x0);
    archive->ReadFloat(&rect->z0);
    archive->ReadFloat(&rect->x1);
    archive->ReadFloat(&rect->z1);
  }

  void AddRect2IntField(RType* typeInfo, const char* fieldName, const int offset)
  {
    typeInfo->fields_.push_back(RField(fieldName, CachedIntType(), offset));
  }

  void AddRect2FloatField(RType* typeInfo, const char* fieldName, const int offset)
  {
    typeInfo->fields_.push_back(RField(fieldName, CachedFloatType(), offset));
  }

gpg::Rect2iTypeInfo gRect2iTypeInfo;
gpg::Rect2fTypeInfo gRect2fTypeInfo;
gpg::Rect2iSerializer gRect2iSerializer;
gpg::Rect2fSerializer gRect2fSerializer;
gpg::RPointerType<moho::CTaskThread> gCTaskThreadPointerType;
gpg::RPointerType<moho::CLuaConOutputHandler> gCLuaConOutputHandlerPointerType;

  struct Rect2ReflectionRegistration
  {
    Rect2ReflectionRegistration()
    {
      gpg::PreRegisterRType(typeid(gpg::Rect2i), &gRect2iTypeInfo);
      gpg::PreRegisterRType(typeid(gpg::Rect2f), &gRect2fTypeInfo);

      gRect2iSerializer.mHelperNext = nullptr;
      gRect2iSerializer.mHelperPrev = nullptr;
      gRect2iSerializer.mLoadCallback = &DeserializeRect2i;
      gRect2iSerializer.mSaveCallback = &SerializeRect2i;

      gRect2fSerializer.mHelperNext = nullptr;
      gRect2fSerializer.mHelperPrev = nullptr;
      gRect2fSerializer.mLoadCallback = &DeserializeRect2f;
      gRect2fSerializer.mSaveCallback = &SerializeRect2f;

      gRect2iSerializer.RegisterSerializeFunctions();
      gRect2fSerializer.RegisterSerializeFunctions();
    }
  };

Rect2ReflectionRegistration gRect2ReflectionRegistration;

struct PointerTypeRegistration
{
    PointerTypeRegistration()
    {
        gpg::PreRegisterRType(typeid(moho::CTaskThread*), &gCTaskThreadPointerType);
        gpg::PreRegisterRType(typeid(moho::CLuaConOutputHandler*), &gCLuaConOutputHandlerPointerType);
    }
};

PointerTypeRegistration gPointerTypeRegistration;
} // namespace

RField::RField()
  : mName(nullptr)
  , mType(nullptr)
  , mOffset(0)
  , v4(0)
  , mDesc(nullptr)
{}

RField::RField(const char* name, RType* type, const int offset)
  : mName(name)
  , mType(type)
  , mOffset(offset)
  , v4(0)
  , mDesc(nullptr)
{}

RField::RField(const char* name, RType* type, const int offset, const int v, const char* desc)
  : mName(name)
  , mType(type)
  , mOffset(offset)
  , v4(v)
  , mDesc(desc)
{}

RType* gpg::LookupRType(const std::type_info& typeInfo)
{
  TypeInfoMap& preregistered = GetRTypePreregisteredMap();
  const TypeInfoMap::iterator it = preregistered.find(&typeInfo);
  if (it == preregistered.end()) {
    const msvc8::string msg =
      STR_Printf("Attempting to lookup the RType for %s before it is registered.", typeInfo.name());
    throw std::runtime_error(msg.c_str());
  }

  RType* type = it->second;
  if (!type->finished_) {
    type->finished_ = true;
    type->Init();
    type->RegisterType();
    type->initFinished_ = true;
  }

  return type;
}

void gpg::PreRegisterRType(const std::type_info& typeInfo, RType* type)
{
  GetRTypePreregisteredMap().insert(TypeInfoMap::value_type(&typeInfo, type));
}

void gpg::REF_RegisterAllTypes()
{
  std::stringstream errs;

  for (TypeInfoMap::const_iterator it = GetRTypePreregisteredMap().begin(); it != GetRTypePreregisteredMap().end();
       ++it) {
    try {
      (void)LookupRType(*it->first);
    } catch (const std::exception& ex) {
      errs << ex.what() << std::endl;
    }
  }

  const std::string aggregated = errs.str();
  if (!aggregated.empty()) {
    throw std::runtime_error(aggregated);
  }
}

const RType* gpg::REF_GetTypeIndexed(const int index)
{
  return GetRTypeVec()[index];
}

RType* gpg::REF_FindTypeNamed(const char* const name)
{
  if (!name) {
    return nullptr;
  }

  const TypeMap::const_iterator it = GetRTypeMap().find(name);
  if (it == GetRTypeMap().end()) {
    return nullptr;
  }

  return it->second;
}

RRef gpg::REF_UpcastPtr(const RRef& source, const RType* const targetType)
{
  RRef out{};
  if (!source.mObj || !source.mType || !targetType) {
    return out;
  }

  std::int32_t offset = 0;
  if (!source.mType->IsDerivedFrom(targetType, &offset)) {
    return out;
  }

  out.mObj = reinterpret_cast<void*>(reinterpret_cast<std::intptr_t>(source.mObj) + static_cast<std::intptr_t>(offset));
  out.mType = const_cast<RType*>(targetType);
  return out;
}

RRef gpg::RRef_ArchiveToken(ArchiveToken* const token)
{
  RRef out{};
  out.mObj = token;

  try {
    out.mType = LookupRType(typeid(ArchiveToken));
  } catch (...) {
    out.mType = nullptr;
  }

  return out;
}

msvc8::string RRef::GetLexical() const
{
  return mType->GetLexical(*this);
}

bool RRef::SetLexical(const char* name) const
{
  return mType->SetLexical(*this, name);
}

const char* RRef::GetTypeName() const
{
  if (!mType) {
    return "null";
  }

  return mType->GetName();
}

RRef RRef::operator[](const unsigned int ind) const
{
  const RIndexed* indexed = mType->IsIndexed();
  return indexed->SubscriptIndex(mObj, static_cast<int>(ind));
}

size_t RRef::GetCount() const
{
  const RIndexed* indexed = mType->IsIndexed();
  if (!indexed) {
    return 0;
  }

  return indexed->GetCount(mObj);
}

const RType* RRef::GetRType() const
{
  return mType;
}

const RIndexed* RRef::IsIndexed() const
{
  return mType->IsIndexed();
}

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
 * Address: 0x004012D0 (FUN_004012D0)
 * Demangled: gpg::RObject::dtr
 *
 * What it does:
 * Owns deleting-dtor lane for RObject base and conditionally frees `this`.
 */
RObject::~RObject() noexcept = default;

/**
 * Address: 0x004012F0 (FUN_004012F0)
 * Demangled: gpg::RIndexed::SetCount
 *
 * What it does:
 * Base implementation rejects resize/count mutation for non-resizable indexed types.
 */
void RIndexed::SetCount(void*, int) const
{
  throw std::bad_cast{};
}

/**
 * Address: 0x00401320 (FUN_00401320)
 * Demangled: gpg::RIndexed::AssignPointer
 *
 * What it does:
 * Base implementation rejects pointer assignment for non-pointer indexed types.
 */
void RIndexed::AssignPointer(void*, const RRef&) const
{
    throw std::bad_cast{};
}

RRef gpg::RPointerTypeBase::SubscriptIndex(void* const obj, const int ind) const
{
    GPG_ASSERT(ind == 0);
    if (ind != 0) {
        return {};
    }

    auto* const slot = static_cast<void**>(obj);
    RType* const pointeeType = GetPointeeType();

    RRef out{};
    out.mObj = slot ? *slot : nullptr;
    out.mType = pointeeType;
    if (!out.mObj || !pointeeType) {
        return out;
    }

    if (pointeeType->ctorRefFunc_) {
        return pointeeType->ctorRefFunc_(out.mObj);
    }

    return out;
}

size_t gpg::RPointerTypeBase::GetCount(void* const obj) const
{
    auto* const slot = static_cast<void**>(obj);
    return (slot && *slot) ? 1u : 0u;
}

void gpg::RPointerTypeBase::SetCount(void* const obj, const int count) const
{
    auto* const slot = static_cast<void**>(obj);
    if (!slot) {
        throw std::bad_cast{};
    }

    if (count == 0) {
        *slot = nullptr;
        return;
    }
    if (count == 1) {
        return;
    }

    throw std::bad_cast{};
}

void gpg::RPointerTypeBase::AssignPointer(void* const obj, const RRef& from) const
{
    auto* const slot = static_cast<void**>(obj);
    GPG_ASSERT(slot != nullptr);
    if (!slot) {
        return;
    }

    if (!from.mObj) {
        *slot = nullptr;
        return;
    }

    const RRef upcast = REF_UpcastPtr(from, GetPointeeType());
    if (!upcast.mObj) {
        throw std::bad_cast{};
    }

    *slot = upcast.mObj;
}

const RIndexed* gpg::RPointerTypeBase::AsIndexedSelf() const noexcept
{
    return this;
}

/**
 * Address: 0x0040CBD0 (FUN_0040CBD0)
 * Demangled: sub_40CBD0
 */
gpg::RPointerType<moho::CTaskThread>::~RPointerType() = default;

/**
 * Address: 0x0040C7C0 (FUN_0040C7C0)
 * Demangled: gpg::RPointerType_CTaskThread::GetName
 */
const char* gpg::RPointerType<moho::CTaskThread>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x0040C950 (FUN_0040C950)
 * Demangled: gpg::RPointerType_CTaskThread::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CTaskThread>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CTaskThread>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x0040CAD0 (FUN_0040CAD0)
 * Demangled: gpg::RPointerType_CTaskThread::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CTaskThread>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0040CAE0 (FUN_0040CAE0)
 * Demangled: gpg::RPointerType_CTaskThread::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CTaskThread>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x0040C920 (FUN_0040C920)
 * Demangled: gpg::RPointerType_CTaskThread::Init
 */
void gpg::RPointerType<moho::CTaskThread>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CTaskThread*);
    newRefFunc_ = &NewPointerSlotRef<moho::CTaskThread>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::CTaskThread>;
    deleteFunc_ = &DeletePointerSlot<moho::CTaskThread>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::CTaskThread>;
    movRefFunc_ = &MovePointerSlotRef<moho::CTaskThread>;
}

RType* gpg::RPointerType<moho::CTaskThread>::GetPointeeType() const
{
    return CachedCTaskThreadType();
}

/**
 * Address: 0x004215C0 (FUN_004215C0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::dtr
 */
gpg::RPointerType<moho::CLuaConOutputHandler>::~RPointerType() = default;

/**
 * Address: 0x004211B0 (FUN_004211B0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::GetName
 */
const char* gpg::RPointerType<moho::CLuaConOutputHandler>::GetName() const
{
    static msvc8::string cachedName;
    if (cachedName.empty()) {
        cachedName = BuildPointerName(GetPointeeType());
    }
    return cachedName.c_str();
}

/**
 * Address: 0x00421340 (FUN_00421340)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::GetLexical
 */
msvc8::string gpg::RPointerType<moho::CLuaConOutputHandler>::GetLexical(const RRef& ref) const
{
    return BuildPointerLexical<moho::CLuaConOutputHandler>(ref.mObj, GetPointeeType());
}

/**
 * Address: 0x004214C0 (FUN_004214C0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::IsIndexed
 */
const RIndexed* gpg::RPointerType<moho::CLuaConOutputHandler>::IsIndexed() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x004214D0 (FUN_004214D0)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::IsPointer
 */
const RIndexed* gpg::RPointerType<moho::CLuaConOutputHandler>::IsPointer() const
{
    return AsIndexedSelf();
}

/**
 * Address: 0x00421310 (FUN_00421310)
 * Demangled: gpg::RPointerType_CLuaConOutputHandler::Init
 */
void gpg::RPointerType<moho::CLuaConOutputHandler>::Init()
{
    v24 = true;
    size_ = sizeof(moho::CLuaConOutputHandler*);
    newRefFunc_ = &NewPointerSlotRef<moho::CLuaConOutputHandler>;
    cpyRefFunc_ = &CopyPointerSlotRef<moho::CLuaConOutputHandler>;
    deleteFunc_ = &DeletePointerSlot<moho::CLuaConOutputHandler>;
    ctorRefFunc_ = &ConstructPointerSlotRef<moho::CLuaConOutputHandler>;
    movRefFunc_ = &MovePointerSlotRef<moho::CLuaConOutputHandler>;
}

RType* gpg::RPointerType<moho::CLuaConOutputHandler>::GetPointeeType() const
{
    return CachedCLuaConOutputHandlerType();
}

/**
 * Address: 0x008DD9D0 (FUN_008DD9D0)
 * Demangled: gpg::RType::dtr
 *
 * What it does:
 * Destroys base reflection type descriptor state.
 */
RType::~RType() = default;

/**
 * Address: 0x00401370 (FUN_00401370)
 * Demangled: gpg::RType::GetClass
 *
 * What it does:
 * Lazily resolves and caches the family descriptor for `RType`.
 */
RType* RType::GetClass() const
{
  static RType* familyDescriptor = nullptr;
  if (!familyDescriptor) {
    familyDescriptor = LookupRType(typeid(RType));
  }
  return familyDescriptor;
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
 * Address: 0x008DB100 (FUN_008DB100)
 * Demangled: gpg::RType::GetLexical
 *
 * What it does:
 * Returns default lexical text in the form `"<name> at 0x<ptr>"`.
 */
msvc8::string RType::GetLexical(const RRef& ref) const
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

  std::sort(first, last, [](const RField& a, const RField& b) {
    return std::strcmp(a.mName, b.mName) < 0;
  });
}

void RType::Version(const int version)
{
  GPG_ASSERT(version_ == 0 || version_ == version);
  version_ = version;
}

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

  // MSVC8 vector layout may expose raw pointers;
  // keep null-safe checks like in the original.
  const RField* it = baseType->fields_.begin();
  const RField* end = baseType->fields_.end();
  if (!it)
    return; // consistent with original early-exit when start==nullptr

  for (; it < end; ++it) {
    // Copy-by-value semantics;
    // strings/descriptions are pointer aliases in the original.
    RField out{
      // same literal pointer as in base
      it->mName,
      // same field type
      it->mType,
      // adjust offset by base field offset
      field.mOffset + it->mOffset
    };

    out.v4 = it->v4;
    out.mDesc = it->mDesc;

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

  // 2) Append to global type list
  GetRTypeVec().push_back(this);
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

      if (outOffset) {
        *outOffset += it->mOffset;
      }

      found = true;
    }
  }

  return found;
}

/**
 * Address: 0x00905E40 (FUN_00905E40)
 * Demangled: gpg::SerSaveLoadHelper<class gpg::Rect2<int>>::Init
 *
 * What it does:
 * Lazily resolves Rect2<int> RTTI and installs serializer callbacks from this helper.
 */
void gpg::Rect2iSerializer::RegisterSerializeFunctions()
{
  RType* const type = CachedRect2iType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00905EE0 (FUN_00905EE0)
 * Demangled: gpg::SerSaveLoadHelper<class gpg::Rect2<float>>::Init
 *
 * What it does:
 * Lazily resolves Rect2<float> RTTI and installs serializer callbacks from this helper.
 */
void gpg::Rect2fSerializer::RegisterSerializeFunctions()
{
  RType* const type = CachedRect2fType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSaveCallback;
}

/**
 * Address: 0x00906020 (FUN_00906020)
 * Demangled: gpg::Rect2iTypeInfo::GetName
 */
const char* gpg::Rect2iTypeInfo::GetName() const
{
  return "Rect2i";
}

/**
 * Address: 0x009060D0 (FUN_009060D0)
 * Demangled: gpg::Rect2fTypeInfo::GetName
 */
const char* gpg::Rect2fTypeInfo::GetName() const
{
  return "Rect2f";
}

/**
 * Address: 0x00906270 (FUN_00906270)
 * Demangled: gpg::Rect2iTypeInfo::Init
 *
 * What it does:
 * Sets reflected object size, registers int fields x0/y0/x1/y1, and finalizes indices.
 */
void gpg::Rect2iTypeInfo::Init()
{
  size_ = sizeof(Rect2i);
  gpg::RType::Init();
  AddRect2IntField(this, "x0", offsetof(Rect2i, x0));
  AddRect2IntField(this, "y0", offsetof(Rect2i, z0));
  AddRect2IntField(this, "x1", offsetof(Rect2i, x1));
  AddRect2IntField(this, "y1", offsetof(Rect2i, z1));
  Finish();
}

/**
 * Address: 0x009062D0 (FUN_009062D0)
 * Demangled: gpg::Rect2fTypeInfo::Init
 *
 * What it does:
 * Sets reflected object size, registers float fields x0/y0/x1/y1, and finalizes indices.
 */
void gpg::Rect2fTypeInfo::Init()
{
  size_ = sizeof(Rect2f);
  gpg::RType::Init();
  AddRect2FloatField(this, "x0", offsetof(Rect2f, x0));
  AddRect2FloatField(this, "y0", offsetof(Rect2f, z0));
  AddRect2FloatField(this, "x1", offsetof(Rect2f, x1));
  AddRect2FloatField(this, "y1", offsetof(Rect2f, z1));
  Finish();
}

msvc8::string REnumType::GetLexical(const RRef& ref) const
{
  const int* enumValue = static_cast<const int*>(ref.mObj);
  const int value = enumValue ? *enumValue : 0;

  const ROptionValue* it = mEnumNames.begin();
  const ROptionValue* end = mEnumNames.end();
  for (; it != end; ++it) {
    if (it->mValue == value) {
      return msvc8::string(it->mName ? it->mName : "");
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

void REnumType::AddEnum(char const* name, const int index)
{
  const ROptionValue opt{index, name};
  mEnumNames.push_back(opt);
}
