#include "moho/entity/EntitySetReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityFastVectorReflection.h"

namespace
{
  using EntitySet = moho::EntitySetTemplate<moho::Entity>;
  using WeakEntitySet = moho::WeakEntitySetTemplate<moho::Entity>;

  /**
   * Address: 0x00BFCCC0 (FUN_00BFCCC0, atexit destructor of the moho::EntitySetBaseTypeInfo object)
   */
  [[nodiscard]] moho::EntitySetBaseTypeInfo& AcquireEntitySetBaseTypeInfo()
  {
    static moho::EntitySetBaseTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BFCD50 (FUN_00BFCD50, atexit destructor of the moho::EntitySetTypeInfo object)
   */
  [[nodiscard]] moho::EntitySetTypeInfo& AcquireEntitySetTypeInfo()
  {
    static moho::EntitySetTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BFCDE0 (FUN_00BFCDE0, atexit destructor of the moho::WeakEntitySetTypeInfo object)
   */
  [[nodiscard]] moho::WeakEntitySetTypeInfo& AcquireWeakEntitySetTypeInfo()
  {
    static moho::WeakEntitySetTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00689740 (FUN_00689740)
   *
   * What it does:
   * Resolves and caches RTTI for one `EntitySetBase` lane.
   */
  [[nodiscard]] gpg::RType* ResolveEntitySetBaseType()
  {
    gpg::RType* type = moho::EntitySetBase::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::EntitySetBase));
      moho::EntitySetBase::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveEntitySetType()
  {
    gpg::RType* type = EntitySet::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(EntitySet));
      EntitySet::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    return type;
  }

  /**
   * Address: 0x006940F0 (FUN_006940F0)
   *
   * What it does:
   * Resolves and caches RTTI for one `WeakEntitySetTemplate<Entity>` lane.
   */
  [[nodiscard]] gpg::RType* ResolveWeakEntitySetType()
  {
    gpg::RType* type = WeakEntitySet::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(WeakEntitySet));
      WeakEntitySet::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    return type;
  }

  /**
   * Address: 0x006947C0 (FUN_006947C0)
   *
   * What it does:
   * Resolves and caches RTTI for one `fastvector<Entity*>` lane.
   */
  [[nodiscard]] gpg::RType* ResolveFastVectorEntityPointerType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::fastvector<moho::Entity*>));
      if (!type) {
        type = moho::register_FastVectorEntityPtrType_00();
      }
    }

    GPG_ASSERT(type != nullptr);
    return type;
  }

  // Address 0x006947E0 (the duplicate RTTI-resolve "VariantB" lane formerly
  // modeled here) is dead: zero data_refs and zero call_edges in the
  // callgraph index, and no source-level caller anywhere in src/sdk/**.
  // ResolveFastVectorEntityPointerType above is the real, heavily-used
  // resolver and already covers this address's behavior.

  [[nodiscard]] gpg::RRef MakeEntitySetBaseRef(
    moho::EntitySetBase* object
  )
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = ResolveEntitySetBaseType();
    return ref;
  }

  /**
   * Address: 0x006944B0 (FUN_006944B0)
   *
   * What it does:
   * Deserializes one `EntitySetBase` object lane through archive owner context
   * and returns the archive instance.
   */
  gpg::ReadArchive* ReadEntitySetBaseArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    archive->Read(ResolveEntitySetBaseType(), object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x006944F0 (FUN_006944F0)
   *
   * What it does:
   * Serializes one `EntitySetBase` object lane through archive owner context
   * and returns the archive instance.
   */
  gpg::WriteArchive* WriteEntitySetBaseArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    archive->Write(ResolveEntitySetBaseType(), objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00694530 (FUN_00694530)
   *
   * What it does:
   * Deserializes one `EntitySetBase` object lane through archive owner context.
   */
  void ReadEntitySetBaseArchiveObjectLane1(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    archive->Read(ResolveEntitySetBaseType(), object, *ownerRef);
  }

  /**
   * Address: 0x00694560 (FUN_00694560)
   *
   * What it does:
   * Serializes one `EntitySetBase` object lane through archive owner context.
   */
  void WriteEntitySetBaseArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    archive->Write(ResolveEntitySetBaseType(), objectSlot, *ownerRef);
  }

  /**
   * Address: 0x006946E0 (FUN_006946E0)
   *
   * What it does:
   * Deserializes one `fastvector<Entity*>` object lane through archive owner
   * context and returns the archive instance.
   */
  gpg::ReadArchive* ReadFastVectorEntityPointerArchiveAdapter(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    archive->Read(ResolveFastVectorEntityPointerType(), object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00694720 (FUN_00694720)
   *
   * What it does:
   * Serializes one `fastvector<Entity*>` object lane through archive owner
   * context and returns the archive instance.
   */
  gpg::WriteArchive* WriteFastVectorEntityPointerArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    archive->Write(ResolveFastVectorEntityPointerType(), objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00694760 (FUN_00694760)
   *
   * What it does:
   * Deserializes one `fastvector<Entity*>` object lane through archive owner
   * context.
   */
  void ReadFastVectorEntityPointerArchiveObjectLane1(
    gpg::ReadArchive* const archive,
    void* const object,
    gpg::RRef* const ownerRef
  )
  {
    archive->Read(ResolveFastVectorEntityPointerType(), object, *ownerRef);
  }

  /**
   * Address: 0x00694790 (FUN_00694790)
   *
   * What it does:
   * Serializes one `fastvector<Entity*>` object lane through archive owner
   * context.
   */
  void WriteFastVectorEntityPointerArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    archive->Write(ResolveFastVectorEntityPointerType(), objectSlot, *ownerRef);
  }

  // Addresses 0x00694160/0x00694490 (the "ThunkA"/"ThunkB" bridge duplicates
  // formerly modeled here) are dead: zero data_refs and zero call_edges in
  // the callgraph index for both, and no source-level caller anywhere in
  // src/sdk/**. `EntitySetBaseSerializer::Deserialize` below already calls
  // `DeserializeEntitySetBaseSerializerBody` above directly.

  // Addresses 0x00694170/0x006944A0 (the "ThunkA"/"ThunkB" register-shape
  // duplicates formerly modeled here) are dead: zero data_refs and zero
  // call_edges in the callgraph index for both, and no source-level caller
  // anywhere in src/sdk/**. `EntitySetBaseSerializer::Serialize` below
  // already calls `SerializeEntitySetBaseSerializerBody` above directly.

  /**
   * Address: 0x006946B0 (FUN_006946B0)
   *
   * What it does:
   * Builds one temporary `RRef_EntitySetBase` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* PackRRef_EntitySetBase(
    gpg::RRef* const out,
    moho::EntitySetBase* const value
  )
  {
    gpg::RRef tmp{};
    tmp = gpg::MakeRRef<moho::EntitySetBase>(value);
    out->mObj = tmp.mObj;
    out->mType = tmp.mType;
    return out;
  }

  /**
   * Address: 0x00693660 (FUN_00693660, sub_693660)
   *
   * What it does:
   * Clears reflected base/field vectors for `EntitySetBaseTypeInfo`.
   */
  void reset_EntitySetBaseTypeInfoVectors(
    moho::EntitySetBaseTypeInfo* const typeInfo
  )
  {
    if (!typeInfo) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x00693850 (FUN_00693850, sub_693850)
   *
   * What it does:
   * Clears reflected base/field vectors for `EntitySetTypeInfo`.
   */
  void reset_EntitySetTypeInfoVectors(
    moho::EntitySetTypeInfo* const typeInfo
  )
  {
    if (!typeInfo) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x00693AA0 (FUN_00693AA0, sub_693AA0)
   *
   * What it does:
   * Clears reflected base/field vectors for `WeakEntitySetTypeInfo`.
   */
  void reset_WeakEntitySetTypeInfoVectors(
    moho::WeakEntitySetTypeInfo* const typeInfo
  )
  {
    if (!typeInfo) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x00693570 (FUN_00693570, sub_693570)
   */
  EntitySetBaseTypeInfo::EntitySetBaseTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(EntitySetBase), this);
  }

  /**
   * Address: 0x00693600 (FUN_00693600, Moho::EntitySetBaseTypeInfo::dtr)
   */
  EntitySetBaseTypeInfo::~EntitySetBaseTypeInfo()
  {
    reset_EntitySetBaseTypeInfoVectors(this);
  }

  /**
   * Address: 0x006935F0 (FUN_006935F0, Moho::EntitySetBaseTypeInfo::GetName)
   */
  const char* EntitySetBaseTypeInfo::GetName() const
  {
    return "EntitySetBase";
  }

  /**
   * Address: 0x006935D0 (FUN_006935D0, Moho::EntitySetBaseTypeInfo::Init)
   */
  void EntitySetBaseTypeInfo::Init()
  {
    size_ = sizeof(EntitySetBase);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00693760 (FUN_00693760, sub_693760)
   */
  EntitySetTypeInfo::EntitySetTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(EntitySet), this);
  }

  /**
   * Address: 0x006937F0 (FUN_006937F0, Moho::EntitySetTypeInfo::dtr)
   */
  EntitySetTypeInfo::~EntitySetTypeInfo()
  {
    reset_EntitySetTypeInfoVectors(this);
  }

  /**
   * Address: 0x006937E0 (FUN_006937E0, Moho::EntitySetTypeInfo::GetName)
   */
  const char* EntitySetTypeInfo::GetName() const
  {
    return "EntitySet";
  }

  /**
   * Address: 0x00694180 (FUN_00694180, Moho::EntitySetTypeInfo::AddBase_EntitySetBase)
   */
  void EntitySetTypeInfo::AddBase_EntitySetBaseVariant1(
    gpg::RType* const typeInfo
  )
  {
    gpg::RType* const baseType = ResolveEntitySetBaseType();

    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(baseType != nullptr);
    if (!typeInfo || !baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00693890 (FUN_00693890, sub_693890)
   *
   * What it does:
   * Bridge thunk that forwards to `EntitySetTypeInfo::AddBase_EntitySetBase`.
   */
  void add_EntitySetBaseBase(
    gpg::RType* const typeInfo
  )
  {
    EntitySetTypeInfo::AddBase_EntitySetBaseVariant1(typeInfo);
  }

  /**
   * Address: 0x006937C0 (FUN_006937C0, Moho::EntitySetTypeInfo::Init)
   */
  void EntitySetTypeInfo::Init()
  {
    size_ = sizeof(EntitySet);
    gpg::RType::Init();
    add_EntitySetBaseBase(this);
    Finish();
  }

  /**
   * Address: 0x006939B0 (FUN_006939B0, sub_6939B0)
   */
  WeakEntitySetTypeInfo::WeakEntitySetTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(WeakEntitySet), this);
  }

  /**
   * Address: 0x00693A40 (FUN_00693A40, Moho::WeakEntitySetTypeInfo::dtr)
   */
  WeakEntitySetTypeInfo::~WeakEntitySetTypeInfo()
  {
    reset_WeakEntitySetTypeInfoVectors(this);
  }

  /**
   * Address: 0x00693A30 (FUN_00693A30, Moho::WeakEntitySetTypeInfo::GetName)
   */
  const char* WeakEntitySetTypeInfo::GetName() const
  {
    return "WeakEntitySet";
  }

  /**
   * Address: 0x00694260 (FUN_00694260, Moho::WeakEntitySetTypeInfo::AddBase_EntitySetTemplate_Entity)
   */
  void WeakEntitySetTypeInfo::AddBase_EntitySet(
    gpg::RType* const typeInfo
  )
  {
    gpg::RType* const baseType = ResolveEntitySetType();

    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(baseType != nullptr);
    if (!typeInfo || !baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00693AE0 (FUN_00693AE0, sub_693AE0)
   *
   * What it does:
   * Bridge thunk that forwards to `WeakEntitySetTypeInfo::AddBase_EntitySet`.
   */
  void add_EntitySetBaseWeakBase(
    gpg::RType* const typeInfo
  )
  {
    WeakEntitySetTypeInfo::AddBase_EntitySet(typeInfo);
  }

  /**
   * Address: 0x00693A10 (FUN_00693A10, Moho::WeakEntitySetTypeInfo::Init)
   */
  void WeakEntitySetTypeInfo::Init()
  {
    size_ = sizeof(WeakEntitySet);
    gpg::RType::Init();
    add_EntitySetBaseWeakBase(this);
    Finish();
  }

  /**
   * Address: 0x00BD5770 (FUN_00BD5770, sub_BD5770)
   */
  void register_EntitySetBaseTypeInfo()
  {
    (void)AcquireEntitySetBaseTypeInfo();
  }

  /**
   * Address: 0x00BD57D0 (FUN_00BD57D0, sub_BD57D0)
   */
  void register_EntitySetTypeInfo()
  {
    (void)AcquireEntitySetTypeInfo();
  }

  /**
   * Address: 0x00BD5830 (FUN_00BD5830, sub_BD5830)
   */
  void register_WeakEntitySetTypeInfo()
  {
    (void)AcquireWeakEntitySetTypeInfo();
  }
} // namespace moho

namespace
{
  struct EntitySetReflectionBootstrap
  {
    EntitySetReflectionBootstrap()
    {
      (void)moho::register_EntitySetBaseTypeInfo();
      (void)moho::register_EntitySetTypeInfo();
      (void)moho::register_WeakEntitySetTypeInfo();
    }
  };

  EntitySetReflectionBootstrap gEntitySetReflectionBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(
  register_EntitySetBaseTypeInfo_2618e1,
  moho::register_EntitySetBaseTypeInfo
)
GPG_PREREGISTER_INIT(
  register_EntitySetTypeInfo_2618e1,
  moho::register_EntitySetTypeInfo
)
GPG_PREREGISTER_INIT(
  register_WeakEntitySetTypeInfo_2618e1,
  moho::register_WeakEntitySetTypeInfo
)

namespace moho
{
  /**
   * Address: 0x006945D0 (FUN_006945D0)
   *
   * What it does:
   * Tracks one `EntitySetBase` pointer lane and deserializes the embedded
   * `fastvector<Entity*>` payload from archive storage.
   */
  void EntitySetBase::MemberDeserialize(
    gpg::ReadArchive* const archive
  )
  {
    if (!archive) {
      return;
    }

    const gpg::RRef selfRef = MakeEntitySetBaseRef(this);
    archive->TrackPointer(selfRef);

    const gpg::RRef owner{};
    archive->Read(ResolveFastVectorEntityPointerType(), &mVec, owner);
  }

  /**
   * Address: 0x00694640 (FUN_00694640)
   *
   * What it does:
   * Marks one pre-created `EntitySetBase` pointer lane and serializes the
   * embedded `fastvector<Entity*>` payload to archive storage.
   */
  void EntitySetBase::MemberSerialize(
    gpg::WriteArchive* const archive
  ) const
  {
    if (!archive) {
      return;
    }

    gpg::RRef selfRef = MakeEntitySetBaseRef(const_cast<moho::EntitySetBase*>(this));
    archive->PreCreatedPtr(selfRef);

    const gpg::RRef owner{};
    archive->Write(ResolveFastVectorEntityPointerType(), &mVec, owner);
  }

  template <class T>
  void EntitySetTemplate<T>::MemberDeserialize(
    gpg::ReadArchive* const archive
  )
  {
    archive->Read(gpg::RTypeOf<EntitySetBase>(), static_cast<EntitySetBase*>(this), gpg::RRef{});
  }

  template <class T>
  void EntitySetTemplate<T>::MemberSerialize(
    gpg::WriteArchive* const archive
  ) const
  {
    archive->Write(gpg::RTypeOf<EntitySetBase>(), static_cast<const EntitySetBase*>(this), gpg::RRef{});
  }

  template <class T>
  void WeakEntitySetTemplate<T>::MemberDeserialize(
    gpg::ReadArchive* const archive
  )
  {
    archive->Read(gpg::RTypeOf<EntitySetTemplate<T>>(), static_cast<EntitySetTemplate<T>*>(this), gpg::RRef{});
  }

  template <class T>
  void WeakEntitySetTemplate<T>::MemberSerialize(
    gpg::WriteArchive* const archive
  ) const
  {
    archive->Write(gpg::RTypeOf<EntitySetTemplate<T>>(), static_cast<const EntitySetTemplate<T>*>(this), gpg::RRef{});
  }

  template void EntitySetTemplate<Entity>::MemberDeserialize(gpg::ReadArchive*);
  template void EntitySetTemplate<Entity>::MemberSerialize(gpg::WriteArchive*) const;
  template void EntitySetTemplate<Unit>::MemberDeserialize(gpg::ReadArchive*);
  template void EntitySetTemplate<Unit>::MemberSerialize(gpg::WriteArchive*) const;
  template void WeakEntitySetTemplate<Entity>::MemberDeserialize(gpg::ReadArchive*);
  template void WeakEntitySetTemplate<Entity>::MemberSerialize(gpg::WriteArchive*) const;
  template void WeakEntitySetTemplate<Unit>::MemberDeserialize(gpg::ReadArchive*);
  template void WeakEntitySetTemplate<Unit>::MemberSerialize(gpg::WriteArchive*) const;
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<EntitySetBase>`, vtable 0x00E28E9C.
   *
   * Address: 0x00BD5790 (FUN_00BD5790 -- constructs the global and registers its destructor.)
   * Address: 0x00BFCD20 (FUN_00BFCD20 -- the global's destructor.)
   * Address: 0x006936D0 (FUN_006936D0 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00693DE0 (FUN_00693DE0 -- `Init`.)
   * Address: 0x006936B0 (FUN_006936B0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x006936C0 (FUN_006936C0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct EntitySetBaseSerializer : gpg::SerSaveLoadHelper<EntitySetBase>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B4F78 -- process-global `EntitySetBaseSerializer` singleton.
  moho::EntitySetBaseSerializer gEntitySetBaseSerializer;
} // namespace

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<EntitySetTemplate<Entity>>`, vtable 0x00E28EDC.
   *
   * Address: 0x00BD57F0 (FUN_00BD57F0 -- constructs the global and registers its destructor.)
   * Address: 0x00BFCDB0 (FUN_00BFCDB0 -- the global's destructor.)
   * Address: 0x00693920 (FUN_00693920 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00693E80 (FUN_00693E80 -- `Init`.)
   * Address: 0x006938A0 (FUN_006938A0 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x006938E0 (FUN_006938E0 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct EntitySetSerializer : gpg::SerSaveLoadHelper<EntitySetTemplate<Entity>>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B4EFC -- process-global `EntitySetSerializer` singleton.
  moho::EntitySetSerializer gEntitySetSerializer;
} // namespace

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<WeakEntitySetTemplate<Entity>>`, vtable 0x00E28F1C.
   *
   * Address: 0x00BD5850 (FUN_00BD5850 -- constructs the global and registers its destructor.)
   * Address: 0x00BFCE40 (FUN_00BFCE40 -- the global's destructor.)
   * Address: 0x00693B70 (FUN_00693B70 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00693F20 (FUN_00693F20 -- `Init`.)
   * Address: 0x00693AF0 (FUN_00693AF0 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x00693B30 (FUN_00693B30 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct WeakEntitySetSerializer : gpg::SerSaveLoadHelper<WeakEntitySetTemplate<Entity>>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B4E84 -- process-global `WeakEntitySetSerializer` singleton.
  moho::WeakEntitySetSerializer gWeakEntitySetSerializer;
} // namespace
