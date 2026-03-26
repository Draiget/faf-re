#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <type_traits>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace moho
{
  class CTaskThread;
  class CLuaConOutputHandler;
} // namespace moho

namespace gpg
{
  class RObject;
  class RRef;
  class RType;
  class RField;
  class REnumType;
  class RIndexed;
  struct SerHelperBase;

  /**
   * C-string comparator for map keys.
   */
  struct CStrLess
  {
    bool operator()(const char* a, const char* b) const noexcept
    {
      if (a == b)
        return false;
      if (!a)
        return true;
      if (!b)
        return false;
      return std::strcmp(a, b) < 0;
    }
  };

  /**
   * type_info comparator used by the preregistration map.
   * Mirrors the binary's use of type_info::before.
   */
  struct TypeInfoLess
  {
    bool operator()(const std::type_info* a, const std::type_info* b) const noexcept
    {
      if (a == b)
        return false;
      if (!a)
        return b != nullptr;
      if (!b)
        return false;
      return a->before(*b) != 0;
    }
  };

  using TypeMap = std::map<const char*, RType*, CStrLess>;
  using TypeVec = msvc8::vector<RType*>;
  using TypeInfoMap = std::map<const std::type_info*, RType*, TypeInfoLess>;

  class RObject
  {
  public:
    /**
     * Address: 0x00A82547
     * VFTable SLOT: 0
     */
    [[nodiscard]]
    virtual RType* GetClass() const = 0;

    /**
     * Address: 0x00A82547
     * VFTable SLOT: 1
     */
    virtual RRef GetDerivedObjectRef() = 0;

    /**
     * Address: 0x004012D0 (FUN_004012D0)
     * PDB name: sub_4012D0
     * VFTable SLOT: 2
     *
     * What it does:
     * Owns deleting-dtor lane for RObject base and conditionally frees `this`.
     */
    virtual ~RObject() noexcept;
  };
  static_assert(sizeof(RObject) == 0x04, "RObject must be 0x04");

  // template<class T>
  class RRef
  {
  public:
    void* mObj;
    RType* mType;

    // RRef(T*);
    // RRef(void* ptr, gpg::RType* type) : mObj{ ptr }, mType{ type } {}

    msvc8::string GetLexical() const;        // 0x004A35D0
    bool SetLexical(const char*) const;      // 0x004A3600
    const char* GetTypeName() const;         // gpgcore.dll
    RRef operator[](unsigned int ind) const; // 0x004A3610
    size_t GetCount() const;                 // 0x004A3630
    const RType* GetRType() const;           // 0x004A3650
    const RIndexed* IsIndexed() const;       // 0x004A3660
    const RIndexed* IsPointer() const;       // 0x004CC9E0
    int GetNumBases() const;                 // gpgcore.dll
    RRef GetBase(int ind) const;             // gpgcore.dll
    int GetNumFields() const;                // 0x004CC9B0
    RRef GetField(int ind) const;            // gpgcore.dll
    const char* GetFieldName(int ind) const; // gpgcore.dll
    void Delete();                           // 0x008D8800
  };
  static_assert(sizeof(RRef) == 0x08, "RRef must be 0x08");

  /**
   * Global registries (original: func_GetRTypeMap / func_GetRTypeVec).
   */
  inline TypeMap& GetRTypeMap()
  {
    static TypeMap gMap;
    return gMap;
  }

  inline TypeVec& GetRTypeVec()
  {
    static TypeVec gVec;
    return gVec;
  }

  inline TypeInfoMap& GetRTypePreregisteredMap()
  {
    static TypeInfoMap gMap;
    return gMap;
  }

  /**
   * Address: 0x008E0750 (FA), 0x1001CDC0 (gpgcore.dll)
   *
   * type_info const &
   *
   * What it does:
   * Resolves a preregistered type descriptor by RTTI and lazily finalizes
   * registration (`Init` + `RegisterType`) on first lookup.
   */
  RType* LookupRType(const std::type_info& typeInfo);

  /**
   * Address: 0x1001BBC0 (gpgcore.dll)
   *
   * type_info const &, gpg::RType *
   *
   * What it does:
   * Adds a type descriptor to the RTTI preregistration map.
   */
  void PreRegisterRType(const std::type_info& typeInfo, RType* type);

  /**
   * Address: 0x1001CEB0 (gpgcore.dll)
   *
   * What it does:
   * Forces lazy registration for all preregistered RTTI entries.
   */
  void REF_RegisterAllTypes();

  /**
   * Address: 0x10018CB0 (gpgcore.dll)
   *
   * int
   *
   * What it does:
   * Returns the type descriptor at an index in the global registration vector.
   */
  const RType* REF_GetTypeIndexed(int index);

  /**
   * Address: 0x008DF8A0
   *
   * char const *
   *
   * What it does:
   * Returns registered reflection descriptor by exact type-name lookup.
   */
  RType* REF_FindTypeNamed(const char* name);

  /**
   * Address: 0x008DBF60
   *
   * gpg::RRef const &, gpg::RType const *
   *
   * What it does:
   * Upcasts a reflected object reference to a requested base type when valid.
   */
  RRef REF_UpcastPtr(const RRef& source, const RType* targetType);

  class RField
  {
  public:
    const char* mName;
    RType* mType;
    int mOffset;
    int v4;
    const char* mDesc;

    RField();
    RField(const char* name, RType* type, int offset);
    RField(const char* name, RType* type, int offset, int v, const char* desc);
  };
  static_assert(sizeof(RField) == 0x14, "RField must be 0x14");

  class RType : public RObject
  {
    // Primary vftable (11 entries)
  public:
    using save_construct_args_func_t = void (*)(void*);
    using save_func_t = void (*)(WriteArchive*, int, int, RRef*);
    using construct_func_t = void (*)(void*);
    using load_func_t = void (*)(ReadArchive*, int, int, RRef*);
    using new_ref_func_t = RRef (*)();
    using cpy_ref_func_t = RRef (*)(RRef*);
    using delete_func_t = void (*)(void*);
    using ctor_ref_func_t = RRef (*)(void*);
    using mov_ref_func_t = RRef (*)(void*, RRef*);
    using dtr_func_t = void (*)(void*);

    /**
     * In binary: returns the family descriptor (descriptor for gpg::RType).
     *
     * Address: 0x00401370 (FUN_00401370)
     * SLOT: 0
     */
    [[nodiscard]]
    virtual RType* GetClass() const;

    /**
     * Packs { this, GetFamilyDescriptor() } into the provided handle.
     *
     * Address: 0x00401390 (FUN_00401390)
     * SLOT: 1
     */
    [[nodiscard]]
    virtual RRef GetDerivedObjectRef();

    /**
     * Destructor.
     *
     * Address: 0x008DD9D0
     * SLOT: 2
     */
    virtual ~RType();

    /**
     * Abstract: provide a label/name string for a given instance pointer.
     * In base RType default ToString uses this label with "%s at 0x%p".
     *
     * Address: 0x00A82547
     * SLOT: 3
     */
    virtual const char* GetName() const = 0;

    /**
     * Default stringification: "<label> at 0x<ptr>".
     * Returns number of bytes appended.
     *
     * Address: 0x008DB100 (FUN_008DB100)
     * SLOT: 4
     */
    virtual msvc8::string GetLexical(const RRef&) const;

    /**
     * Unknown (base: no-op/false).
     *
     * Address: 0x008D86E0 (FUN_008D86E0)
     * SLOT: 5
     */
    virtual bool SetLexical(const RRef&, const char*) const;

    /**
     * Unknown (observed as zero in base).
     *
     * Address: 0x004013B0 (FUN_004013B0)
     * SLOT: 6
     */
    [[nodiscard]]
    virtual const RIndexed* IsIndexed() const;

    /**
     * Unknown (observed as zero in base).
     *
     * Address: 0x004013C0 (FUN_004013C0)
     * SLOT: 7
     */
    [[nodiscard]]
    virtual const RIndexed* IsPointer() const;

    /**
     * Unknown (observed as zero in base).
     *
     * Address: 0x004013D0 (FUN_004013D0)
     * SLOT: 8
     */
    [[nodiscard]]
    virtual const REnumType* IsEnumType() const;

    /**
     * One-shot registration hook (called by lazy-init).
     *
     * Address: 0x008D8680
     * SLOT: 9
     */
    virtual void Init();

    /**
     * Finalization: builds indices over 20-byte member records.
     *
     * Address: 0x008DF4A0
     * SLOT: 10
     */
    virtual void Finish();

    /**
     * Address: 0x008D8640
     */
    void Version(int version);

    /**
     * Add a base-class reference and flatten its fields into this type.
     * - Fails if initialization is already finished (matches original assert).
     * - Appends `base` into `bases_`.
     * - For each field of `base.mType`, appends a copy into `fields_` with
     *   offset adjusted by `base.mOffset`.
     *
     * Address: 0x008DF500
     */
    void AddBase(const RField& field);

    /**
     * Register this type in global registries.
     *
     * Address: 0x008DF960
     */
    void RegisterType();

    /**
     * Binary-search a field by its name.
     * Preconditions:
     *  - `initFinished_` must be true (indices built, `fields_` sorted by name).
     *  - `fields_` is sorted ascending by `RField::mName` (strcmp order).
     * Returns:
     *  - Pointer to matching RField if found;
     *  - nullptr if not found or container is empty.
     *
     * Address: 0x008D94E0
     */
    const RField* GetFieldNamed(const char* name) const;

    /**
     * Check if `this` is (transitively) derived from `baseType`.
     * If `outOffset` is provided and relation holds, accumulates byte offset
     * from `this` object start to the subobject of type `baseType`.
     * Throws std::runtime_error("Ambiguous base class") if there are >=2 distinct base paths.
     *
     * Address: 0x008DBFF0
     */
    bool IsDerivedFrom(const RType* baseType, int32_t* outOffset) const;

  public:
    bool finished_;
    bool initFinished_;
    int size_;
    int version_;
    save_construct_args_func_t serSaveConstructArgsFunc_;
    save_func_t serSaveFunc_;
    construct_func_t serConstructFunc_;
    load_func_t serLoadFunc_;
    int v8;
    int v9;
    msvc8::vector<RField> bases_;
    msvc8::vector<RField> fields_;
    new_ref_func_t newRefFunc_;
    cpy_ref_func_t cpyRefFunc_;
    delete_func_t deleteFunc_;
    ctor_ref_func_t ctorRefFunc_;
    mov_ref_func_t movRefFunc_;
    dtr_func_t dtrFunc_;
    bool v24;

  public:
    template <class T, class B>
    static int BaseSubobjectOffset()
    {
      static_assert(std::is_base_of<B, T>::value, "B must be a base of T");

      const auto* t = reinterpret_cast<const T*>(0x1000);
      const auto* b = static_cast<const B*>(t);
      return static_cast<int>(reinterpret_cast<std::uintptr_t>(b) - reinterpret_cast<std::uintptr_t>(t));
    }

    template <class T>
    RField* AddField(const char* name, int offset)
    {
      GPG_ASSERT(!initFinished_); // if (this->mInitFinished) { gpg::HandleAssertFailure("!mInitFinished", 734,
                                  // "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/reflection.h"); }
      RField f{name, const_cast<RType*>(T::StaticGetClass()), offset};
      this->fields_.push_back(f);
      return &this->fields_.back();
    }

    template <class T, class B>
    void AddBase()
    {
      RType* type = const_cast<RType*>(B::StaticGetClass());
      this->AddBase(RField{type->GetName(), type, BaseSubobjectOffset<T, B>()});
    }
  };
  static_assert(sizeof(RType) == 0x64, "RType must be 0x64 bytes on x86");

  /**
   * VFTABLE: 0x00D44B4C
   * COL:  0x00E5156C
   */
  class Rect2iTypeInfo final : public RType
  {
  public:
    /**
     * Address: 0x00906020 (FUN_00906020)
     * Demangled: gpg::Rect2iTypeInfo::GetName
     *
     * What it does:
     * Returns the reflection type label string for Rect2<int>.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00906270 (FUN_00906270)
     * Demangled: gpg::Rect2iTypeInfo::Init
     *
     * What it does:
     * Registers Rect2<int> field metadata (x0/y0/x1/y1) and finalizes the descriptor.
     */
    void Init() override;
  };
  static_assert(sizeof(Rect2iTypeInfo) == 0x64, "Rect2iTypeInfo size must be 0x64");

  /**
   * VFTABLE: 0x00D44B84
   * COL:  0x00E515BC
   */
  class Rect2fTypeInfo final : public RType
  {
  public:
    /**
     * Address: 0x009060D0 (FUN_009060D0)
     * Demangled: gpg::Rect2fTypeInfo::GetName
     *
     * What it does:
     * Returns the reflection type label string for Rect2<float>.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x009062D0 (FUN_009062D0)
     * Demangled: gpg::Rect2fTypeInfo::Init
     *
     * What it does:
     * Registers Rect2<float> field metadata (x0/y0/x1/y1) and finalizes the descriptor.
     */
    void Init() override;
  };
  static_assert(sizeof(Rect2fTypeInfo) == 0x64, "Rect2fTypeInfo size must be 0x64");

  /**
   * VFTABLE: 0x00D44B44
   * COL:  0x00E51514
   */
  class Rect2iSerializer
  {
  public:
    /**
     * Address: 0x00905E40 (FUN_00905E40)
     * Demangled: gpg::SerSaveLoadHelper<class gpg::Rect2<int>>::Init
     *
     * What it does:
     * Binds Rect2<int> load/save callbacks onto the reflected type descriptor.
     */
    virtual void RegisterSerializeFunctions();

  public:
    SerHelperBase* mHelperNext;
    SerHelperBase* mHelperPrev;
    RType::load_func_t mLoadCallback;
    RType::save_func_t mSaveCallback;
  };
  static_assert(offsetof(Rect2iSerializer, mHelperNext) == 0x04, "Rect2iSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(Rect2iSerializer, mHelperPrev) == 0x08, "Rect2iSerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(Rect2iSerializer, mLoadCallback) == 0x0C, "Rect2iSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(Rect2iSerializer, mSaveCallback) == 0x10, "Rect2iSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(Rect2iSerializer) == 0x14, "Rect2iSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00D44B3C
   * COL:  0x00E514BC
   */
  class Rect2fSerializer
  {
  public:
    /**
     * Address: 0x00905EE0 (FUN_00905EE0)
     * Demangled: gpg::SerSaveLoadHelper<class gpg::Rect2<float>>::Init
     *
     * What it does:
     * Binds Rect2<float> load/save callbacks onto the reflected type descriptor.
     */
    virtual void RegisterSerializeFunctions();

  public:
    SerHelperBase* mHelperNext;
    SerHelperBase* mHelperPrev;
    RType::load_func_t mLoadCallback;
    RType::save_func_t mSaveCallback;
  };
  static_assert(offsetof(Rect2fSerializer, mHelperNext) == 0x04, "Rect2fSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(Rect2fSerializer, mHelperPrev) == 0x08, "Rect2fSerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(Rect2fSerializer, mLoadCallback) == 0x0C, "Rect2fSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(Rect2fSerializer, mSaveCallback) == 0x10, "Rect2fSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(Rect2fSerializer) == 0x14, "Rect2fSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00D48CA0
   * COL:  0x00E5DC40
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  class REnumType : public RType
  {
  public:
    struct ROptionValue
    {
      int mValue;
      const char* mName;
    };

    /**
     * In binary:
     *
     * Address: 0x00418120
     * VFTable SLOT: 2
     */
    ~REnumType() override = default;

    /**
     * In binary:
     *
     * Address: 0x008E1C40
     * VFTable SLOT: 4
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * In binary:
     *
     * Address: 0x008D9670
     * VFTable SLOT: 5
     */
    bool SetLexical(const RRef&, const char*) const override;

    /**
     * In binary:
     *
     * Address: 0x004180F0
     * VFTable SLOT: 8
     */
    const REnumType* IsEnumType() const override
    {
      return this;
    }

    const msvc8::vector<ROptionValue>& GetEnumOptions() const
    {
      return mEnumNames;
    }

    /**
     * In binary:
     *
     * Address: 0x008D86F0
     */
    const char* StripPrefix(const char*) const;

    bool GetEnumValue(const char*, int*) const;

    /**
     * In binary:
     *
     * Address: 0x008DF5F0
     */
    void AddEnum(char const* name, int index);

  public:
    const char* mPrefix;
    msvc8::vector<ROptionValue> mEnumNames;
  };
  static_assert(sizeof(REnumType) == 0x78, "REnumType must be 0x78 bytes on x86");

  class RIndexed
  {
  public:
    virtual RRef SubscriptIndex(void* obj, int ind) const = 0;

    virtual size_t GetCount(void* obj) const = 0;

    /**
     * Address: 0x004012F0 (FUN_004012F0)
     *
     * What it does:
     * Base implementation rejects resize/count mutation for non-resizable indexed types.
     */
    virtual void SetCount(void* obj, int count) const;

    /**
     * Address: 0x00401320 (FUN_00401320)
     *
     * What it does:
     * Base implementation rejects pointer assignment for non-pointer indexed types.
     */
    virtual void AssignPointer(void* obj, const RRef& from) const;
  };

  template <class T>
  class RPointerType;

  /**
   * Common base for pointer-reflection wrappers (`T*`).
   *
   * What it does:
   * Owns shared pointer-slot indexed semantics so per-type specializations only
   * recover the type-specific virtual surface from FA.
   */
  class RPointerTypeBase : public RType, public RIndexed
  {
  public:
    RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
    void AssignPointer(void* obj, const RRef& from) const override;

    /**
     * Shared indexed-self helper used by specialization thunks.
     */
    [[nodiscard]]
    const RIndexed* AsIndexedSelf() const noexcept;

  protected:
    [[nodiscard]]
    virtual RType* GetPointeeType() const = 0;
  };
  static_assert(sizeof(RPointerTypeBase) == 0x68, "RPointerTypeBase size must be 0x68");

  /**
   * VFTABLE: 0x00E0043C
   * COL:  0x00E5CC74
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::CTaskThread> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x0040CBD0 (FUN_0040CBD0)
     * Demangled: sub_40CBD0
     */
    ~RPointerType() override;

    /**
     * Address: 0x0040C7C0 (FUN_0040C7C0)
     * Demangled: gpg::RPointerType_CTaskThread::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x0040C950 (FUN_0040C950)
     * Demangled: gpg::RPointerType_CTaskThread::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x0040CAD0 (FUN_0040CAD0)
     * Demangled: gpg::RPointerType_CTaskThread::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0040CAE0 (FUN_0040CAE0)
     * Demangled: gpg::RPointerType_CTaskThread::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x0040C920 (FUN_0040C920)
     * Demangled: gpg::RPointerType_CTaskThread::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(sizeof(RPointerType<moho::CTaskThread>) == 0x68, "RPointerType<CTaskThread> size must be 0x68");

  /**
   * VFTABLE: 0x00E017C0
   * COL:  0x00E5DD44
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  template <>
  class RPointerType<moho::CLuaConOutputHandler> final : public RPointerTypeBase
  {
  public:
    /**
     * Address: 0x004215C0 (FUN_004215C0)
     * Demangled: gpg::RPointerType_CLuaConOutputHandler::dtr
     */
    ~RPointerType() override;

    /**
     * Address: 0x004211B0 (FUN_004211B0)
     * Demangled: gpg::RPointerType_CLuaConOutputHandler::GetName
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00421340 (FUN_00421340)
     * Demangled: gpg::RPointerType_CLuaConOutputHandler::GetLexical
     */
    [[nodiscard]]
    msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x004214C0 (FUN_004214C0)
     * Demangled: gpg::RPointerType_CLuaConOutputHandler::IsIndexed
     */
    [[nodiscard]]
    const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x004214D0 (FUN_004214D0)
     * Demangled: gpg::RPointerType_CLuaConOutputHandler::IsPointer
     */
    [[nodiscard]]
    const RIndexed* IsPointer() const override;

    /**
     * Address: 0x00421310 (FUN_00421310)
     * Demangled: gpg::RPointerType_CLuaConOutputHandler::Init
     */
    void Init() override;

  protected:
    [[nodiscard]]
    RType* GetPointeeType() const override;
  };
  static_assert(
    sizeof(RPointerType<moho::CLuaConOutputHandler>) == 0x68, "RPointerType<CLuaConOutputHandler> size must be 0x68"
  );
} // namespace gpg
