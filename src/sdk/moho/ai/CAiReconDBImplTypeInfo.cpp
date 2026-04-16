#include "moho/ai/CAiReconDBImplTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/IAiReconDB.h"
#include "moho/ai/IAiReconDBTypeInfo.h"
#include "moho/sim/ReconBlip.h"

using namespace moho;

namespace
{
  constexpr std::uint8_t kNodeColorRed = 0u;
  constexpr std::uint8_t kNodeColorBlack = 1u;
  constexpr std::uint32_t kReconMapMaxSize = 0x0FFFFFFEu;

  struct ReconMapNodeRuntime
  {
    ReconMapNodeRuntime* left;   // +0x00
    ReconMapNodeRuntime* parent; // +0x04
    ReconMapNodeRuntime* right;  // +0x08
    SReconKey key;               // +0x0C
    ReconBlip* value;            // +0x18
    std::uint8_t color;          // +0x1C
    std::uint8_t isNil;          // +0x1D
    std::uint8_t pad_1E_1F[0x02];
  };
  static_assert(sizeof(ReconMapNodeRuntime) == 0x20, "ReconMapNodeRuntime size must be 0x20");
  static_assert(offsetof(ReconMapNodeRuntime, key) == 0x0C, "ReconMapNodeRuntime::key offset must be 0x0C");
  static_assert(offsetof(ReconMapNodeRuntime, value) == 0x18, "ReconMapNodeRuntime::value offset must be 0x18");

  /**
   * Address: 0x005C58E0 (FUN_005C58E0)
   */
  void DeserializeReconBlipPointerVector(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef);

  /**
   * Address: 0x005C59F0 (FUN_005C59F0)
   */
  void SerializeReconBlipPointerVector(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef);

  /**
   * Address: 0x005C6210 (FUN_005C6210)
   */
  void DeserializeReconBlipMapStorage(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef* ownerRef);

  /**
   * Address: 0x005C6390 (FUN_005C6390)
   */
  void SerializeReconBlipMapStorage(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef* ownerRef);

  class ReconBlipPointerVectorTypeRuntime final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x005C40D0 (FUN_005C40D0, gpg::RVectorType_ReconBlipP::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005C4170 (FUN_005C4170, gpg::RVectorType_ReconBlipP::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x005C4200 (FUN_005C4200, gpg::RVectorType_ReconBlipP::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x005C4150 (FUN_005C4150, gpg::RVectorType_ReconBlipP::Init)
     */
    void Init() override;

    /**
     * Address: 0x005C4240 (FUN_005C4240, gpg::RVectorType_ReconBlipP::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x005C4210 (FUN_005C4210, gpg::RVectorType_ReconBlipP::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x005C4230 (FUN_005C4230, gpg::RVectorType_ReconBlipP::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };
  static_assert(
    sizeof(ReconBlipPointerVectorTypeRuntime) == 0x68, "ReconBlipPointerVectorTypeRuntime size must be 0x68"
  );

  class ReconBlipMapTypeRuntime final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005C4D50 (FUN_005C4D50, gpg::RMultiMapType_SReconKey_ReconBlipP::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005C4E20 (FUN_005C4E20, gpg::RMultiMapType_SReconKey_ReconBlipP::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x005C4E00 (FUN_005C4E00, gpg::RMultiMapType_SReconKey_ReconBlipP::Init)
     */
    void Init() override;
  };
  static_assert(sizeof(ReconBlipMapTypeRuntime) == 0x64, "ReconBlipMapTypeRuntime size must be 0x64");

  alignas(CAiReconDBImplTypeInfo) unsigned char gCAiReconDBImplTypeInfoStorage[sizeof(CAiReconDBImplTypeInfo)];
  bool gCAiReconDBImplTypeInfoConstructed = false;
  alignas(ReconBlipPointerVectorTypeRuntime)
  unsigned char gReconBlipPtrVectorTypeStorage[sizeof(ReconBlipPointerVectorTypeRuntime)];
  bool gReconBlipPtrVectorTypeConstructed = false;
  alignas(ReconBlipMapTypeRuntime) unsigned char gReconBlipMapTypeStorage[sizeof(ReconBlipMapTypeRuntime)];
  bool gReconBlipMapTypeConstructed = false;

  msvc8::string gReconBlipPtrVectorTypeName;
  bool gReconBlipPtrVectorTypeNameInit = false;
  msvc8::string gReconBlipMapTypeName;
  bool gReconBlipMapTypeNameInit = false;

  gpg::RType* gReconBlipType = nullptr;
  gpg::RType* gReconBlipPtrType = nullptr;
  gpg::RType* gSReconKeyType = nullptr;

  [[nodiscard]] CAiReconDBImplTypeInfo* AcquireCAiReconDBImplTypeInfo()
  {
    if (!gCAiReconDBImplTypeInfoConstructed) {
      new (gCAiReconDBImplTypeInfoStorage) CAiReconDBImplTypeInfo();
      gCAiReconDBImplTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiReconDBImplTypeInfo*>(gCAiReconDBImplTypeInfoStorage);
  }

  [[nodiscard]] ReconBlipPointerVectorTypeRuntime* AcquireReconBlipPtrVectorType()
  {
    if (!gReconBlipPtrVectorTypeConstructed) {
      new (gReconBlipPtrVectorTypeStorage) ReconBlipPointerVectorTypeRuntime();
      gReconBlipPtrVectorTypeConstructed = true;
    }
    return reinterpret_cast<ReconBlipPointerVectorTypeRuntime*>(gReconBlipPtrVectorTypeStorage);
  }

  [[nodiscard]] ReconBlipMapTypeRuntime* AcquireReconBlipMapType()
  {
    if (!gReconBlipMapTypeConstructed) {
      new (gReconBlipMapTypeStorage) ReconBlipMapTypeRuntime();
      gReconBlipMapTypeConstructed = true;
    }
    return reinterpret_cast<ReconBlipMapTypeRuntime*>(gReconBlipMapTypeStorage);
  }

  void cleanup_ReconBlipPtrVectorTypeName()
  {
    gReconBlipPtrVectorTypeName.clear();
    gReconBlipPtrVectorTypeNameInit = false;
  }

  void cleanup_ReconBlipMapTypeName()
  {
    gReconBlipMapTypeName.clear();
    gReconBlipMapTypeNameInit = false;
  }

  [[nodiscard]] gpg::RType* CachedCAiReconDBImplType()
  {
    if (!CAiReconDBImpl::sType) {
      CAiReconDBImpl::sType = gpg::LookupRType(typeid(CAiReconDBImpl));
    }
    return CAiReconDBImpl::sType;
  }

  [[nodiscard]] gpg::RType* CachedIAiReconDBType()
  {
    if (!IAiReconDB::sType) {
      IAiReconDB::sType = gpg::LookupRType(typeid(IAiReconDB));
    }
    return IAiReconDB::sType;
  }

  [[nodiscard]] gpg::RType* CachedReconBlipType()
  {
    if (!gReconBlipType) {
      gReconBlipType = ReconBlip::sType ? ReconBlip::sType : gpg::LookupRType(typeid(ReconBlip));
      ReconBlip::sType = gReconBlipType;
    }
    return gReconBlipType;
  }

  [[nodiscard]] gpg::RType* CachedReconBlipPointerType()
  {
    if (!gReconBlipPtrType) {
      gReconBlipPtrType = gpg::LookupRType(typeid(ReconBlip*));
    }
    return gReconBlipPtrType;
  }

  [[nodiscard]] gpg::RType* CachedSReconKeyType()
  {
    if (!gSReconKeyType) {
      gSReconKeyType = SReconKey::sType ? SReconKey::sType : gpg::LookupRType(typeid(SReconKey));
      SReconKey::sType = gSReconKeyType;
    }
    return gSReconKeyType;
  }

  template <typename T>
  [[nodiscard]] gpg::RRef MakeTypedRef(T* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(staticType, &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  [[nodiscard]] gpg::RRef MakeReconBlipObjectRef(ReconBlip* object)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedReconBlipType();
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = out.mType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = out.mType;
    }

    std::int32_t baseOffset = 0;
    const bool derived =
      dynamicType != nullptr && out.mType != nullptr && dynamicType->IsDerivedFrom(out.mType, &baseOffset);
    out.mObj = derived
      ? reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset))
      : static_cast<void*>(object);
    out.mType = dynamicType ? dynamicType : out.mType;
    return out;
  }

  [[nodiscard]] gpg::RRef MakeReconBlipPointerSlotRef(ReconBlip** slot)
  {
    if (gpg::RType* const pointerType = CachedReconBlipPointerType(); pointerType != nullptr) {
      gpg::RRef out{};
      out.mObj = slot;
      out.mType = pointerType;
      return out;
    }

    return MakeReconBlipObjectRef(slot ? *slot : nullptr);
  }

  [[nodiscard]] ReconBlip* DecodeTrackedReconBlipPointer(const gpg::TrackedPointerInfo& tracked)
  {
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RType* const expected = CachedReconBlipType();
    if (!expected) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expected);
    return static_cast<ReconBlip*>(upcast.mObj);
  }

  [[nodiscard]] bool IsNil(const ReconMapNodeRuntime* node) noexcept
  {
    return !node || node->isNil != 0u;
  }

  [[nodiscard]] ReconMapNodeRuntime* MapHead(SReconBlipMapStorage* storage) noexcept
  {
    return storage ? reinterpret_cast<ReconMapNodeRuntime*>(storage->mHead) : nullptr;
  }

  [[nodiscard]] ReconMapNodeRuntime* MapHead(const SReconBlipMapStorage* storage) noexcept
  {
    return storage ? reinterpret_cast<ReconMapNodeRuntime*>(storage->mHead) : nullptr;
  }

  [[nodiscard]] ReconMapNodeRuntime* AllocateMapHeadNode()
  {
    auto* const head = new ReconMapNodeRuntime{};
    head->left = head;
    head->parent = head;
    head->right = head;
    head->value = nullptr;
    head->color = kNodeColorBlack;
    head->isNil = 1u;
    return head;
  }

  [[nodiscard]] ReconMapNodeRuntime* EnsureMapHead(SReconBlipMapStorage* storage)
  {
    if (!storage) {
      return nullptr;
    }

    auto* head = MapHead(storage);
    if (!head) {
      head = AllocateMapHeadNode();
      storage->mHead = head;
    }
    return head;
  }

  [[nodiscard]] ReconMapNodeRuntime* MapBegin(const SReconBlipMapStorage* storage) noexcept
  {
    auto* const head = MapHead(storage);
    if (!head || IsNil(head->parent)) {
      return head;
    }
    return head->left;
  }

  [[nodiscard]] ReconMapNodeRuntime* MapNext(ReconMapNodeRuntime* node, ReconMapNodeRuntime* head) noexcept
  {
    if (!node || IsNil(node)) {
      return head;
    }

    ReconMapNodeRuntime* right = node->right;
    if (IsNil(right)) {
      ReconMapNodeRuntime* parent = node->parent;
      while (!IsNil(parent) && node == parent->right) {
        node = parent;
        parent = parent->parent;
      }
      return parent;
    }

    node = right;
    while (!IsNil(node->left)) {
      node = node->left;
    }
    return node;
  }

  void ClearMapStorage(SReconBlipMapStorage* storage)
  {
    auto* const head = EnsureMapHead(storage);
    if (!head) {
      return;
    }

    for (ReconMapNodeRuntime* node = MapBegin(storage); node != head;) {
      ReconMapNodeRuntime* const current = node;
      node = MapNext(current, head);
      current->key.sourceUnit.UnlinkFromOwnerChain();
      delete current;
    }

    storage->mSize = 0u;
    head->parent = head;
    head->left = head;
    head->right = head;
    head->color = kNodeColorBlack;
    head->isNil = 1u;
  }

  void RotateLeft(SReconBlipMapStorage* storage, ReconMapNodeRuntime* node) noexcept
  {
    auto* const head = MapHead(storage);
    if (!head || !node) {
      return;
    }

    ReconMapNodeRuntime* const right = node->right;
    node->right = right->left;
    if (!IsNil(right->left)) {
      right->left->parent = node;
    }

    right->parent = node->parent;
    if (node == head->parent) {
      head->parent = right;
    } else if (node == node->parent->left) {
      node->parent->left = right;
    } else {
      node->parent->right = right;
    }

    right->left = node;
    node->parent = right;
  }

  void RotateRight(SReconBlipMapStorage* storage, ReconMapNodeRuntime* node) noexcept
  {
    auto* const head = MapHead(storage);
    if (!head || !node) {
      return;
    }

    ReconMapNodeRuntime* const left = node->left;
    node->left = left->right;
    if (!IsNil(left->right)) {
      left->right->parent = node;
    }

    left->parent = node->parent;
    if (node == head->parent) {
      head->parent = left;
    } else if (node == node->parent->right) {
      node->parent->right = left;
    } else {
      node->parent->left = left;
    }

    left->right = node;
    node->parent = left;
  }

  [[nodiscard]] ReconMapNodeRuntime*
  AllocateMapNode(ReconMapNodeRuntime* head, ReconMapNodeRuntime* parent, const SReconKey& key, ReconBlip* value)
  {
    auto* const node = new ReconMapNodeRuntime{};
    node->left = head;
    node->parent = parent;
    node->right = head;
    node->key = key;
    node->value = value;
    node->color = kNodeColorRed;
    node->isNil = 0u;
    node->key.sourceUnit.LinkIntoOwnerChainHeadUnlinked();
    return node;
  }

  [[nodiscard]] ReconMapNodeRuntime* InsertNodeWithFixup(
    SReconBlipMapStorage* storage, ReconMapNodeRuntime* parent, bool insertLeft, const SReconKey& key, ReconBlip* value
  )
  {
    auto* const head = EnsureMapHead(storage);
    if (!head) {
      return nullptr;
    }

    GPG_ASSERT(storage->mSize < kReconMapMaxSize);
    if (storage->mSize >= kReconMapMaxSize) {
      return nullptr;
    }

    ReconMapNodeRuntime* const inserted = AllocateMapNode(head, parent, key, value);
    ++storage->mSize;

    if (parent == head) {
      head->parent = inserted;
      head->left = inserted;
      head->right = inserted;
    } else if (insertLeft) {
      parent->left = inserted;
      if (parent == head->left) {
        head->left = inserted;
      }
    } else {
      parent->right = inserted;
      if (parent == head->right) {
        head->right = inserted;
      }
    }

    ReconMapNodeRuntime* node = inserted;
    while (node->parent->color == kNodeColorRed) {
      ReconMapNodeRuntime* const parentNode = node->parent;
      ReconMapNodeRuntime* const grandParent = parentNode->parent;
      if (parentNode == grandParent->left) {
        ReconMapNodeRuntime* const uncle = grandParent->right;
        if (uncle->color == kNodeColorBlack) {
          if (node == parentNode->right) {
            node = parentNode;
            RotateLeft(storage, parentNode);
          }
          node->parent->color = kNodeColorBlack;
          node->parent->parent->color = kNodeColorRed;
          RotateRight(storage, node->parent->parent);
        } else {
          parentNode->color = kNodeColorBlack;
          uncle->color = kNodeColorBlack;
          grandParent->color = kNodeColorRed;
          node = grandParent;
          continue;
        }
      } else {
        ReconMapNodeRuntime* const uncle = grandParent->left;
        if (uncle->color == kNodeColorBlack) {
          if (node == parentNode->left) {
            node = parentNode;
            RotateRight(storage, parentNode);
          }
          node->parent->color = kNodeColorBlack;
          node->parent->parent->color = kNodeColorRed;
          RotateLeft(storage, node->parent->parent);
        } else {
          parentNode->color = kNodeColorBlack;
          uncle->color = kNodeColorBlack;
          grandParent->color = kNodeColorRed;
          node = grandParent;
          continue;
        }
      }
      break;
    }

    head->parent->color = kNodeColorBlack;
    head->isNil = 1u;
    return inserted;
  }

  [[nodiscard]] ReconMapNodeRuntime* InsertMapNodeBySourceEntityId(SReconBlipMapStorage* storage, const SReconKey& key, ReconBlip* value)
  {
    auto* const head = EnsureMapHead(storage);
    if (!head) {
      return nullptr;
    }

    ReconMapNodeRuntime* parent = head;
    ReconMapNodeRuntime* cursor = head->parent;
    bool insertLeft = true;
    while (!IsNil(cursor)) {
      parent = cursor;
      insertLeft = key.sourceEntityId < cursor->key.sourceEntityId;
      cursor = insertLeft ? cursor->left : cursor->right;
    }

    return InsertNodeWithFixup(storage, parent, insertLeft, key, value);
  }

  class DeleteWithFlagSlot0Runtime
  {
  public:
    virtual void* DeleteWithFlag(int deleteFlag) = 0;

  protected:
    ~DeleteWithFlagSlot0Runtime() = default;
  };

  /**
   * Address: 0x005C7EE0 (FUN_005C7EE0)
   *
   * What it does:
   * Invokes slot-0 delete-with-flag semantics with flag `1` when the runtime
   * object pointer is non-null.
   */
  void DeleteSlot0RuntimeWithFlagOne(void* const object)
  {
    auto* const runtime = static_cast<DeleteWithFlagSlot0Runtime*>(object);
    if (!runtime) {
      return;
    }

    (void)runtime->DeleteWithFlag(1);
  }

  /**
   * Address: 0x005C7F70 (FUN_005C7F70)
   *
   * What it does:
   * Invokes slot-0 delete-with-flag semantics with flag `0` (non-deleting
   * destructor path).
   */
  void DestroySlot0RuntimeWithFlagZero(void* const object)
  {
    (void)static_cast<DeleteWithFlagSlot0Runtime*>(object)->DeleteWithFlag(0);
  }

  /**
   * Address: 0x005C7E60 (FUN_005C7E60, Moho::CAiReconDBImpl::operator new)
   *
   * What it does:
   * Allocates one `CAiReconDBImpl`, runs constructor defaults, and returns the
   * typed reflection reference payload used by `CAiReconDBImplTypeInfo::Init`.
   */
  [[nodiscard]] gpg::RRef CreateAiReconDbRefOwned()
  {
    return MakeTypedRef(new CAiReconDBImpl(nullptr, false), CachedCAiReconDBImplType());
  }

  [[maybe_unused]] void DeleteAiReconDbOwned(void* object)
  {
    delete static_cast<CAiReconDBImpl*>(object);
  }

  /**
   * Address: 0x005C7F00 (FUN_005C7F00)
   *
   * What it does:
   * Runs one in-place `CAiReconDBImpl` default construction lane and wraps the
   * resulting storage pointer as one reflected `RRef_CAiReconDBImpl` payload.
   */
  [[nodiscard]] gpg::RRef ConstructAiReconDbRefInPlace(void* objectStorage)
  {
    auto* const recon = static_cast<CAiReconDBImpl*>(objectStorage);
    CAiReconDBImpl* constructed = nullptr;
    if (recon != nullptr) {
      constructed = new (recon) CAiReconDBImpl();
    }

    gpg::RRef out{};
    gpg::RRef_CAiReconDBImpl(&out, constructed);
    return out;
  }

  [[maybe_unused]] void DestroyAiReconDbInPlace(void* object)
  {
    auto* const recon = static_cast<CAiReconDBImpl*>(object);
    if (recon) {
      recon->~CAiReconDBImpl();
    }
  }

  /**
   * Address: 0x005C9860 (FUN_005C9860, sub_5C9860)
   *
   * What it does:
   * Lazily resolves `IAiReconDB::sType`, builds a zero-offset `gpg::RField`,
   * and registers `IAiReconDB` as a base of `typeInfo`.
   */
  void AddIAiReconDBBase(gpg::RType* typeInfo)
  {
    gpg::RType* const baseType = CachedIAiReconDBType();
    gpg::RField field{};
    field.mName = baseType->GetName();
    field.mType = baseType;
    field.mOffset = 0;
    field.v4 = 0;
    field.mDesc = nullptr;
    typeInfo->AddBase(field);
  }

  /**
   * Address: 0x00BF7A50 (FUN_00BF7A50, cleanup_CAiReconDBImplTypeInfo)
   *
   * What it does:
   * Tears down recovered static `CAiReconDBImplTypeInfo` storage.
   */
  void cleanup_CAiReconDBImplTypeInfo()
  {
    if (!gCAiReconDBImplTypeInfoConstructed) {
      return;
    }

    AcquireCAiReconDBImplTypeInfo()->~CAiReconDBImplTypeInfo();
    gCAiReconDBImplTypeInfoConstructed = false;
  }

  /**
    * Alias of FUN_00BF7CC0 (non-canonical helper lane).
   *
   * What it does:
   * Tears down startup-owned `vector<ReconBlip*>` reflection storage.
   */
  void cleanup_RVectorType_ReconBlipPtr_Impl()
  {
    if (!gReconBlipPtrVectorTypeConstructed) {
      return;
    }

    AcquireReconBlipPtrVectorType()->~ReconBlipPointerVectorTypeRuntime();
    gReconBlipPtrVectorTypeConstructed = false;
  }

  /**
    * Alias of FUN_00BF7C60 (non-canonical helper lane).
   *
   * What it does:
   * Tears down startup-owned recon-blip map reflection storage.
   */
  void cleanup_RMultiMapType_SReconKey_ReconBlipPtr_Impl()
  {
    if (!gReconBlipMapTypeConstructed) {
      return;
    }

    AcquireReconBlipMapType()->~ReconBlipMapTypeRuntime();
    gReconBlipMapTypeConstructed = false;
  }

  const char* ReconBlipPointerVectorTypeRuntime::GetName() const
  {
    if (!gReconBlipPtrVectorTypeNameInit) {
      const gpg::RType* const pointerType = CachedReconBlipPointerType();
      const char* const pointerTypeName = pointerType ? pointerType->GetName() : "ReconBlip *";
      gReconBlipPtrVectorTypeName = gpg::STR_Printf("vector<%s>", pointerTypeName);
      gReconBlipPtrVectorTypeNameInit = true;
      (void)std::atexit(&cleanup_ReconBlipPtrVectorTypeName);
    }

    return gReconBlipPtrVectorTypeName.c_str();
  }

  msvc8::string ReconBlipPointerVectorTypeRuntime::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  const gpg::RIndexed* ReconBlipPointerVectorTypeRuntime::IsIndexed() const
  {
    return this;
  }

  void ReconBlipPointerVectorTypeRuntime::Init()
  {
    size_ = sizeof(msvc8::vector<ReconBlip*>);
    version_ = 1;
    serLoadFunc_ = &DeserializeReconBlipPointerVector;
    serSaveFunc_ = &SerializeReconBlipPointerVector;
  }

  gpg::RRef ReconBlipPointerVectorTypeRuntime::SubscriptIndex(void* const obj, const int ind) const
  {
    auto* const storage = static_cast<msvc8::vector<ReconBlip*>*>(obj);
    if (!storage || ind < 0 || static_cast<size_t>(ind) >= storage->size()) {
      return MakeReconBlipPointerSlotRef(nullptr);
    }

    return MakeReconBlipPointerSlotRef(storage->data() + ind);
  }

  size_t ReconBlipPointerVectorTypeRuntime::GetCount(void* const obj) const
  {
    const auto* const storage = static_cast<const msvc8::vector<ReconBlip*>*>(obj);
    return storage ? storage->size() : 0u;
  }

  void ReconBlipPointerVectorTypeRuntime::SetCount(void* const obj, const int count) const
  {
    auto* const storage = static_cast<msvc8::vector<ReconBlip*>*>(obj);
    GPG_ASSERT(storage != nullptr);
    GPG_ASSERT(count >= 0);
    if (!storage || count < 0) {
      return;
    }

    storage->resize(static_cast<size_t>(count), nullptr);
  }

  const char* ReconBlipMapTypeRuntime::GetName() const
  {
    if (!gReconBlipMapTypeNameInit) {
      const gpg::RType* const keyType = CachedSReconKeyType();
      const gpg::RType* const valueType = CachedReconBlipPointerType();
      const char* const keyTypeName = keyType ? keyType->GetName() : "SReconKey";
      const char* const valueTypeName = valueType ? valueType->GetName() : "ReconBlip *";
      gReconBlipMapTypeName = gpg::STR_Printf("multimap<%s,%s>", keyTypeName, valueTypeName);
      gReconBlipMapTypeNameInit = true;
      (void)std::atexit(&cleanup_ReconBlipMapTypeName);
    }

    return gReconBlipMapTypeName.c_str();
  }

  msvc8::string ReconBlipMapTypeRuntime::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    const auto* const storage = static_cast<const SReconBlipMapStorage*>(ref.mObj);
    const std::uint32_t count = storage ? storage->mSize : 0u;
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(count));
  }

  void ReconBlipMapTypeRuntime::Init()
  {
    size_ = sizeof(SReconBlipMapStorage);
    version_ = 1;
    serLoadFunc_ = &DeserializeReconBlipMapStorage;
    serSaveFunc_ = &SerializeReconBlipMapStorage;
  }

  /**
   * Address: 0x005C58E0 (FUN_005C58E0)
   */
  void DeserializeReconBlipPointerVector(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    auto* const storage =
      reinterpret_cast<msvc8::vector<ReconBlip*>*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr)));

    unsigned int count = 0;
    archive->ReadUInt(&count);

    storage->clear();
    storage->resize(static_cast<size_t>(count), nullptr);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, owner);
      (*storage)[i] = DecodeTrackedReconBlipPointer(tracked);
    }
  }

  /**
   * Address: 0x005C59F0 (FUN_005C59F0)
   */
  void SerializeReconBlipPointerVector(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto* const storage = reinterpret_cast<const msvc8::vector<ReconBlip*>*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );

    const unsigned int count = static_cast<unsigned int>(storage->size());
    archive->WriteUInt(count);

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      const gpg::RRef objectRef = MakeReconBlipObjectRef((*storage)[i]);
      gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, owner);
    }
  }

  /**
   * Address: 0x005C6210 (FUN_005C6210)
   */
  void DeserializeReconBlipMapStorage(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    auto* const storage = reinterpret_cast<SReconBlipMapStorage*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );

    unsigned int count = 0;
    archive->ReadUInt(&count);
    ClearMapStorage(storage);

    gpg::RType* const keyType = CachedSReconKeyType();
    GPG_ASSERT(keyType != nullptr);
    if (!keyType) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      SReconKey key{};
      archive->Read(keyType, &key, owner);

      const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, owner);
      (void)InsertMapNodeBySourceEntityId(storage, key, DecodeTrackedReconBlipPointer(tracked));

      key.sourceUnit.UnlinkFromOwnerChain();
    }
  }

  /**
   * Address: 0x005C6390 (FUN_005C6390)
   */
  void SerializeReconBlipMapStorage(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto* const storage = reinterpret_cast<const SReconBlipMapStorage*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );

    const unsigned int count = storage ? storage->mSize : 0u;
    archive->WriteUInt(count);

    auto* const head = MapHead(storage);
    if (!head || count == 0u) {
      return;
    }

    gpg::RType* const keyType = CachedSReconKeyType();
    GPG_ASSERT(keyType != nullptr);
    if (!keyType) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (ReconMapNodeRuntime* node = MapBegin(storage); node != head; node = MapNext(node, head)) {
      archive->Write(keyType, &node->key, owner);
      gpg::WriteRawPointer(archive, MakeReconBlipObjectRef(node->value), gpg::TrackedPointerState::Unowned, owner);
    }
  }

  struct AiReconDBTypeInfoBootstrap
  {
    AiReconDBTypeInfoBootstrap()
    {
      moho::register_IAiReconDBTypeInfo();
      moho::register_CAiReconDBImplTypeInfo();
      (void)moho::register_RVectorType_ReconBlipPtr();
      (void)moho::register_RMultiMapType_SReconKey_ReconBlipPtr();
    }
  };

  [[maybe_unused]] AiReconDBTypeInfoBootstrap gAiReconDBTypeInfoBootstrap;
} // namespace

/**
 * Address: 0x005C27B0 (FUN_005C27B0, Moho::CAiReconDBImplTypeInfo::CAiReconDBImplTypeInfo)
 *
 * What it does:
 * Preregisters `CAiReconDBImpl` RTTI into the reflection lookup table.
 */
CAiReconDBImplTypeInfo::CAiReconDBImplTypeInfo()
{
  gpg::PreRegisterRType(typeid(CAiReconDBImpl), this);
}

/**
 * Address: 0x005C2860 (FUN_005C2860, scalar deleting thunk)
 *
 * What it does:
 * Uses compiler-emitted scalar-delete thunk behavior for `gpg::RType`
 * destruction and optional object free.
 */
CAiReconDBImplTypeInfo::~CAiReconDBImplTypeInfo() = default;

/**
 * Address: 0x005C2850 (FUN_005C2850)
 *
 * IDA signature:
 * const char *Moho::CAiReconDBImplTypeInfo::GetName();
 *
 * What it does:
 * Returns `"CAiReconDBImpl"` for reflection name lookup.
 */
const char* CAiReconDBImplTypeInfo::GetName() const
{
  return "CAiReconDBImpl";
}

/**
 * Address: 0x005C2810 (FUN_005C2810)
 *
 * IDA signature:
 * void __thiscall Moho::CAiReconDBImplTypeInfo::Register(gpg::RType *this);
 *
 * What it does:
 * Registers CAiReconDBImpl reflection factory callbacks, initializes base
 * RType fields, then adds `IAiReconDB` base metadata before `Finish()`.
 */
void CAiReconDBImplTypeInfo::Init()
{
  size_ = sizeof(CAiReconDBImpl);
  BindFactoryCallbacks();
  gpg::RType::Init();
  AddIAiReconDBBase(this);
  Finish();
}

/**
 * Address: 0x005C4D30 (FUN_005C4D30)
 *
 * What it does:
 * Binds the reflection allocation/construction/destruction callback lanes for
 * `CAiReconDBImpl`.
 */
void CAiReconDBImplTypeInfo::BindFactoryCallbacks() noexcept
{
  newRefFunc_ = &CreateAiReconDbRefOwned;
  ctorRefFunc_ = &ConstructAiReconDbRefInPlace;
  deleteFunc_ = &DeleteSlot0RuntimeWithFlagOne;
  dtrFunc_ = &DestroySlot0RuntimeWithFlagZero;
}

/**
 * Address: 0x00BCDDA0 (FUN_00BCDDA0, register_CAiReconDBImplTypeInfo)
 *
 * What it does:
 * Constructs the recovered `CAiReconDBImplTypeInfo` helper and installs
 * process-exit cleanup.
 */
void moho::register_CAiReconDBImplTypeInfo()
{
  (void)AcquireCAiReconDBImplTypeInfo();
  (void)std::atexit(&cleanup_CAiReconDBImplTypeInfo);
}

/**
 * Address: 0x005CA580 (FUN_005CA580, sub_5CA580)
 *
 * What it does:
 * Constructs/preregisters reflection metadata for
 * `msvc8::vector<ReconBlip*>`.
 */
gpg::RType* moho::preregister_RVectorType_ReconBlipPtr()
{
  auto* const type = AcquireReconBlipPtrVectorType();
  gpg::PreRegisterRType(typeid(msvc8::vector<ReconBlip*>), type);
  return type;
}

/**
 * Address: 0x00BF7CC0 (FUN_00BF7CC0, sub_BF7CC0)
 *
 * What it does:
 * Tears down startup-owned `vector<ReconBlip*>` reflection storage.
 */
void moho::cleanup_RVectorType_ReconBlipPtr()
{
  cleanup_RVectorType_ReconBlipPtr_Impl();
}

/**
 * Address: 0x00BCDF60 (FUN_00BCDF60, sub_BCDF60)
 *
 * What it does:
 * Registers `vector<ReconBlip*>` reflection metadata and installs
 * process-exit cleanup.
 */
int moho::register_RVectorType_ReconBlipPtr()
{
  (void)preregister_RVectorType_ReconBlipPtr();
  return std::atexit(&cleanup_RVectorType_ReconBlipPtr_Impl);
}

/**
 * Address: 0x005CA630 (FUN_005CA630, sub_5CA630)
 *
 * What it does:
 * Constructs/preregisters reflection metadata for recon-blip map storage.
 */
gpg::RType* moho::preregister_RMultiMapType_SReconKey_ReconBlipPtr()
{
  auto* const type = AcquireReconBlipMapType();
  gpg::PreRegisterRType(typeid(SReconBlipMapStorage), type);
  return type;
}

/**
 * Address: 0x00BF7C60 (FUN_00BF7C60, sub_BF7C60)
 *
 * What it does:
 * Tears down startup-owned recon-blip map reflection storage.
 */
void moho::cleanup_RMultiMapType_SReconKey_ReconBlipPtr()
{
  cleanup_RMultiMapType_SReconKey_ReconBlipPtr_Impl();
}

/**
 * Address: 0x00BCDF80 (FUN_00BCDF80, sub_BCDF80)
 *
 * What it does:
 * Registers recon-blip map reflection metadata and installs process-exit
 * cleanup.
 */
int moho::register_RMultiMapType_SReconKey_ReconBlipPtr()
{
  (void)preregister_RMultiMapType_SReconKey_ReconBlipPtr();
  return std::atexit(&cleanup_RMultiMapType_SReconKey_ReconBlipPtr_Impl);
}
