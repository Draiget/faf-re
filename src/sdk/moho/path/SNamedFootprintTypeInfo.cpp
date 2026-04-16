#include "moho/path/SNamedFootprint.h"
#include "moho/sim/SRuleFootprintsBlueprint.h"

#include <cstdint>
#include <cstdlib>
#include <list>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  template <class T>
  [[nodiscard]] gpg::RType* ResolveType()
  {
    return gpg::LookupRType(typeid(T));
  }

  /**
   * Address: 0x00514680 (FUN_00514680)
   *
   * What it does:
   * Resolves/caches `SFootprint` RTTI and appends it as a base descriptor of
   * the current `SNamedFootprint` typeinfo object.
   */
  void AddSFootprintBaseDescriptor(gpg::RType* const owner)
  {
    if (!owner) {
      return;
    }

    static gpg::RType* cachedSFootprintType = nullptr;
    gpg::RType* baseType = cachedSFootprintType;
    if (!baseType) {
      baseType = ResolveType<moho::SFootprint>();
      cachedSFootprintType = baseType;
    }
    if (!baseType) {
      return;
    }

    GPG_ASSERT(!owner->initFinished_);
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    owner->AddBase(baseField);
  }

  void AddFieldDescriptor(gpg::RType* const owner, const char* const name, gpg::RType* const fieldType, const int offset)
  {
    if (!owner || !fieldType) {
      return;
    }

    GPG_ASSERT(!owner->initFinished_);
    gpg::RField field{};
    field.mName = name;
    field.mType = fieldType;
    field.mOffset = offset;
    owner->fields_.push_back(field);
  }

  struct SFootprintScalarRuntimeView
  {
    std::uint32_t packedFootprintHeader; // +0x00 (size/caps/flags lane)
    std::uint32_t maxSlopeBits; // +0x04
    std::uint32_t minWaterDepthBits; // +0x08
    std::uint32_t maxWaterDepthBits; // +0x0C
  };
  static_assert(
    offsetof(SFootprintScalarRuntimeView, maxSlopeBits) == 0x4,
    "SFootprintScalarRuntimeView::maxSlopeBits offset must be 0x4"
  );
  static_assert(
    offsetof(SFootprintScalarRuntimeView, minWaterDepthBits) == 0x8,
    "SFootprintScalarRuntimeView::minWaterDepthBits offset must be 0x8"
  );
  static_assert(
    offsetof(SFootprintScalarRuntimeView, maxWaterDepthBits) == 0xC,
    "SFootprintScalarRuntimeView::maxWaterDepthBits offset must be 0xC"
  );
  static_assert(sizeof(SFootprintScalarRuntimeView) == 0x10, "SFootprintScalarRuntimeView size must be 0x10");

  /**
   * Address: 0x005133E0 (FUN_005133E0)
   *
   * What it does:
   * Swaps the three trailing 32-bit scalar lanes (`+0x04/+0x08/+0x0C`) between
   * two footprint runtime views, leaving the packed header lane unchanged.
   */
  [[maybe_unused]] [[nodiscard]] SFootprintScalarRuntimeView* SwapFootprintScalarTailWordsA(
    SFootprintScalarRuntimeView* const left,
    SFootprintScalarRuntimeView* const right
  )
  {
    const std::uint32_t maxSlopeBits = right->maxSlopeBits;
    right->maxSlopeBits = left->maxSlopeBits;
    left->maxSlopeBits = maxSlopeBits;

    const std::uint32_t minWaterDepthBits = right->minWaterDepthBits;
    right->minWaterDepthBits = left->minWaterDepthBits;
    left->minWaterDepthBits = minWaterDepthBits;

    const std::uint32_t maxWaterDepthBits = right->maxWaterDepthBits;
    right->maxWaterDepthBits = left->maxWaterDepthBits;
    left->maxWaterDepthBits = maxWaterDepthBits;
    return left;
  }

  /**
   * Address: 0x00513480 (FUN_00513480)
   *
   * What it does:
   * Alternate call-shape lane for swapping the same footprint trailing
   * `+0x04/+0x08/+0x0C` scalar words.
   */
  [[maybe_unused]] [[nodiscard]] SFootprintScalarRuntimeView* SwapFootprintScalarTailWordsB(
    SFootprintScalarRuntimeView* const left,
    SFootprintScalarRuntimeView* const right
  )
  {
    const std::uint32_t maxSlopeBits = right->maxSlopeBits;
    right->maxSlopeBits = left->maxSlopeBits;
    left->maxSlopeBits = maxSlopeBits;

    const std::uint32_t minWaterDepthBits = right->minWaterDepthBits;
    right->minWaterDepthBits = left->minWaterDepthBits;
    left->minWaterDepthBits = minWaterDepthBits;

    const std::uint32_t maxWaterDepthBits = right->maxWaterDepthBits;
    right->maxWaterDepthBits = left->maxWaterDepthBits;
    left->maxWaterDepthBits = maxWaterDepthBits;
    return left;
  }

  /**
   * Address: 0x00513940 (FUN_00513940)
   *
   * What it does:
   * Swaps the packed footprint header word at offset `+0x00` between two
   * runtime views and returns the first operand.
   */
  [[maybe_unused]] [[nodiscard]] SFootprintScalarRuntimeView* SwapFootprintPackedHeaderWord(
    SFootprintScalarRuntimeView* const left,
    SFootprintScalarRuntimeView* const right
  )
  {
    const std::uint32_t packedHeader = right->packedFootprintHeader;
    right->packedFootprintHeader = left->packedFootprintHeader;
    left->packedFootprintHeader = packedHeader;
    return left;
  }

  /**
   * Address: 0x00514870 (FUN_00514870)
   *
   * What it does:
   * Allocates raw storage for `count` intrusive `SRuleFootprintNode` objects
   * and throws `std::bad_alloc` if the byte-count would overflow 32-bit lanes.
   */
  [[nodiscard]] moho::SRuleFootprintNode* AllocateSRuleFootprintNodeBlock(const unsigned int count)
  {
    if (count == 0u || (0xFFFFFFFFu / count) < sizeof(moho::SRuleFootprintNode)) {
      throw std::bad_alloc();
    }

    return static_cast<moho::SRuleFootprintNode*>(
      operator new(static_cast<std::size_t>(count) * sizeof(moho::SRuleFootprintNode))
    );
  }

  /**
   * Address: 0x00514640 (FUN_00514640)
   *
   * What it does:
   * Allocates one intrusive `SRuleFootprintNode` storage slot.
   */
  [[nodiscard]] moho::SRuleFootprintNode* AllocateSingleSRuleFootprintNode()
  {
    return AllocateSRuleFootprintNodeBlock(1u);
  }

  /**
   * Address: 0x0052CB30 (FUN_0052CB30)
   *
   * What it does:
   * Allocates one intrusive rule-footprint list sentinel node and wires both
   * link lanes to point back to that same node.
   */
  [[maybe_unused]] [[nodiscard]] moho::SRuleFootprintNode* AllocateSelfLinkedSRuleFootprintSentinelNode()
  {
    moho::SRuleFootprintNode* const node = AllocateSingleSRuleFootprintNode();
    if (node != nullptr) {
      node->next = node;
    }
    if (reinterpret_cast<std::intptr_t>(node) != -4 && node != nullptr) {
      node->prev = node;
    }
    return node;
  }

  /**
   * Address: 0x00529550 (FUN_00529550)
   *
   * What it does:
   * Initializes one `SRuleFootprintsBlueprint` list runtime lane by allocating
   * a self-linked sentinel node and resetting element count to zero.
   */
  [[maybe_unused]] moho::SRuleFootprintsBlueprint* InitializeSRuleFootprintsBlueprintList(
    moho::SRuleFootprintsBlueprint* const footprintList
  )
  {
    footprintList->mHead = AllocateSelfLinkedSRuleFootprintSentinelNode();
    footprintList->mSize = 0u;
    return footprintList;
  }

  /**
   * Address: 0x00514660 (FUN_00514660, nullsub_1066)
   *
   * What it does:
   * Provides a no-op compatibility lane used by generated helper/vtable
   * tables in the original binary.
   */
  [[maybe_unused]] void SNamedFootprintNoOpLane()
  {
  }

  /**
   * Address: 0x00514670 (FUN_00514670)
   *
   * What it does:
   * Returns the fixed legacy marker value used by this helper lane.
   */
  [[maybe_unused]] [[nodiscard]] int SNamedFootprintLegacyMarkerValue()
  {
    return 0x05555555;
  }

  /**
   * Address: 0x00514960 (FUN_00514960, func_CopySNamedFootprint)
   *
   * What it does:
   * Copies footprint scalar lanes, resets destination string to SSO-empty,
   * then copies full `mName` and trailing `mIndex`.
   */
  [[nodiscard]] moho::SNamedFootprint* CopySNamedFootprintValue(
    const moho::SNamedFootprint* const source,
    moho::SNamedFootprint* const destination
  )
  {
    GPG_ASSERT(source != nullptr);
    GPG_ASSERT(destination != nullptr);
    if (!source || !destination) {
      return destination;
    }

    destination->mSizeX = source->mSizeX;
    destination->mSizeZ = source->mSizeZ;
    destination->mOccupancyCaps = source->mOccupancyCaps;
    destination->mFlags = source->mFlags;
    destination->mMaxSlope = source->mMaxSlope;
    destination->mMinWaterDepth = source->mMinWaterDepth;
    destination->mMaxWaterDepth = source->mMaxWaterDepth;
    destination->mName.reset_and_assign(source->mName);
    destination->mIndex = source->mIndex;
    return destination;
  }

  /**
   * Address: 0x005145F0 (FUN_005145F0)
   *
   * What it does:
   * Copies one `SNamedFootprint` object into destination when destination is
   * non-null (lane A).
   */
  [[maybe_unused]] [[nodiscard]] moho::SNamedFootprint* CopySNamedFootprintIfTargetPresentA(
    moho::SNamedFootprint* const destination,
    const moho::SNamedFootprint* const source
  )
  {
    if (!destination) {
      return nullptr;
    }
    return CopySNamedFootprintValue(source, destination);
  }

  /**
   * Address: 0x00514820 (FUN_00514820)
   *
   * What it does:
   * Copies one `SNamedFootprint` object into destination when destination is
   * non-null (lane B).
   */
  [[maybe_unused]] [[nodiscard]] moho::SNamedFootprint* CopySNamedFootprintIfTargetPresentB(
    moho::SNamedFootprint* const destination,
    const moho::SNamedFootprint* const source
  )
  {
    if (!destination) {
      return nullptr;
    }
    return CopySNamedFootprintValue(source, destination);
  }

  /**
   * Address: 0x005144A0 (FUN_005144A0)
   *
   * What it does:
   * Allocates one intrusive node, wires `next/prev` lanes, and copy-constructs
   * the embedded `SNamedFootprint` payload from source.
   */
  [[maybe_unused]] [[nodiscard]] moho::SRuleFootprintNode* CreateSRuleFootprintNode(
    moho::SRuleFootprintNode* const next,
    moho::SRuleFootprintNode* const prev,
    const moho::SNamedFootprint* const source
  )
  {
    moho::SRuleFootprintNode* const node = AllocateSingleSRuleFootprintNode();
    node->next = next;
    node->prev = prev;
    (void)CopySNamedFootprintValue(source, &node->value);
    return node;
  }

  struct SNamedFootprintListNodeRuntime
  {
    SNamedFootprintListNodeRuntime* next; // +0x00
    SNamedFootprintListNodeRuntime* prev; // +0x04
    moho::SNamedFootprint value; // +0x08
  };
  static_assert(
    offsetof(SNamedFootprintListNodeRuntime, value) == 0x8,
    "SNamedFootprintListNodeRuntime::value offset must be 0x8"
  );

  struct SNamedFootprintListRuntimeView
  {
    std::uint32_t allocatorProxy; // +0x00
    SNamedFootprintListNodeRuntime* sentinel; // +0x04
    std::uint32_t count; // +0x08
  };
  static_assert(
    offsetof(SNamedFootprintListRuntimeView, sentinel) == 0x4,
    "SNamedFootprintListRuntimeView::sentinel offset must be 0x4"
  );
  static_assert(
    offsetof(SNamedFootprintListRuntimeView, count) == 0x8,
    "SNamedFootprintListRuntimeView::count offset must be 0x8"
  );

  /**
   * Address: 0x005142F0 (FUN_005142F0)
   *
   * What it does:
   * Stores the current list-begin node pointer (`sentinel->next`) into the
   * caller-provided node cursor slot.
   */
  [[maybe_unused]] [[nodiscard]] SNamedFootprintListNodeRuntime** StoreSNamedFootprintListBeginCursor(
    SNamedFootprintListNodeRuntime** const outCursor,
    const SNamedFootprintListRuntimeView* const listRuntime
  )
  {
    *outCursor = listRuntime->sentinel->next;
    return outCursor;
  }

  /**
   * Address: 0x00514300 (FUN_00514300)
   *
   * What it does:
   * Stores the sentinel node pointer from a list runtime view into the
   * caller-provided cursor slot (lane A).
   */
  [[maybe_unused]] [[nodiscard]] SNamedFootprintListNodeRuntime** StoreSNamedFootprintListSentinelCursorA(
    SNamedFootprintListNodeRuntime** const outCursor,
    const SNamedFootprintListRuntimeView* const listRuntime
  )
  {
    *outCursor = listRuntime->sentinel;
    return outCursor;
  }

  /**
   * Address: 0x005143B0 (FUN_005143B0)
   *
   * What it does:
   * Advances one in-place list node cursor to its `next` link.
   */
  [[maybe_unused]] [[nodiscard]] SNamedFootprintListNodeRuntime** AdvanceSNamedFootprintNodeCursor(
    SNamedFootprintListNodeRuntime** const cursor
  )
  {
    *cursor = (*cursor)->next;
    return cursor;
  }

  /**
   * Address: 0x00514400 (FUN_00514400)
   *
   * What it does:
   * Stores the sentinel node pointer from a list runtime view into the
   * caller-provided cursor slot (lane B).
   */
  [[maybe_unused]] [[nodiscard]] SNamedFootprintListNodeRuntime** StoreSNamedFootprintListSentinelCursorB(
    SNamedFootprintListNodeRuntime** const outCursor,
    const SNamedFootprintListRuntimeView* const listRuntime
  )
  {
    *outCursor = listRuntime->sentinel;
    return outCursor;
  }

  /**
   * Address: 0x00514480 (FUN_00514480)
   *
   * What it does:
   * Writes a node pointer directly into a caller-provided cursor slot (lane A).
   */
  [[maybe_unused]] [[nodiscard]] SNamedFootprintListNodeRuntime** StoreSNamedFootprintNodeCursorA(
    SNamedFootprintListNodeRuntime** const outCursor,
    SNamedFootprintListNodeRuntime* const node
  )
  {
    *outCursor = node;
    return outCursor;
  }

  /**
   * Address: 0x005145D0 (FUN_005145D0)
   *
   * What it does:
   * Writes a node pointer directly into a caller-provided cursor slot (lane B).
   */
  [[maybe_unused]] [[nodiscard]] SNamedFootprintListNodeRuntime** StoreSNamedFootprintNodeCursorB(
    SNamedFootprintListNodeRuntime** const outCursor,
    SNamedFootprintListNodeRuntime* const node
  )
  {
    *outCursor = node;
    return outCursor;
  }

  [[nodiscard]] std::uint32_t IncrementSNamedFootprintListCountOrThrow(
    SNamedFootprintListRuntimeView* const listRuntime
  )
  {
    constexpr std::uint32_t kLegacyListMaxCount = 0x05555555u;
    if (listRuntime->count == kLegacyListMaxCount) {
      throw std::length_error("list<T> too long");
    }

    ++listRuntime->count;
    return listRuntime->count;
  }

  /**
   * Address: 0x00514410 (FUN_00514410)
   *
   * What it does:
   * Allocates one rule-footprint node from `source`, links it before the list
   * sentinel, and increments the owning list count with legacy overflow checks.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t InsertRuleFootprintBeforeSentinel(
    const moho::SNamedFootprint* const source,
    SNamedFootprintListRuntimeView* const listRuntime,
    moho::SRuleFootprintNode* const sentinel
  )
  {
    moho::SRuleFootprintNode* const node = CreateSRuleFootprintNode(sentinel, sentinel->prev, source);
    const std::uint32_t count = IncrementSNamedFootprintListCountOrThrow(listRuntime);
    sentinel->prev = node;
    node->prev->next = node;
    return count;
  }

  /**
   * Address: 0x00514340 (FUN_00514340)
   *
   * What it does:
   * Detaches one intrusive `list<SNamedFootprint>` node ring from its
   * sentinel, destroys each node's owned name string payload, deletes each
   * detached node, and resets the list element count to zero.
   */
  [[maybe_unused]] void ClearSNamedFootprintListNodeRing(
    SNamedFootprintListRuntimeView* const listRuntime
  ) noexcept
  {
    if (listRuntime == nullptr || listRuntime->sentinel == nullptr) {
      return;
    }

    SNamedFootprintListNodeRuntime* const sentinel = listRuntime->sentinel;
    SNamedFootprintListNodeRuntime* node = sentinel->next;
    sentinel->next = sentinel;
    sentinel->prev = sentinel;
    listRuntime->count = 0u;

    while (node != sentinel) {
      SNamedFootprintListNodeRuntime* const nextNode = node->next;
      node->value.mName.tidy(true, 0u);
      ::operator delete(static_cast<void*>(node));
      node = nextNode;
    }
  }

  [[nodiscard]] std::size_t CountSNamedFootprintList(const void* const obj) noexcept
  {
    if (!obj) {
      return 0u;
    }

    const auto* const list = static_cast<const std::list<moho::SNamedFootprint>*>(obj);
    return list ? list->size() : 0u;
  }

  [[nodiscard]] const gpg::RRef& NullOwnerRef() noexcept
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  void LoadSNamedFootprintList(gpg::ReadArchive* archive, int objectPtr, int unused, gpg::RRef* ownerRef);
  void SaveSNamedFootprintList(gpg::WriteArchive* archive, int objectPtr, int unused, gpg::RRef* ownerRef);

  msvc8::string gSNamedFootprintListTypeName;
  bool gSNamedFootprintListTypeNameCleanupRegistered = false;

  /**
   * Address: 0x00BF28E0 (FUN_00BF28E0)
   *
   * What it does:
   * Releases the cached `list<SNamedFootprint>` RTTI name string at process exit.
   */
  void CleanupSNamedFootprintListTypeName()
  {
    gSNamedFootprintListTypeName = msvc8::string{};
    gSNamedFootprintListTypeNameCleanupRegistered = false;
  }

  class SNamedFootprintTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00513DA0 (FUN_00513DA0, Moho::SNamedFootprintTypeInfo::dtr)
     *
     * What it does:
     * Destroys reflected field/base storage through the inherited `gpg::RType`
     * teardown lane.
     */
    ~SNamedFootprintTypeInfo() override;

    /**
     * Address: 0x00513D90 (FUN_00513D90, Moho::SNamedFootprintTypeInfo::GetName)
     *
     * What it does:
     * Returns the RTTI label for `SNamedFootprint`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00513D50 (FUN_00513D50, Moho::SNamedFootprintTypeInfo::Init)
     *
     * What it does:
     * Registers the base `SFootprint` metadata plus the `Name` and `Index`
     * reflected fields.
     */
    void Init() override;
  };

  static_assert(sizeof(SNamedFootprintTypeInfo) == 0x64, "SNamedFootprintTypeInfo size must be 0x64");

  /**
   * Address: 0x00513DA0 (FUN_00513DA0, Moho::SNamedFootprintTypeInfo::dtr)
   *
   * What it does:
   * Destroys reflected field/base storage through the inherited `gpg::RType`
   * teardown lane.
   */
  SNamedFootprintTypeInfo::~SNamedFootprintTypeInfo() = default;

  /**
   * Address: 0x00513D90 (FUN_00513D90, Moho::SNamedFootprintTypeInfo::GetName)
   *
   * What it does:
   * Returns the RTTI label for `SNamedFootprint`.
   */
  const char* SNamedFootprintTypeInfo::GetName() const
  {
    return "SNamedFootprint";
  }

  /**
   * Address: 0x00513D50 (FUN_00513D50, Moho::SNamedFootprintTypeInfo::Init)
   *
   * What it does:
   * Registers the base `SFootprint` metadata plus the `Name` and `Index`
   * reflected fields.
   */
  void SNamedFootprintTypeInfo::Init()
  {
    size_ = sizeof(moho::SNamedFootprint);
    gpg::RType::Init();

    AddSFootprintBaseDescriptor(this);
    AddFieldDescriptor(this, "Name", ResolveType<msvc8::string>(), 0x10);
    AddFieldDescriptor(this, "Index", ResolveType<int>(), 0x2C);

    Finish();
  }

  class SNamedFootprintListTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00513FB0 (FUN_00513FB0, gpg::RListType_SNamedFootprint::GetName)
     *
     * What it does:
     * Lazily builds and caches the `list<SNamedFootprint>` RTTI label.
     */
    [[nodiscard]] const char* GetName() const override
    {
      if (gSNamedFootprintListTypeName.empty()) {
        const gpg::RType* const elementType = moho::preregister_SNamedFootprintTypeInfo();
        const char* const elementName = elementType ? elementType->GetName() : "SNamedFootprint";
        gSNamedFootprintListTypeName = gpg::STR_Printf("list<%s>", elementName ? elementName : "SNamedFootprint");
        if (!gSNamedFootprintListTypeNameCleanupRegistered) {
          gSNamedFootprintListTypeNameCleanupRegistered = true;
          (void)std::atexit(&CleanupSNamedFootprintListTypeName);
        }
      }

      return gSNamedFootprintListTypeName.c_str();
    }

    /**
     * Address: 0x00514070 (FUN_00514070, gpg::RListType_SNamedFootprint::GetLexical)
     *
     * What it does:
     * Formats the inherited list lexical text with the current list size.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00514050 (FUN_00514050, gpg::RListType_SNamedFootprint::Init)
     *
     * What it does:
     * Marks the reflected list as versioned and wires archive callbacks.
     */
    void Init() override;
  };

  static_assert(sizeof(SNamedFootprintListTypeInfo) == 0x64, "SNamedFootprintListTypeInfo size must be 0x64");

  /**
   * Address: 0x00514070 (FUN_00514070, gpg::RListType_SNamedFootprint::GetLexical)
   *
   * What it does:
   * Formats the inherited list lexical text with the current list size.
   */
  msvc8::string SNamedFootprintListTypeInfo::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(CountSNamedFootprintList(ref.mObj)));
  }

  /**
   * Address: 0x00514050 (FUN_00514050, gpg::RListType_SNamedFootprint::Init)
   *
   * What it does:
   * Marks the reflected list as versioned and wires archive callbacks.
   */
  void SNamedFootprintListTypeInfo::Init()
  {
    size_ = sizeof(std::list<moho::SNamedFootprint>);
    version_ = 1;
    serLoadFunc_ = &LoadSNamedFootprintList;
    serSaveFunc_ = &SaveSNamedFootprintList;
  }

  alignas(SNamedFootprintTypeInfo) unsigned char gSNamedFootprintTypeInfoStorage[sizeof(SNamedFootprintTypeInfo)]{};
  bool gSNamedFootprintTypeInfoConstructed = false;
  bool gSNamedFootprintTypeInfoPreregistered = false;

  alignas(SNamedFootprintListTypeInfo)
    unsigned char gSNamedFootprintListTypeInfoStorage[sizeof(SNamedFootprintListTypeInfo)]{};
  bool gSNamedFootprintListTypeInfoConstructed = false;
  bool gSNamedFootprintListTypeInfoPreregistered = false;

  [[nodiscard]] SNamedFootprintTypeInfo* AcquireSNamedFootprintTypeInfo()
  {
    if (!gSNamedFootprintTypeInfoConstructed) {
      new (gSNamedFootprintTypeInfoStorage) SNamedFootprintTypeInfo();
      gSNamedFootprintTypeInfoConstructed = true;
    }

    return reinterpret_cast<SNamedFootprintTypeInfo*>(gSNamedFootprintTypeInfoStorage);
  }

  [[nodiscard]] SNamedFootprintListTypeInfo* AcquireSNamedFootprintListTypeInfo()
  {
    if (!gSNamedFootprintListTypeInfoConstructed) {
      new (gSNamedFootprintListTypeInfoStorage) SNamedFootprintListTypeInfo();
      gSNamedFootprintListTypeInfoConstructed = true;
    }

    return reinterpret_cast<SNamedFootprintListTypeInfo*>(gSNamedFootprintListTypeInfoStorage);
  }

  /**
   * Address: 0x00514110 (FUN_00514110, gpg::RListType_SNamedFootprint::SerLoad)
   *
   * What it does:
   * Reads a uint count then iteratively reflects each `SNamedFootprint`
   * element from the archive into the destination list.
   */
  void LoadSNamedFootprintList(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    auto* const list = reinterpret_cast<std::list<moho::SNamedFootprint>*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(list != nullptr);
    if (!archive || !list) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    std::list<moho::SNamedFootprint> loaded{};
    gpg::RType* const elementType = moho::preregister_SNamedFootprintTypeInfo();
    const gpg::RRef& owner = ownerRef ? *ownerRef : NullOwnerRef();
    for (unsigned int i = 0; i < count; ++i) {
      loaded.emplace_back();
      archive->Read(elementType, &loaded.back(), owner);
    }

    list->swap(loaded);
  }

  /**
   * Address: 0x00514240 (FUN_00514240, gpg::RListType_SNamedFootprint::SerSave)
   *
   * What it does:
   * Writes list element count, then reflects each `SNamedFootprint` value to
   * the archive with the incoming owner context.
   */
  void SaveSNamedFootprintList(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    auto* const list = reinterpret_cast<const std::list<moho::SNamedFootprint>*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const unsigned int count = list ? static_cast<unsigned int>(list->size()) : 0u;
    archive->WriteUInt(count);

    if (!list) {
      return;
    }

    gpg::RType* const elementType = moho::preregister_SNamedFootprintTypeInfo();
    const gpg::RRef& owner = ownerRef ? *ownerRef : NullOwnerRef();
    for (const moho::SNamedFootprint& footprint : *list) {
      archive->Write(elementType, &footprint, owner);
    }
  }

  struct SNamedFootprintTypeInfoBootstrap
  {
    SNamedFootprintTypeInfoBootstrap()
    {
      (void)moho::register_SNamedFootprintTypeInfoStartup();
    }
  };

  [[maybe_unused]] SNamedFootprintTypeInfoBootstrap gSNamedFootprintTypeInfoBootstrap;

  struct SNamedFootprintListTypeInfoBootstrap
  {
    SNamedFootprintListTypeInfoBootstrap()
    {
      (void)moho::register_SNamedFootprintListTypeInfoStartup();
    }
  };

  [[maybe_unused]] SNamedFootprintListTypeInfoBootstrap gSNamedFootprintListTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00513CF0 (FUN_00513CF0, preregister_SNamedFootprintTypeInfo)
   *
   * What it does:
   * Constructs and preregisters startup RTTI storage for `SNamedFootprint`.
   */
  gpg::RType* preregister_SNamedFootprintTypeInfo()
  {
    gpg::RType* const typeInfo = AcquireSNamedFootprintTypeInfo();
    if (!gSNamedFootprintTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(SNamedFootprint), typeInfo);
      gSNamedFootprintTypeInfoPreregistered = true;
    }

    return typeInfo;
  }

  /**
   * Address: 0x00BF2820 (FUN_00BF2820, cleanup_SNamedFootprintTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `SNamedFootprintTypeInfo` storage at process exit.
   */
  void cleanup_SNamedFootprintTypeInfo()
  {
    if (!gSNamedFootprintTypeInfoConstructed) {
      return;
    }

    AcquireSNamedFootprintTypeInfo()->~SNamedFootprintTypeInfo();
    gSNamedFootprintTypeInfoConstructed = false;
    gSNamedFootprintTypeInfoPreregistered = false;
  }

  /**
   * Address: 0x00BC8360 (FUN_00BC8360, register_SNamedFootprintTypeInfoStartup)
   *
   * What it does:
   * Preregisters `SNamedFootprint` RTTI and installs process-exit cleanup.
   */
  int register_SNamedFootprintTypeInfoStartup()
  {
    (void)preregister_SNamedFootprintTypeInfo();
    return std::atexit(&cleanup_SNamedFootprintTypeInfo);
  }

  /**
   * Address: 0x005149D0 (FUN_005149D0, preregister_SNamedFootprintListTypeInfo)
   *
   * What it does:
   * Constructs and preregisters startup RTTI storage for `std::list<SNamedFootprint>`.
   */
  gpg::RType* preregister_SNamedFootprintListTypeInfo()
  {
    gpg::RType* const typeInfo = AcquireSNamedFootprintListTypeInfo();
    if (!gSNamedFootprintListTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(std::list<SNamedFootprint>), typeInfo);
      gSNamedFootprintListTypeInfoPreregistered = true;
    }

    return typeInfo;
  }

  /**
   * Address: 0x00BF2910 (FUN_00BF2910, cleanup_SNamedFootprintListTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `std::list<SNamedFootprint>` RTTI storage at process exit.
   */
  void cleanup_SNamedFootprintListTypeInfo()
  {
    if (!gSNamedFootprintListTypeInfoConstructed) {
      return;
    }

    AcquireSNamedFootprintListTypeInfo()->~SNamedFootprintListTypeInfo();
    gSNamedFootprintListTypeInfoConstructed = false;
    gSNamedFootprintListTypeInfoPreregistered = false;
  }

  /**
   * Address: 0x00BC83A0 (FUN_00BC83A0, register_SNamedFootprintListTypeInfoStartup)
   *
   * What it does:
   * Preregisters `std::list<SNamedFootprint>` RTTI and installs process-exit cleanup.
   */
  int register_SNamedFootprintListTypeInfoStartup()
  {
    (void)preregister_SNamedFootprintListTypeInfo();
    return std::atexit(&cleanup_SNamedFootprintListTypeInfo);
  }
} // namespace moho
