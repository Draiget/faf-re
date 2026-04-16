#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

namespace boost
{
  template <typename T>
  class shared_ptr;
}

namespace gpg
{
  struct MD5Context;
  class SerConstructResult;
  struct SerHelperBase;
  class SerSaveConstructArgsResult;
}

namespace moho
{
  class CIntelGrid;
}

namespace gpg
{
  /**
   * Address: 0x00509200 (FUN_00509200, gpg::RRef_CIntelGrid)
   *
   * What it does:
   * Builds one typed reflection reference for a `CIntelGrid*` pointer.
   */
  gpg::RRef* RRef_CIntelGrid(gpg::RRef* outRef, moho::CIntelGrid* value);
}

namespace moho
{
  class STIMap;

  /**
   * Address: 0x005CAFB0 (FUN_005CAFB0, boost::shared_ptr_CIntelGrid::shared_ptr_CIntelGrid)
   *
   * What it does:
   * Constructs one `shared_ptr<CIntelGrid>` from one raw intel-grid pointer
   * lane.
   */
  boost::shared_ptr<CIntelGrid>* ConstructSharedIntelGridFromRaw(
    boost::shared_ptr<CIntelGrid>* outIntelGrid,
    CIntelGrid* intelGrid
  );

  struct SDelayedSubVizInfo
  {
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    Wm3::Vec3f mLastPos;          // +0x00
    float mRadius;                // +0x0C
    std::int32_t mTicksTilUpdate; // +0x10

    /**
     * Address: 0x005088F0 (FUN_005088F0, Moho::SDelayedSubVizInfo::MemberDeserialize)
     *
     * What it does:
     * Loads `mLastPos`, `mRadius`, and `mTicksTilUpdate` from archive lanes.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00508950 (FUN_00508950, Moho::SDelayedSubVizInfo::MemberSerialize)
     *
     * What it does:
     * Writes `mLastPos`, `mRadius`, and `mTicksTilUpdate` into archive lanes.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;
  };

  struct SDelayedSubVizInfoVectorStorage
  {
    std::uint32_t mAllocatorProxyOrReserved; // +0x00
    SDelayedSubVizInfo* mStart;              // +0x04
    SDelayedSubVizInfo* mFinish;             // +0x08
    SDelayedSubVizInfo* mCapacity;           // +0x0C
  };

  using CIntelUpdate = SDelayedSubVizInfo;
  using CIntelUpdateListStorage = SDelayedSubVizInfoVectorStorage;

  static_assert(sizeof(SDelayedSubVizInfo) == 0x14, "SDelayedSubVizInfo size must be 0x14");
  static_assert(sizeof(SDelayedSubVizInfoVectorStorage) == 0x10, "SDelayedSubVizInfoVectorStorage size must be 0x10");

  class CIntelGrid
  {
  public:
    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x00507720 (FUN_00507720, ??0CIntelGrid@Moho@@QAE@PBVSTIMap@1@H@Z)
     *
     * What it does:
     * Binds map source, allocates byte coverage grid, and sets delayed-update
     * storage to empty.
     */
    CIntelGrid(const STIMap* map, std::uint32_t size);

    /**
       * Address: 0x00508D80 (FUN_00508D80)
     *
     * What it does:
     * Releases delayed-sub-viz storage and backing visibility grid memory.
     */
    ~CIntelGrid();

    /**
     * Address: 0x005BE150 (FUN_005BE150, ?IsVisible@CIntelGrid@Moho@@QBE_NHH@Z)
     *
     * What it does:
     * Returns true when `(x,z)` is inside the intel grid bounds and the cell
     * visibility byte is non-zero.
     */
    [[nodiscard]] bool IsVisible(std::int32_t x, std::int32_t z) const;

    /**
     * Address: 0x005BE180 (FUN_005BE180, ?IsVisible@CIntelGrid@Moho@@QBE_NABV?$Vector2@H@Wm3@@@Z)
     *
     * What it does:
     * Returns true when integer grid coordinates are inside bounds and the
     * addressed visibility byte is non-zero.
     */
    [[nodiscard]] bool IsVisible(const Wm3::Vector2i& gridCell) const;

    /**
     * Address: 0x005BE1C0 (FUN_005BE1C0, ?IsVisible@CIntelGrid@Moho@@QBE_NABV?$Vector3@M@Wm3@@@Z)
     *
     * Wm3::Vector3<float> const &
     *
     * IDA signature:
     * bool __usercall Moho::CIntelGrid::IsVisible@<al>(
     *   Moho::CIntelGrid *this@<edi>,
     *   Wm3::Vector3f *position@<esi>)
     *
     * What it does:
     * Converts world-space position to grid coordinates and returns true when
     * the mapped cell is inside bounds and has non-zero visibility.
     */
    [[nodiscard]] bool IsVisible(const Wm3::Vec3f& position) const;

    /**
     * Address: 0x005BE210 (FUN_005BE210, ?IsVisible@CIntelGrid@Moho@@QBE_NABV?$Rect2@H@gpg@@_N@Z)
     *
     * What it does:
     * Converts world-space rectangle bounds into grid-cell bounds and returns
     * true when any covered grid cell is visible.
     */
    [[nodiscard]] bool IsVisible(const gpg::Rect2<int>& rect, bool unused = false) const;

    /**
     * Address: 0x00507670 (FUN_00507670, ?AddCircle@CIntelGrid@Moho@@QAEXABV?$Vector3@M@Wm3@@I@Z)
     *
     * What it does:
     * Converts world radius to cell radius and adds +1 coverage over the
     * rasterized circle.
     */
    void AddCircle(const Wm3::Vec3f& position, std::uint32_t radius);

    /**
     * Address: 0x00507690 (FUN_00507690, ?SubtractCircle@CIntelGrid@Moho@@QAEXABV?$Vector3@M@Wm3@@I@Z)
     *
     * What it does:
     * Converts world radius to cell radius and subtracts 1 coverage over the
     * rasterized circle.
     */
    void SubtractCircle(const Wm3::Vec3f& position, std::uint32_t radius);

    /**
     * Address: 0x005076B0 (FUN_005076B0, ?DelayedSubtractCircle@CIntelGrid@Moho@@QAEXABV?$Vector3@M@Wm3@@I@Z)
     *
     * What it does:
     * Queues delayed subtraction update (30 ticks) for later processing.
     */
    void DelayedSubtractCircle(const Wm3::Vec3f& position, std::uint32_t radius);

    /**
     * Address: 0x005077B0 (FUN_005077B0, ?Tick@CIntelGrid@Moho@@QAEXH@Z)
     *
     * What it does:
     * Advances delayed subtraction timers and applies expired raster removals.
     */
    void Tick(std::int32_t dTicks);

    /**
     * Address: 0x00507880 (FUN_00507880, ?UpdateChecksum@CIntelGrid@Moho@@QAEXAAVMD5Context@gpg@@@Z)
     *
     * What it does:
     * Explicit no-op checksum lane (`retn` in binary).
     */
    void UpdateChecksum(gpg::MD5Context& context);

    /**
     * Address: 0x005072D0 (FUN_005072D0,
     * ?MemberSaveConstructArgs@CIntelGrid@Moho@@AAEXAAVWriteArchive@gpg@@HABVRRef@4@AAVSerSaveConstructArgsResult@4@@Z)
     *
     * What it does:
     * Saves construct args (`STIMap*`, `mGridSize`) as unowned tracked pointer
     * payload for serializer construct callback.
     */
    void MemberSaveConstructArgs(
      gpg::WriteArchive& archive, int version, const gpg::RRef& ownerRef, gpg::SerSaveConstructArgsResult& result
    );

  private:
    /**
     * Address: 0x00507540 (FUN_00507540, ?Raster@CIntelGrid@Moho@@AAEXABV?$Vector3@M@Wm3@@I_N@Z)
     *
     * What it does:
     * Applies +/-1 over the filled cell-space circle.
     */
    void Raster(const Wm3::Vec3f& position, std::uint32_t radiusInCells, bool doAdd);

    void PushDelayedUpdate(const SDelayedSubVizInfo& update);

  public:
    STIMap* mMapData;                            // +0x00
    std::int8_t* mGrid;                          // +0x04
    std::uint32_t mWidth;                        // +0x08
    std::uint32_t mHeight;                       // +0x0C
    SDelayedSubVizInfoVectorStorage mUpdateList; // +0x10
    std::uint32_t mGridSize;                     // +0x20
  };

  /**
   * VFTABLE: 0x00E0D7B4
   * COL: 0x00E67010
   */
  class CIntelGridSaveConstruct
  {
  public:
    /**
     * Address: 0x00507240 (FUN_00507240, CIntelGridSaveConstruct::SaveConstruct)
     *
     * What it does:
     * Forwards save-construct-args callback flow into
     * `CIntelGrid::MemberSaveConstructArgs`.
     */
    static void SaveConstruct(
      gpg::WriteArchive* archive,
      int objectPtr,
      int version,
      gpg::RRef* ownerRef,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x00507D60 (FUN_00507D60, Moho::CIntelGridSaveConstruct::RegisterSaveConstructArgsFunction)
     *
     * What it does:
     * Binds save-construct callback into CIntelGrid RTTI
     * (`serSaveConstructArgsFunc_`).
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc;
  };

  /**
   * VFTABLE: 0x00E0D7C4
   * COL: 0x00E66F64
   */
  class CIntelGridConstruct
  {
  public:
    /**
     * Address: 0x005073C0 (FUN_005073C0, Moho::CIntelGridConstruct::Construct)
     *
     * What it does:
     * Reads construct arguments (`STIMap*`, `mGridSize`) and returns a new
     * `CIntelGrid` as an unowned construct result.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x005089F0 (FUN_005089F0, Moho::CIntelGridConstruct::Deconstruct)
     *
     * What it does:
     * Destroys and frees one `CIntelGrid` object allocated via construct helper.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x00507DE0 (FUN_00507DE0, Moho::CIntelGridConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds construct/delete callbacks into CIntelGrid RTTI
     * (`serConstructFunc_`, `deleteFunc_`).
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::construct_func_t mSerConstructFunc;
    gpg::RType::delete_func_t mDeleteFunc;
  };

  /**
   * VFTABLE: 0x00E0D7D4
   * COL: 0x00E66EB8
   */
  class CIntelGridSerializer
  {
  public:
    /**
     * Address: 0x00507490 (FUN_00507490, Moho::CIntelGridSerializer::Deserialize)
     *
     * What it does:
     * Empty serializer load callback lane (binary `retn` stub).
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005074A0 (FUN_005074A0, Moho::CIntelGridSerializer::Serialize)
     *
     * What it does:
     * Empty serializer save callback lane (binary `retn` stub).
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00507E60 (FUN_00507E60, Moho::CIntelGridSerializer::RegisterSerializeFunctions)
     *
     * What it does:
     * Binds load/save callbacks into CIntelGrid RTTI
     * (`serLoadFunc_`, `serSaveFunc_`).
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  /**
   * VFTABLE: 0x00E0D784
   * COL: 0x00E670A8
   */
  class CIntelGridTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005070D0 (FUN_005070D0, Moho::CIntelGridTypeInfo::CIntelGridTypeInfo)
     *
     * What it does:
     * Constructs `CIntelGrid` type-info storage and preregisters RTTI mapping.
     */
    CIntelGridTypeInfo();

    /**
     * Address: 0x00507160 (FUN_00507160, gpg::RType::~RType thunk)
     * Slot: 2
     */
    ~CIntelGridTypeInfo() override;

    /**
     * Address: 0x00507150 (FUN_00507150, Moho::CIntelGridTypeInfo::GetName)
     * Slot: 3
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x00507130 (FUN_00507130, Moho::CIntelGridTypeInfo::Init)
     * Slot: 9
     */
    void Init() override;
  };

  static_assert(sizeof(CIntelGrid) == 0x24, "CIntelGrid size must be 0x24");
  static_assert(offsetof(CIntelGrid, mMapData) == 0x00, "CIntelGrid::mMapData offset must be 0x00");
  static_assert(offsetof(CIntelGrid, mGrid) == 0x04, "CIntelGrid::mGrid offset must be 0x04");
  static_assert(offsetof(CIntelGrid, mWidth) == 0x08, "CIntelGrid::mWidth offset must be 0x08");
  static_assert(offsetof(CIntelGrid, mHeight) == 0x0C, "CIntelGrid::mHeight offset must be 0x0C");
  static_assert(offsetof(CIntelGrid, mUpdateList) == 0x10, "CIntelGrid::mUpdateList offset must be 0x10");
  static_assert(offsetof(CIntelGrid, mGridSize) == 0x20, "CIntelGrid::mGridSize offset must be 0x20");

  static_assert(sizeof(CIntelGridSaveConstruct) == 0x10, "CIntelGridSaveConstruct size must be 0x10");
  static_assert(sizeof(CIntelGridConstruct) == 0x14, "CIntelGridConstruct size must be 0x14");
  static_assert(sizeof(CIntelGridSerializer) == 0x14, "CIntelGridSerializer size must be 0x14");
  static_assert(sizeof(CIntelGridTypeInfo) == 0x64, "CIntelGridTypeInfo size must be 0x64");

  /**
   * Address: 0x00BF1D90 (FUN_00BF1D90, cleanup_CIntelGridTypeInfo)
   *
   * What it does:
   * Releases startup `CIntelGridTypeInfo` field/base storage lanes.
   */
  void cleanup_CIntelGridTypeInfo();

  /**
   * Address: 0x00BF1DF0 (FUN_00BF1DF0, cleanup_CIntelGridSaveConstruct)
   *
   * What it does:
   * Unlinks startup `CIntelGridSaveConstruct` helper node.
   */
  gpg::SerHelperBase* cleanup_CIntelGridSaveConstruct();

  /**
   * Address: 0x00BF1E20 (FUN_00BF1E20, cleanup_CIntelGridConstruct)
   *
   * What it does:
   * Unlinks startup `CIntelGridConstruct` helper node.
   */
  gpg::SerHelperBase* cleanup_CIntelGridConstruct();

  /**
   * Address: 0x00BF1E50 (FUN_00BF1E50, cleanup_CIntelGridSerializer)
   *
   * What it does:
   * Unlinks startup `CIntelGridSerializer` helper node.
   */
  gpg::SerHelperBase* cleanup_CIntelGridSerializer();

  /**
   * Address: 0x00BC7920 (FUN_00BC7920, register_CIntelGridTypeInfo)
   *
   * What it does:
   * Forces startup construction for `CIntelGridTypeInfo` and installs `atexit`
   * cleanup.
   */
  void register_CIntelGridTypeInfo();

  /**
   * Address: 0x00BC7940 (FUN_00BC7940, register_CIntelGridSaveConstruct)
   *
   * What it does:
   * Initializes startup `CIntelGridSaveConstruct` callback lanes and installs
   * `atexit` cleanup.
   */
  void register_CIntelGridSaveConstruct();

  /**
   * Address: 0x00BC7970 (FUN_00BC7970, register_CIntelGridConstruct)
   *
   * What it does:
   * Initializes startup `CIntelGridConstruct` callback lanes and installs
   * `atexit` cleanup.
   */
  void register_CIntelGridConstruct();

  /**
   * Address: 0x00BC79B0 (FUN_00BC79B0, register_CIntelGridSerializer)
   *
   * What it does:
   * Initializes startup `CIntelGridSerializer` callback lanes and installs
   * `atexit` cleanup.
   */
  void register_CIntelGridSerializer();
} // namespace moho
