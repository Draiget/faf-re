#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "wm3/Vector3.h"

namespace gpg
{
  class SerSaveConstructArgsResult;
}

namespace moho
{
  class STIMap;

  struct SDelayedSubVizInfo
  {
    Wm3::Vec3f mLastPos;          // +0x00
    float mRadius;                // +0x0C
    std::int32_t mTicksTilUpdate; // +0x10
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
    /**
     * Address: 0x00507720 (FUN_00507720, ??0CIntelGrid@Moho@@QAE@PBVSTIMap@1@H@Z)
     *
     * What it does:
     * Binds map source, allocates byte coverage grid, and sets delayed-update
     * storage to empty.
     */
    CIntelGrid(const STIMap* map, std::uint32_t size);

    /**
     * Address: 0x005089F0 (FUN_005089F0, ??1CIntelGrid@Moho@@QAE@XZ)
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
     * Address: 0x00507D60 (FUN_00507D60, sub_507D60)
     *
     * What it does:
     * Binds save-construct callback into CIntelGrid RTTI
     * (`serSaveConstructArgsFunc_`).
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    void* mNext;
    void* mPrev;
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
     * Address: 0x00507DE0 (FUN_00507DE0, sub_507DE0)
     *
     * What it does:
     * Binds construct/delete callbacks into CIntelGrid RTTI
     * (`serConstructFunc_`, `deleteFunc_`).
     */
    virtual void RegisterConstructFunction();

  public:
    void* mNext;
    void* mPrev;
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
     * Address: 0x00507E60 (FUN_00507E60, sub_507E60)
     *
     * What it does:
     * Binds load/save callbacks into CIntelGrid RTTI
     * (`serLoadFunc_`, `serSaveFunc_`).
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
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
} // namespace moho
