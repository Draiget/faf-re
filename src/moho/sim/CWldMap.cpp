#include "CWldMap.h"
#include "legacy/math/X87Math.h"
#include <cstdio>

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "gpg/core/containers/BitArray2D.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/BinaryWriter.h"
#include "gpg/core/streams/Stream.h"
#include "lua/LuaObject.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/Tree.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/math/Vector4f.h"
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/console/CVarAccess.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/WldSessionInfo.h"

namespace
{
  constexpr float kQuaternionNormalizeEpsilon = 0.000001f;

  /**
   * `.scmap` container header, written at 0x008911D2/0x008911DA by
   * `CWldMap::MapSave` and validated at 0x00890E81 by `CWldMap::MapLoad`.
   */
  constexpr std::uint32_t kWorldMapFileMagic = 0x1A70614DU; // 'Map' + 0x1A
  constexpr std::uint32_t kWorldMapFileVersion = 2U;

  /**
   * The two header lanes are staged adjacently on the stack at 0x008911D2 and
   * flushed by a single 8-byte `BinaryWriter::Write` (0x008915F0), so they are
   * modelled as one record rather than two separate scalar writes.
   */
  struct SWorldMapFileHeader
  {
    std::uint32_t mMagic;   // +0x00
    std::uint32_t mVersion; // +0x04
  };
  static_assert(offsetof(SWorldMapFileHeader, mVersion) == 0x04, "SWorldMapFileHeader::mVersion offset must be 0x04");
  static_assert(sizeof(SWorldMapFileHeader) == 0x08, "SWorldMapFileHeader size must be 0x08");


  struct TerrainNormalEncodeBlock
  {
    std::uint8_t mNormalX[16]{};
    std::uint8_t mNormalZ[16]{};
  };
  static_assert(sizeof(TerrainNormalEncodeBlock) == 0x20, "TerrainNormalEncodeBlock size must be 0x20");

  /**
   * Adopt a device-resources texture-sheet handle into the water-map slot.
   *
   * The binary (FUN_008A1700, water-map block) copies the returned handle's
   * `(sheet, count.pi_)` pair straight into `mWaterMapTexture`, reinterpreting
   * the `RD3DTextureResource*` payload as the same `CD3DDynamicTextureSheet`
   * object (they are the one DDS sheet, only modelled under two names). This
   * helper performs that identical refcount-preserving raw copy through the
   * SharedPtrRaw machinery so no open `{px,pi}` arithmetic leaks into Load.
   */
  void AdoptWaterMapSheetFromResource(
    boost::shared_ptr<moho::CD3DDynamicTextureSheet>& waterMap,
    const moho::ID3DDeviceResources::TextureResourceHandle& sheet
  ) noexcept
  {
    const boost::SharedPtrRaw<moho::RD3DTextureResource> sourceBorrow =
      boost::SharedPtrRawFromSharedBorrow(sheet);

    boost::SharedPtrRaw<moho::CD3DDynamicTextureSheet> reinterpreted{};
    reinterpreted.px = reinterpret_cast<moho::CD3DDynamicTextureSheet*>(sourceBorrow.px);
    reinterpreted.pi = sourceBorrow.pi;

    waterMap = boost::SharedPtrFromRawRetained(reinterpreted);
  }


  void AdoptDynamicSheetAsStratumMask(
    boost::SharedPtrRaw<moho::RD3DTextureResource>& mask,
    const boost::shared_ptr<moho::CD3DDynamicTextureSheet>& sheet
  ) noexcept
  {
    const boost::SharedPtrRaw<moho::CD3DDynamicTextureSheet> borrow =
      boost::SharedPtrRawFromSharedBorrow(sheet);

    boost::SharedPtrRaw<moho::RD3DTextureResource> reinterpreted{};
    reinterpreted.px = reinterpret_cast<moho::RD3DTextureResource*>(borrow.px);
    reinterpreted.pi = borrow.pi;
    mask.assign_retain(reinterpreted);
  }


  /**
   * Address: 0x008915F0 (FUN_008915F0, sub_8915F0)
   *
   * What it does:
   * Writes two contiguous 32-bit lanes to a binary writer in one 8-byte
   * payload.
   */
  void WriteBinaryWriterPairU32(gpg::BinaryWriter& writer, const std::uint32_t first, const std::uint32_t second)
  {
    const std::uint32_t pair[2]{first, second};
    writer.Write(reinterpret_cast<const char*>(pair), sizeof(pair));
  }


  /**
   * Address: 0x00891620 (FUN_00891620, sub_891620)
   *
   * What it does:
   * Destroys one owned preview chunk pointer and frees its allocation when
   * the pointer is non-null.
   */
  void DestroyPreviewChunk(moho::RWldMapPreviewChunk* const chunk) noexcept
  {
    if (chunk == nullptr) {
      return;
    }

    chunk->~RWldMapPreviewChunk();
    operator delete(chunk);
  }

  /**
   * Address: 0x00891680 (FUN_00891680)
   *
   * What it does:
   * Runs one `RWldMapPreviewChunk` teardown+free deleting path and returns the
   * original pointer lane.
   */
  [[maybe_unused]] moho::RWldMapPreviewChunk* DeletePreviewChunkAndReturn(
    moho::RWldMapPreviewChunk* const chunk
  ) noexcept
  {
    chunk->~RWldMapPreviewChunk();
    operator delete(chunk);
    return chunk;
  }

  /**
   * Address: 0x00891400 (FUN_00891400, sub_891400)
   *
   * What it does:
   * Replaces one preview-chunk owner slot and destroys/frees the previous
   * chunk when it exists.
   */
  void ReplaceOwnedPreviewChunk(
    moho::RWldMapPreviewChunk** const slot,
    moho::RWldMapPreviewChunk* const replacement
  ) noexcept
  {
    moho::RWldMapPreviewChunk* const previous = *slot;
    *slot = replacement;
    if (previous != nullptr) {
      previous->~RWldMapPreviewChunk();
      operator delete(previous);
    }
  }

  void DestroyWldProps(moho::CWldProps* const props) noexcept
  {
    delete props;
  }

  /**
   * Address: 0x008914C0 (FUN_008914C0)
   *
   * What it does:
   * Replaces one owned `CWldProps*` slot and destroys the previous object when
   * non-null.
   */
  [[maybe_unused]] moho::CWldProps** ReplaceOwnedWldPropsSlot(
    moho::CWldProps** const slot,
    moho::CWldProps* const replacement
  ) noexcept
  {
    moho::CWldProps* const previous = *slot;
    *slot = replacement;
    delete previous;
    return slot;
  }

  /**
   * Address: 0x00891650 (FUN_00891650)
   *
   * What it does:
   * Destroys one `CWldProps` owner lane when present and returns the original
   * pointer value.
   */
  [[maybe_unused]] moho::CWldProps* DestroyWldPropsIfPresent(moho::CWldProps* const props) noexcept
  {
    delete props;
    return props;
  }

  /**
   * Address: 0x008915C0 (FUN_008915C0)
   *
   * What it does:
   * Jump-only adapter lane that forwards directly to global `operator delete`.
   */
  [[maybe_unused]] void DeleteRawPointerLaneA(void* const pointer) noexcept
  {
    ::operator delete(pointer);
  }

  /**
   * Address: 0x008915D0 (FUN_008915D0)
   *
   * What it does:
   * Reads one little-endian signed 16-bit lane from a binary stream.
   */
  [[maybe_unused]] std::int16_t ReadSigned16Lane(gpg::BinaryReader* const reader)
  {
    std::int16_t value = 0;
    reader->Read(reinterpret_cast<char*>(&value), sizeof(value));
    return value;
  }

  /**
   * Address: 0x00891770 (FUN_00891770)
   *
   * What it does:
   * Clears one legacy string lane to empty state and returns zero.
   */
  [[maybe_unused]] int ClearLegacyStringAndReturnZero(msvc8::string* const value) noexcept
  {
    value->tidy(true, 0U);
    return 0;
  }

  /**
   * Address: 0x008917A0 (FUN_008917A0)
   *
   * What it does:
   * Clears one legacy string lane to empty state and returns the same pointer.
   */
  [[maybe_unused]] msvc8::string* ClearLegacyStringAndReturnSelf(msvc8::string* const value) noexcept
  {
    value->tidy(true, 0U);
    return value;
  }

  /**
   * Address: 0x00891D10 (FUN_00891D10)
   *
   * What it does:
   * Copy-assigns one world-prop entry lane (path string + packed transform).
   */
  [[maybe_unused]] moho::CWldPropEntry* CopyWldPropEntryLane(
    moho::CWldPropEntry* const destination,
    const moho::CWldPropEntry* const source
  )
  {
    destination->mBlueprintPath.assign(source->mBlueprintPath, 0u, msvc8::string::npos);
    destination->mTransform = source->mTransform;
    return destination;
  }

  /**
   * Address: 0x008513A0 (FUN_008513A0)
   *
   * What it does:
   * Runs `CWldMap` non-deleting destructor logic, then frees the heap storage
   * block that owns that map instance.
   */
  [[maybe_unused]] moho::CWldMap* DestroyAndDeleteWldMap(moho::CWldMap* const map) noexcept
  {
    if (map != nullptr) {
      map->~CWldMap();
      ::operator delete(static_cast<void*>(map));
    }
    return map;
  }

  /**
   * Address: 0x00886610 (FUN_00886610, sub_886610)
   *
   * What it does:
   * Transfers one CWldMap ownership lane from source auto_ptr slot into target
   * slot, deleting the previous target object when ownership changes.
   */
  [[maybe_unused]] moho::CWldMap** TransferAutoPtrCWldMapOwnership(
    moho::CWldMap** const sourceSlot,
    moho::CWldMap** const targetSlot
  ) noexcept
  {
    moho::CWldMap* const transferred = *sourceSlot;
    *sourceSlot = nullptr;

    moho::CWldMap* const targetValue = *targetSlot;
    if (transferred != targetValue && targetValue != nullptr) {
      (void)DestroyAndDeleteWldMap(targetValue);
    }

    *targetSlot = transferred;
    return targetSlot;
  }

  /**
   * Address: 0x0088E720 (FUN_0088E720, sub_88E720)
   *
   * What it does:
   * Transfers one STIMap ownership lane from source auto_ptr slot into target
   * slot, deleting the previous target map when ownership changes.
   */
  [[maybe_unused]] moho::STIMap** TransferAutoPtrSTIMapOwnership(
    moho::STIMap** const sourceSlot,
    moho::STIMap** const targetSlot
  ) noexcept
  {
    moho::STIMap* const transferred = *sourceSlot;
    *sourceSlot = nullptr;

    moho::STIMap* const targetValue = *targetSlot;
    if (transferred != targetValue && targetValue != nullptr) {
      targetValue->~STIMap();
      operator delete(targetValue);
    }

    *targetSlot = transferred;
    return targetSlot;
  }

  /**
   * Address: 0x00886500 (FUN_00886500, sub_886500)
   *
   * What it does:
   * Transfers one LuaState ownership lane from source auto_ptr slot into
   * target slot, deleting the previous target state when ownership changes.
   */
  [[maybe_unused]] LuaPlus::LuaState** TransferAutoPtrLuaStateOwnership(
    LuaPlus::LuaState** const sourceSlot,
    LuaPlus::LuaState** const targetSlot
  ) noexcept
  {
    LuaPlus::LuaState* const transferred = *sourceSlot;
    *sourceSlot = nullptr;

    LuaPlus::LuaState* const targetValue = *targetSlot;
    if (transferred != targetValue && targetValue != nullptr) {
      targetValue->~LuaState();
      operator delete(targetValue);
    }

    *targetSlot = transferred;
    return targetSlot;
  }

  /**
   * The record `CWldProps::Load` grows its vector with: an empty blueprint
   * path, an identity orientation and a zero position.
   */
  [[nodiscard]] moho::CWldPropEntry MakeDefaultWldPropEntry()
  {
    moho::CWldPropEntry defaultEntry{};
    defaultEntry.mBlueprintPath.tidy(false, 0U);
    defaultEntry.mTransform.orient_ = Wm3::Quatf{1.0f, 0.0f, 0.0f, 0.0f};
    defaultEntry.mTransform.pos_ = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
    return defaultEntry;
  }

  /**
   * Address: 0x00891840 (FUN_00891840, sub_891840)
   *
   * What it does:
   * Packs one blueprint path plus seven transform lanes into a prop-entry
   * storage record.
   */
  moho::CWldPropEntry*
  PackWldPropEntry(moho::CWldPropEntry& outEntry, const moho::VTransform& transform, const msvc8::string& path)
  {
    outEntry.mBlueprintPath.assign_owned(path.c_str());
    outEntry.mTransform = transform;
    return &outEntry;
  }

  void TickLoadingProgress(moho::CBackgroundTaskControl& loadControl)
  {
    if (loadControl.mHandle != nullptr) {
      loadControl.mHandle->UpdateLoadingProgress();
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00892210 (FUN_00892210, ?WLD_CreateProps@Moho@@YAPAVCWldProps@1@XZ)
   *
   * What it does:
   * Allocates one `CWldProps` object and initializes entry-storage pointer lanes
   * to null.
   */
  CWldProps* WLD_CreateProps()
  {
    return new (std::nothrow) CWldProps();
  }

  /**
   * Address: 0x00891330 (FUN_00891330,
   * ?WLD_LoadMapPreview@Moho@@YA?AV?$auto_ptr@VCWldMap@Moho@@@std@@VStrArg@gpg@@@Z)
   *
   * IDA signature:
   * std::auto_ptr<Moho::CWldMap> __thiscall Moho::WLD_LoadMapPreview(gpg::StrArg);
   *
   * What it does:
   * Heap-allocates one value-initialized `CWldMap` (zero-init of the three
   * owned pointer lanes), runs `MapLoad` in preview-only mode, and returns
   * the auto_ptr. When the load did not populate `mMapPreviewChunk` the map
   * is destroyed and the returned auto_ptr is empty.
   *
   * Callsite evidence (per CLAUDE.md callsite verification rule):
   *  - code xref from Moho::CUIMapPreview::SetTextureFromMap (FUN_008509A0) at 0x00850A25
   */
  msvc8::auto_ptr<CWldMap> WLD_LoadMapPreview(gpg::StrArg mapPath)
  {
    msvc8::auto_ptr<CWldMap> map(new CWldMap());

    CBackgroundTaskControl loadControl{};
    (void)map->MapLoad(mapPath, nullptr, true, loadControl);

    if (map->mMapPreviewChunk == nullptr) {
      map.reset();
    }

    return map;
  }


  /**
   * Address: 0x008A7B90 (FUN_008A7B90, ?WLD_CreateTerrainRes@Moho@@YAPAVIWldTerrainRes@1@XZ)
   * Mangled: ?WLD_CreateTerrainRes@Moho@@YAPAVIWldTerrainRes@1@XZ
   *
   * IDA signature:
   * Moho::CWldTerrainRes *__cdecl Moho::WLD_CreateTerrainRes();
   *
   * What it does:
   * Allocates and constructs one `CWldTerrainRes` (0xC38 bytes; the binary's
   * plain `operator new` and MSVC8's null check before the constructor
   * 0x008A0AD0), returned as the interface. Used by world-map load/new flows.
   *
   * Engine addition (dedicated-server plan WPL.4): the `CWldTerrainRes` is the
   * client's (moho/terrain/CWldTerrainRes.cpp sets sTerrainResFactory); without a
   * client the map loads into the headless resource.
   */
  IWldTerrainRes* WLD_CreateTerrainRes()
  {
    return sTerrainResFactory != nullptr ? sTerrainResFactory() : WLD_CreateHeadlessTerrainRes();
  }

  TerrainResFactoryHook sTerrainResFactory = nullptr;

  /**
   * Address: 0x008918E0 (FUN_008918E0,
   * ?Load@CWldProps@Moho@@QAE_NAAVBinaryReader@gpg@@AAVCBackgroundTaskControl@2@@Z)
   *
   * What it does:
   * Reads world-prop entries from stream, converts matrix orientation to a
   * normalized quaternion lane, and stores packed 7-float transform data for
   * each entry.
   */
  bool CWldProps::Load(gpg::BinaryReader& reader, CBackgroundTaskControl& loadControl)
  {
    (void)loadControl;

    std::uint32_t entryCount = 0;
    reader.ReadExact(entryCount);

    mEntries.resize(entryCount, MakeDefaultWldPropEntry());

    for (std::uint32_t index = 0; index < entryCount; ++index) {
      msvc8::string blueprintPath;
      blueprintPath.tidy(false, 0U);
      reader.ReadString(&blueprintPath);

      VTransform transform{};
      reader.ReadExact(transform.pos_.x);
      reader.ReadExact(transform.pos_.y);
      reader.ReadExact(transform.pos_.z);

      Wm3::Vector3f matrixRows[3]{};
      for (Wm3::Vector3f& row : matrixRows) {
        reader.ReadExact(row.x);
        reader.ReadExact(row.y);
        reader.ReadExact(row.z);
      }

      float ignoredLane0 = 0.0f;
      float ignoredLane1 = 0.0f;
      float ignoredLane2 = 0.0f;
      reader.ReadExact(ignoredLane0);
      reader.ReadExact(ignoredLane1);
      reader.ReadExact(ignoredLane2);

      MatrixToQuat(matrixRows, &transform.orient_);
      Wm3::Quatf& orientation = transform.orient_;
      // This map-loader normalization sums z/y/x/w, unlike the shared
      // NormalizeQuatInPlace path. Keep the original rounding order.
      const float magnitude = std::sqrt(
        ((orientation.z * orientation.z + orientation.y * orientation.y) + orientation.x * orientation.x)
        + orientation.w * orientation.w);
      if (magnitude > kQuaternionNormalizeEpsilon) {
        const float inverseMagnitude = 1.0f / magnitude;
        orientation.w *= inverseMagnitude;
        orientation.x *= inverseMagnitude;
        orientation.y *= inverseMagnitude;
        orientation.z *= inverseMagnitude;
      } else {
        orientation = Wm3::Quatf{0.0f, 0.0f, 0.0f, 0.0f};
      }

      PackWldPropEntry(mEntries[index], transform, blueprintPath);
    }

    return true;
  }

  /**
   * Address: 0x00891D50 (FUN_00891D50, ?Save@CWldProps@Moho@@QAE_NAAVBinaryWriter@gpg@@@Z)
   *
   * What it does:
   * Saves all prop entries as blueprint path + position + rotation matrix
   * lanes in the world-map binary format.
   */
  bool CWldProps::Save(gpg::BinaryWriter& writer) const
  {
    const auto propCount = static_cast<std::int32_t>(mEntries.size());
    writer.Write(propCount);

    for (std::int32_t index = 0; index < propCount; ++index) {
      const CWldPropEntry& entry = mEntries[static_cast<std::size_t>(index)];
      writer.Write(entry.mBlueprintPath.c_str(), entry.mBlueprintPath.size() + 1u);

      writer.Write(entry.mTransform.pos_.x);
      writer.Write(entry.mTransform.pos_.y);
      writer.Write(entry.mTransform.pos_.z);

      const VAxes3 matrix(entry.mTransform.orient_);
      writer.Write(matrix.vX.x);
      writer.Write(matrix.vX.y);
      writer.Write(matrix.vX.z);
      writer.Write(matrix.vY.x);
      writer.Write(matrix.vY.y);
      writer.Write(matrix.vY.z);
      writer.Write(matrix.vZ.x);
      writer.Write(matrix.vZ.y);
      writer.Write(matrix.vZ.z);

      constexpr float kScaleIdentity = 1.0f;
      writer.Write(kScaleIdentity);
      writer.Write(kScaleIdentity);
      writer.Write(kScaleIdentity);
    }

    return true;
  }

  /**
   * Address: 0x008902E0 (FUN_008902E0, ??0RWldMapPreviewChunk@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes preview texture ownership, preview size metadata, and preview name to
   * an empty state.
   */
  RWldMapPreviewChunk::RWldMapPreviewChunk()
    : mPreviewTexture()
    , mPreviewSize(0.0f, 0.0f)
    , mPreviewName()
  {
    mPreviewName.tidy(false, 0U);
  }

  /**
   * Address: 0x00890350 (FUN_00890350)
   * Mangled: ??0RWldMapPreviewChunk@Moho@@QAE@V?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@ABV?$Vector2@M@Wm3@@PBD@Z
   *
   * What it does:
   * Captures the provided texture-sheet handle, preview size, and preview
   * display name into this chunk.
   */
  RWldMapPreviewChunk::RWldMapPreviewChunk(
    boost::shared_ptr<ID3DTextureSheet> textureSheet, const Wm3::Vector2f& previewSize, const char* const previewName
  )
    : mPreviewTexture(textureSheet)
    , mPreviewSize(previewSize)
    , mPreviewName()
  {
    mPreviewName.tidy(false, 0U);
    mPreviewName.assign_owned(previewName);
  }

  /**
   * Address: 0x00890420 (FUN_00890420, ??1RWldMapPreviewChunk@Moho@@QAE@XZ)
   *
   * What it does:
   * Releases owned preview-name storage and drops preview texture ownership.
   */
  RWldMapPreviewChunk::~RWldMapPreviewChunk()
  {
    mPreviewName.tidy(true, 0U);
  }

  /**
   * Address: 0x00890480 (FUN_00890480, ?GetTextureSheet@RWldMapPreviewChunk@Moho@@QAE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
   *
   * What it does:
   * Returns one retained shared texture-sheet handle for this preview chunk.
   */
  boost::shared_ptr<ID3DTextureSheet> RWldMapPreviewChunk::GetTextureSheet()
  {
    return mPreviewTexture;
  }

  /**
   * Address: 0x008904A0 (FUN_008904A0, ?GetTerrainDim@RWldMapPreviewChunk@Moho@@QBE?AV?$Vector2@M@Wm3@@XZ)
   *
   * What it does:
   * Returns stored preview terrain dimensions.
   */
  Wm3::Vector2f RWldMapPreviewChunk::GetTerrainDim() const
  {
    return mPreviewSize;
  }

  /**
   * Address: 0x008904B0 (FUN_008904B0, ?GetDescription@RWldMapPreviewChunk@Moho@@QBEPBDXZ)
   *
   * What it does:
   * Returns preview description text buffer pointer.
   */
  const char* RWldMapPreviewChunk::GetDescription() const
  {
    return mPreviewName.c_str();
  }

  /**
   * Address: 0x008904C0 (FUN_008904C0,
   * ?Load@RWldMapPreviewChunk@Moho@@QAE_NAAVBinaryReader@gpg@@AAVCBackgroundTaskControl@2@@Z)
   *
   * What it does:
   * Loads optional preview metadata header (version/size/name), then loads the
   * remaining preview texture payload and resolves runtime texture ownership.
   */
  bool RWldMapPreviewChunk::Load(gpg::BinaryReader& reader, CBackgroundTaskControl& loadControl)
  {
    constexpr std::uint32_t kPreviewHeaderMagic = 0xBEEFFEEDU;

    gpg::Stream* const stream = reader.stream();
    std::uint32_t previewChunkVersion = 0U;

    std::uint32_t maybeMagic = 0U;
    reader.ReadExact(maybeMagic);

    if (maybeMagic == kPreviewHeaderMagic) {
      reader.ReadExact(previewChunkVersion);

      if (previewChunkVersion >= 1U) {
        reader.ReadExact(mPreviewSize.x);
        reader.ReadExact(mPreviewSize.y);

        std::wstring previewNameWide;
        while (true) {
          std::uint16_t wideChar = 0U;
          reader.ReadExact(wideChar);
          if (wideChar == 0U) {
            break;
          }
          previewNameWide.push_back(static_cast<wchar_t>(wideChar));
        }

        const msvc8::string previewNameUtf8 = gpg::STR_WideToUtf8(previewNameWide.c_str());
        mPreviewName.assign_owned(previewNameUtf8.c_str());

        std::uint32_t metadataEntryCount = 0U;
        reader.ReadExact(metadataEntryCount);
        for (std::uint32_t i = 0; i < metadataEntryCount; ++i) {
          std::uint32_t metadataTag = 0U;
          std::uint32_t metadataValue = 0U;
          reader.ReadExact(metadataTag);
          reader.ReadExact(metadataValue);
        }
      }
    } else {
      stream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginCurr, -4);
    }

    TickLoadingProgress(loadControl);

    const std::uint64_t payloadStart = stream->VirtTell(gpg::Stream::ModeReceive);
    const std::uint64_t payloadEnd = stream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginEnd, 0);
    stream->VirtSeek(gpg::Stream::ModeReceive, gpg::Stream::OriginBegin, static_cast<std::int64_t>(payloadStart));

    const std::size_t remainingBytes =
      payloadEnd >= payloadStart ? static_cast<std::size_t>(payloadEnd - payloadStart) : 0U;

    std::size_t payloadSize = remainingBytes;
    if (previewChunkVersion >= 2U) {
      std::uint32_t explicitPayloadSize = 0U;
      reader.ReadExact(explicitPayloadSize);
      payloadSize = static_cast<std::size_t>(explicitPayloadSize);
      if (payloadSize > remainingBytes) {
        return false;
      }
    }

    // Engine addition (dedicated-server plan WPL.4): the preview texture is the
    // client's (sPreviewTextureLoad, CWldMap.h): the device resources' texture
    // sheet `_mappreview.dds` from the payload, or the fallback texture when there
    // is none. Without a client the preview has no texture and still loads.
    if (payloadSize != 0U) {
      std::vector<char> payloadBytes(payloadSize);
      reader.Read(payloadBytes.data(), payloadBytes.size());

      TickLoadingProgress(loadControl);

      if (sPreviewTextureLoad == nullptr) {
        return true;
      }
      mPreviewTexture = sPreviewTextureLoad(payloadBytes.data(), payloadBytes.size());
    } else {
      if (sPreviewTextureLoad == nullptr) {
        return true;
      }
      mPreviewTexture = sPreviewTextureLoad(nullptr, 0U);
    }

    return mPreviewTexture.get() != nullptr;
  }

  PreviewTextureLoadHook sPreviewTextureLoad = nullptr;


  /**
   * What it does: see the header - resolves the active map's heightfield
   * through the terrain runtime view's `mMap` lane.
   */
  CHeightField* IWldTerrainRes::GetHeightField() const
  {
    return mMap->mHeightField.get();
  }

  /**
   * What it does: see the header - reads the active map's water-enabled flag
   * through the terrain runtime view's `mMap` lane.
   */
  bool IWldTerrainRes::IsWaterEnabled() const
  {
    return mMap->mWaterEnabled != 0;
  }

  /**
   * What it does: see the header - reads the active map's water elevation
   * through the terrain runtime view's `mMap` lane.
   */
  float IWldTerrainRes::GetWaterElevation() const
  {
    return mMap->mWaterElevation;
  }


  /**
   * Address: 0x00811210 (FUN_00811210, Moho::CWldTerrainRes::GetHeightAt)
   *
   * What it does:
   * Returns one clamped terrain height sample converted into world-space
   * height units (`heightWord * 1/128`).
   */
  float IWldTerrainRes::GetHeightAt(const std::int32_t x, const std::int32_t z) const
  {
    const CHeightField* const field = mMap->mHeightField.get();
    return static_cast<float>(field->GetHeightAt(x, z)) * 0.0078125f;
  }


  /**
   * Address: 0x008A74D0 (FUN_008A74D0, IWldTerrainRes ctor lane)
   *
   * What it does:
   * Initializes one terrain-resource interface base and clears playable-rect
   * source ownership to null.
   */
  IWldTerrainRes::IWldTerrainRes()
    : mMap(nullptr)
  {}

  /**
   * Address: 0x0089E870 (FUN_0089E870, IWldTerrainRes scalar-deleting destructor)
   *
   * What it does:
   * Releases the owned `mMap` before the base object is torn down.
   */
  IWldTerrainRes::~IWldTerrainRes()
  {
    delete mMap;
  }


  /**
   * Address: 0x008A0A20 (FUN_008A0A20, ??0struct_Env@@QAE@@Z)
   *
   * What it does:
   * Captures one environment lookup key plus one terrain texture resource
   * handle in one terrain environment entry object.
   */
  TerrainEnvironmentLookupEntry::TerrainEnvironmentLookupEntry(
    const msvc8::string& environmentName,
    boost::shared_ptr<RD3DTextureResource> texture
  )
  {
    mEnvironmentName.assign(environmentName, 0u, 0xFFFFFFFFu);
    mTexture = texture;
  }

  /**
   * Address: 0x00890CF0 (FUN_00890CF0, ?Reset@CWldMap@Moho@@AAEXXZ)
   *
   * What it does:
   * Releases preview chunk, terrain resource, and world props in-place and
   * nulls each owning pointer.
   */
  void CWldMap::Reset()
  {
    RWldMapPreviewChunk* const previewChunk = mMapPreviewChunk;
    mMapPreviewChunk = nullptr;
    DestroyPreviewChunk(previewChunk);

    IWldTerrainRes* const terrainRes = mTerrainRes;
    mTerrainRes = nullptr;
    delete terrainRes;

    CWldProps* const props = mProps;
    mProps = nullptr;
    DestroyWldProps(props);
  }

  /**
   * Address: 0x00890C70 (FUN_00890C70, ??1CWldMap@Moho@@QAE@XZ)
   *
   * What it does:
   * Performs standard map reset, then repeats guarded teardown checks matching
   * destructor epilogue behavior from the binary.
   */
  CWldMap::~CWldMap()
  {
    Reset();

    DestroyWldProps(mProps);
    delete mTerrainRes;
    DestroyPreviewChunk(mMapPreviewChunk);
  }

  /**
   * Address: 0x00890D40 (FUN_00890D40, ?MapNew@CWldMap@Moho@@QAE_NHHPAVLuaState@LuaPlus@@@Z)
   *
   * IDA signature:
   * char __usercall Moho::CWldMap::MapNew@<al>(Moho::CWldMap *this@<eax>,
   *     int width, int height, LuaPlus::LuaState *state);
   *
   * What it does:
   * Drops every currently owned map resource, then builds an empty chart of the
   * requested size: a fresh terrain resource reset to `width x height`
   * (0x00890D69 dispatches `IWldTerrainRes` vtable slot 23 = `Reset`) and a
   * fresh, empty prop set. The terrain `Reset` result is discarded and the
   * function unconditionally reports success (`0x00890D8E: mov al, 1`).
   */
  bool CWldMap::MapNew(const std::int32_t width, const std::int32_t height, LuaPlus::LuaState* const state)
  {
    Reset();

    // 0x00890D49-0x00890D5E: swap in the new terrain resource, destroy the old.
    IWldTerrainRes* const newTerrainRes = WLD_CreateTerrainRes();
    IWldTerrainRes* const previousTerrainRes = mTerrainRes;
    mTerrainRes = newTerrainRes;
    delete previousTerrainRes;

    // 0x00890D60-0x00890D77: the binary dereferences the freshly stored terrain
    // resource without a null check and ignores the returned status byte.
    const SChartSize chartSize{width, height};
    (void)mTerrainRes->Reset(chartSize, state);

    // 0x00890D79-0x00890D8C: same swap-then-destroy shape for the prop set.
    CWldProps* const newProps = WLD_CreateProps();
    CWldProps* const previousProps = mProps;
    mProps = newProps;
    DestroyWldProps(previousProps);

    return true;
  }

  /**
   * Address: 0x00890DA0 (FUN_00890DA0,
   * ?MapLoad@CWldMap@Moho@@QAE_NVStrArg@gpg@@PAVLuaState@LuaPlus@@_NAAVCBackgroundTaskControl@2@@Z)
   *
   * What it does:
   * Resets current world-map resources, opens map stream data, and loads
   * preview/terrain/props stages with background progress updates.
   */
  bool CWldMap::MapLoad(
    const gpg::StrArg mapName,
    LuaPlus::LuaState* const state,
    const bool previewOnly,
    CBackgroundTaskControl& loadControl
  )
  {
    Reset();

    msvc8::string resolvedPath;
    resolvedPath.tidy(false, 0U);
    const char* openPath = mapName != nullptr ? mapName : "";

    FWaitHandleSet* const waitHandleSet = FILE_GetWaitHandleSet();
    if (waitHandleSet != nullptr && waitHandleSet->mHandle != nullptr) {
      (void)waitHandleSet->mHandle->FindFile(&resolvedPath, openPath, nullptr);
      openPath = resolvedPath.c_str();
    }

    msvc8::auto_ptr<gpg::Stream> stream = DISK_OpenFileRead(openPath);
    if (!stream.get()) {
      return false;
    }

    gpg::BinaryReader reader(stream.get());
    TickLoadingProgress(loadControl);

    std::uint32_t fileMagic = 0;
    std::uint32_t fileVersion = 0;
    reader.ReadExact(fileMagic);
    reader.ReadExact(fileVersion);
    if (fileMagic != kWorldMapFileMagic || fileVersion != kWorldMapFileVersion) {
      return false;
    }

    auto* const newPreviewChunk = new (std::nothrow) RWldMapPreviewChunk();
    ReplaceOwnedPreviewChunk(&mMapPreviewChunk, newPreviewChunk);
    if (mMapPreviewChunk == nullptr || !mMapPreviewChunk->Load(reader, loadControl)) {
      return false;
    }

    if (previewOnly) {
      return true;
    }

    TickLoadingProgress(loadControl);
    IWldTerrainRes* const newTerrainRes = WLD_CreateTerrainRes();
    IWldTerrainRes* const previousTerrainRes = mTerrainRes;
    mTerrainRes = newTerrainRes;
    delete previousTerrainRes;
    if (mTerrainRes == nullptr || !mTerrainRes->Load(reader, state, loadControl)) {
      return false;
    }

    TickLoadingProgress(loadControl);
    CWldProps* const newProps = WLD_CreateProps();
    CWldProps* const previousProps = mProps;
    mProps = newProps;
    DestroyWldProps(previousProps);
    if (mProps == nullptr || !mProps->Load(reader, loadControl)) {
      return false;
    }

    return true;
  }


  /**
   * Address: 0x00891250 (FUN_00891250, ?MapSetPreview@CWldMap@Moho@@QAEXV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@ABV?$Vector2@M@Wm3@@PBD@Z)
   *
   * What it does:
   * Replaces the owned preview chunk with one built from the provided
   * texture/size/name lane and destroys any previous chunk.
   */
  void CWldMap::MapSetPreview(
    boost::shared_ptr<ID3DTextureSheet> textureSheet,
    const Wm3::Vector2f& previewSize,
    const char* const previewName
  )
  {
    auto* const newChunk = new (std::nothrow) RWldMapPreviewChunk(textureSheet, previewSize, previewName);
    ReplaceOwnedPreviewChunk(&mMapPreviewChunk, newChunk);
  }
} // namespace moho
