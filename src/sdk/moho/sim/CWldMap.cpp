#include "CWldMap.h"

#include <cmath>
#include <cstddef>
#include <new>

#include "gpg/core/streams/BinaryReader.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/WldSessionInfo.h"

namespace
{
  constexpr float kQuaternionNormalizeEpsilon = 0.000001f;

  struct QuaternionLanes
  {
    float w;
    float x;
    float y;
    float z;
  };

  [[nodiscard]] QuaternionLanes QuaternionFromMatrixRows(const float matrix[3][3]) noexcept
  {
    QuaternionLanes out{1.0f, 0.0f, 0.0f, 0.0f};

    const float trace = matrix[0][0] + matrix[1][1] + matrix[2][2];
    if (trace > 0.0f) {
      const float s = std::sqrt(trace + 1.0f) * 2.0f;
      if (s > kQuaternionNormalizeEpsilon) {
        out.w = 0.25f * s;
        out.x = (matrix[2][1] - matrix[1][2]) / s;
        out.y = (matrix[0][2] - matrix[2][0]) / s;
        out.z = (matrix[1][0] - matrix[0][1]) / s;
      }
      return out;
    }

    if (matrix[0][0] > matrix[1][1] && matrix[0][0] > matrix[2][2]) {
      const float s = std::sqrt(1.0f + matrix[0][0] - matrix[1][1] - matrix[2][2]) * 2.0f;
      if (s > kQuaternionNormalizeEpsilon) {
        out.w = (matrix[2][1] - matrix[1][2]) / s;
        out.x = 0.25f * s;
        out.y = (matrix[0][1] + matrix[1][0]) / s;
        out.z = (matrix[0][2] + matrix[2][0]) / s;
      }
      return out;
    }

    if (matrix[1][1] > matrix[2][2]) {
      const float s = std::sqrt(1.0f + matrix[1][1] - matrix[0][0] - matrix[2][2]) * 2.0f;
      if (s > kQuaternionNormalizeEpsilon) {
        out.w = (matrix[0][2] - matrix[2][0]) / s;
        out.x = (matrix[0][1] + matrix[1][0]) / s;
        out.y = 0.25f * s;
        out.z = (matrix[1][2] + matrix[2][1]) / s;
      }
      return out;
    }

    const float s = std::sqrt(1.0f + matrix[2][2] - matrix[0][0] - matrix[1][1]) * 2.0f;
    if (s > kQuaternionNormalizeEpsilon) {
      out.w = (matrix[1][0] - matrix[0][1]) / s;
      out.x = (matrix[0][2] + matrix[2][0]) / s;
      out.y = (matrix[1][2] + matrix[2][1]) / s;
      out.z = 0.25f * s;
    }
    return out;
  }

  void NormalizeQuaternionLanes(QuaternionLanes& q) noexcept
  {
    const float magnitude =
      std::sqrt((q.w * q.w) + (q.x * q.x) + (q.y * q.y) + (q.z * q.z));
    if (magnitude <= kQuaternionNormalizeEpsilon) {
      q.w = 0.0f;
      q.x = 0.0f;
      q.y = 0.0f;
      q.z = 0.0f;
      return;
    }

    const float inverseMagnitude = 1.0f / magnitude;
    q.w *= inverseMagnitude;
    q.x *= inverseMagnitude;
    q.y *= inverseMagnitude;
    q.z *= inverseMagnitude;
  }

  void DestroyTerrainRes(moho::IWldTerrainRes* const terrainRes) noexcept
  {
    delete terrainRes;
  }

  void DestroyPreviewChunk(moho::RWldMapPreviewChunk* const chunk) noexcept
  {
    if (chunk == nullptr) {
      return;
    }

    chunk->~RWldMapPreviewChunk();
    operator delete(chunk);
  }

  void DestroyPropsEntry(moho::CWldPropEntry& entry) noexcept
  {
    entry.mBlueprintPath.tidy(true, 0U);
  }

  void DestroyPropsEntries(moho::CWldPropEntry* const begin, moho::CWldPropEntry* const end) noexcept
  {
    if (begin == nullptr || end == nullptr || end < begin) {
      return;
    }

    for (auto* entry = begin; entry != end; ++entry) {
      DestroyPropsEntry(*entry);
    }
  }

  void DestroyWldProps(moho::CWldProps* const props) noexcept
  {
    if (props == nullptr) {
      return;
    }

    if (props->mEntriesBegin != nullptr) {
      DestroyPropsEntries(props->mEntriesBegin, props->mEntriesEnd);
      operator delete(props->mEntriesBegin);
    }

    props->mEntriesBegin = nullptr;
    props->mEntriesEnd = nullptr;
    props->mEntriesCapacityEnd = nullptr;
    operator delete(props);
  }

  bool ResizeWldPropsEntries(moho::CWldProps& props, const std::uint32_t entryCount)
  {
    if (props.mEntriesBegin != nullptr) {
      DestroyPropsEntries(props.mEntriesBegin, props.mEntriesEnd);
      operator delete(props.mEntriesBegin);
    }

    props.mEntriesBegin = nullptr;
    props.mEntriesEnd = nullptr;
    props.mEntriesCapacityEnd = nullptr;

    if (entryCount == 0) {
      return true;
    }

    auto* const storage = static_cast<moho::CWldPropEntry*>(
      ::operator new(sizeof(moho::CWldPropEntry) * static_cast<std::size_t>(entryCount), std::nothrow)
    );
    if (storage == nullptr) {
      return false;
    }

    moho::CWldPropEntry* it = storage;
    try {
      for (; it != storage + entryCount; ++it) {
        new (it) moho::CWldPropEntry{};
        it->mBlueprintPath.tidy(false, 0U);
      }
    } catch (...) {
      DestroyPropsEntries(storage, it);
      operator delete(storage);
      throw;
    }

    props.mEntriesBegin = storage;
    props.mEntriesEnd = storage + entryCount;
    props.mEntriesCapacityEnd = storage + entryCount;
    return true;
  }

  /**
   * Address: 0x00891840 (FUN_00891840, sub_891840)
   *
   * What it does:
   * Packs one blueprint path plus seven transform lanes into a prop-entry
   * storage record.
   */
  moho::CWldPropEntry*
  PackWldPropEntry(moho::CWldPropEntry& outEntry, const float packedTransformLanes[7], const msvc8::string& path)
  {
    outEntry.mBlueprintPath.assign_owned(path.c_str());
    for (std::size_t i = 0; i < 7; ++i) {
      outEntry.mTransformData[i] = packedTransformLanes[i];
    }
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
    auto* const rawStorage = static_cast<CWldProps*>(::operator new(sizeof(CWldProps), std::nothrow));
    if (rawStorage == nullptr) {
      return nullptr;
    }

    rawStorage->mEntriesBegin = nullptr;
    rawStorage->mEntriesEnd = nullptr;
    rawStorage->mEntriesCapacityEnd = nullptr;
    return rawStorage;
  }

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

    if (!ResizeWldPropsEntries(*this, entryCount)) {
      return false;
    }

    for (std::uint32_t index = 0; index < entryCount; ++index) {
      msvc8::string blueprintPath;
      blueprintPath.tidy(false, 0U);
      reader.ReadString(&blueprintPath);

      float packedTransformLanes[7]{};
      reader.ReadExact(packedTransformLanes[4]);
      reader.ReadExact(packedTransformLanes[5]);
      reader.ReadExact(packedTransformLanes[6]);

      float matrix[3][3]{};
      matrix[0][0] = 1.0f;
      matrix[1][1] = 1.0f;
      matrix[2][2] = 1.0f;

      reader.ReadExact(matrix[0][0]);
      reader.ReadExact(matrix[0][1]);
      reader.ReadExact(matrix[0][2]);
      reader.ReadExact(matrix[1][0]);
      reader.ReadExact(matrix[1][1]);
      reader.ReadExact(matrix[1][2]);
      reader.ReadExact(matrix[2][0]);
      reader.ReadExact(matrix[2][1]);
      reader.ReadExact(matrix[2][2]);

      float ignoredLane0 = 0.0f;
      float ignoredLane1 = 0.0f;
      float ignoredLane2 = 0.0f;
      reader.ReadExact(ignoredLane0);
      reader.ReadExact(ignoredLane1);
      reader.ReadExact(ignoredLane2);

      QuaternionLanes orientation = QuaternionFromMatrixRows(matrix);
      NormalizeQuaternionLanes(orientation);

      packedTransformLanes[0] = orientation.w;
      packedTransformLanes[1] = orientation.x;
      packedTransformLanes[2] = orientation.y;
      packedTransformLanes[3] = orientation.z;

      PackWldPropEntry(mEntriesBegin[index], packedTransformLanes, blueprintPath);
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
   * Address: 0x0089E710 (FUN_0089E710, ?GetPlayableMapRect@IWldTerrainRes@Moho@@UBE?AV?$Rect2@H@gpg@@XZ)
   *
   * What it does:
   * Copies playable map bounds from terrain-res internal storage into `outRect`
   * and returns `&outRect`.
   */
  const VisibilityRect* IWldTerrainRes::GetPlayableMapRect(VisibilityRect& outRect) const
  {
    const TerrainPlayableRectSource* const source = mPlayableRectSource;
    outRect = source->mPlayableRect;
    return &outRect;
  }

  /**
   * Address: 0x00890CF0 (?Reset@CWldMap@Moho@@AAEXXZ)
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
    DestroyTerrainRes(terrainRes);

    CWldProps* const props = mProps;
    mProps = nullptr;
    DestroyWldProps(props);
  }

  /**
   * Address: 0x00890C70 (??1CWldMap@Moho@@QAE@XZ)
   *
   * What it does:
   * Performs standard map reset, then repeats guarded teardown checks matching
   * destructor epilogue behavior from the binary.
   */
  CWldMap::~CWldMap()
  {
    Reset();

    DestroyWldProps(mProps);
    DestroyTerrainRes(mTerrainRes);
    DestroyPreviewChunk(mMapPreviewChunk);
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
    if (fileMagic != 0x1A70614Du || fileVersion != 2u) {
      return false;
    }

    auto* const newPreviewChunk = new (std::nothrow) RWldMapPreviewChunk();
    RWldMapPreviewChunk* const previousPreviewChunk = mMapPreviewChunk;
    mMapPreviewChunk = newPreviewChunk;
    DestroyPreviewChunk(previousPreviewChunk);
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
    DestroyTerrainRes(previousTerrainRes);
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
} // namespace moho
