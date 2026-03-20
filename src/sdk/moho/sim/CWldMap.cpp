#include "CWldMap.h"

#include <cstddef>
#include <new>

namespace
{
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
} // namespace

namespace moho
{
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
} // namespace moho
