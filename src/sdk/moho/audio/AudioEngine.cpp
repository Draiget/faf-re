#include "moho/audio/AudioEngine.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>
#include <windows.h>
#include <mmreg.h>
#include <mmsystem.h>
#include <dsound.h>
#include <boost/ptr_container/exception.hpp>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/String.h"
#include "moho/audio/XAudioError.h"
#include "moho/app/CWaitHandleSet.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/camera/VTransform.h"

moho::SoundConfiguration* moho::sSoundConfiguration = nullptr;

extern "C" __declspec(dllimport) void __cdecl X3DAudioCalculate(
  const void* instance,
  const moho::Audio3DListener* listener,
  const moho::Audio3DEmitter* emitter,
  std::uint32_t flags,
  moho::Audio3DDspSettings* dspSettings
);
extern "C" __declspec(dllimport) void __cdecl X3DAudioInitialize(
  std::uint32_t speakerChannelMask,
  float speedOfSound,
  void* instance
);

namespace moho
{
  const char* func_SoundErrorCodeToMsg(int errorCode);
  int register_SoundConfigurationCleanupAtExit();
}

namespace
{
  /**
   * Address: 0x00BF0DB0 (FUN_00BF0DB0, sub_BF0DB0)
   *
   * What it does:
   * Deletes the process-global sound-configuration singleton when present.
   */
  void cleanup_SoundConfigurationSingleton()
  {
    if (moho::sSoundConfiguration == nullptr) {
      return;
    }

    delete moho::sSoundConfiguration;
    moho::sSoundConfiguration = nullptr;
  }
}

/**
 * Address: 0x00BC67C0 (FUN_00BC67C0, sub_BC67C0)
 *
 * What it does:
 * Registers process-exit cleanup for the global sound configuration singleton.
 */
int moho::register_SoundConfigurationCleanupAtExit()
{
  return std::atexit(&cleanup_SoundConfigurationSingleton);
}

/**
 * Address: 0x004DDD80 (FUN_004DDD80, boost::shared_ptr_AudioEngine::shared_ptr_AudioEngine)
 *
 * What it does:
 * Constructs one `shared_ptr<AudioEngine>` from one raw audio-engine pointer lane.
 */
boost::shared_ptr<moho::AudioEngine>* ConstructSharedAudioEngineFromRaw(
  boost::shared_ptr<moho::AudioEngine>* const outEngine,
  moho::AudioEngine* const engine
)
{
  return ::new (outEngine) boost::shared_ptr<moho::AudioEngine>(engine);
}

/**
 * Address: 0x004DE470 (FUN_004DE470)
 *
 * What it does:
 * Releases one contiguous range of `AudioEngineRef` control lanes.
 */
[[nodiscard]] std::uintptr_t ReleaseAudioEngineRefControlRange(
  moho::AudioEngineRef* const begin,
  moho::AudioEngineRef* const end
) noexcept
{
  std::uintptr_t lastControlAddress = 0u;
  if (begin == nullptr || end == nullptr) {
    return lastControlAddress;
  }

  for (moho::AudioEngineRef* entry = begin; entry != end; ++entry) {
    auto* const control = static_cast<boost::detail::sp_counted_base*>(entry->mControl);
    if (control == nullptr) {
      continue;
    }

    lastControlAddress = reinterpret_cast<std::uintptr_t>(control);
    control->release();
  }

  return lastControlAddress;
}

/**
 * Address: 0x004DE4C0 (FUN_004DE4C0)
 *
 * What it does:
 * Fills one destination `AudioEngineRef` range from one source pair and
 * retains the copied shared-control lane for each written element.
 */
void FillAudioEngineRefRangeFromSingleSource(
  std::int32_t count,
  moho::AudioEngineRef* destination,
  const moho::AudioEngineRef* const source
) noexcept
{
  for (; count > 0; --count, ++destination) {
    if (destination == nullptr) {
      continue;
    }

    destination->mEngine = source != nullptr ? source->mEngine : nullptr;
    destination->mControl = source != nullptr ? source->mControl : nullptr;

    auto* const control = static_cast<boost::detail::sp_counted_base*>(destination->mControl);
    if (control != nullptr) {
      control->add_ref_copy();
    }
  }
}

namespace
{
  struct SpCountedImplAudioEngineRuntimeView
  {
    void* mVftable;                         // +0x00
    std::int32_t mUseCount;                 // +0x04
    std::int32_t mWeakCount;                // +0x08
    moho::AudioEngineImpl** mOwnedSlot;     // +0x0C
  };

  static_assert(
    sizeof(SpCountedImplAudioEngineRuntimeView) == 0x10,
    "SpCountedImplAudioEngineRuntimeView size must be 0x10"
  );

  void DestroyAudioEngineImplOwnedSlotCore(moho::AudioEngineImpl** const ownedSlot) noexcept
  {
    if (ownedSlot == nullptr) {
      return;
    }

    moho::AudioEngineImpl* const impl = *ownedSlot;
    if (impl != nullptr) {
      impl->~AudioEngineImpl();
      operator delete(impl);
    }

    operator delete(ownedSlot);
  }
}

/**
 * Address: 0x004DE750 (FUN_004DE750)
 *
 * What it does:
 * Releases one `sp_counted_impl_p<AudioEngine>` owned slot by destroying the
 * pointed `AudioEngineImpl` and deleting the slot storage.
 */
void DestroyAudioEngineImplOwnedByCountedBlock(
  SpCountedImplAudioEngineRuntimeView* const countedBlock
) noexcept
{
  if (countedBlock == nullptr) {
    return;
  }

  DestroyAudioEngineImplOwnedSlotCore(countedBlock->mOwnedSlot);
}

/**
 * Address: 0x004DE7C0 (FUN_004DE7C0)
 *
 * What it does:
 * Destroys one heap-owned `AudioEngineImpl*` slot and its pointee.
 */
void DestroyAudioEngineImplOwnedSlot(
  moho::AudioEngineImpl** const ownedSlot
) noexcept
{
  DestroyAudioEngineImplOwnedSlotCore(ownedSlot);
}

/**
 * Address: 0x004DE650 (FUN_004DE650, ??0WeakPtr_AudioEngine@Moho@@QAE@@Z)
 * Mangled: ??0WeakPtr_AudioEngine@Moho@@QAE@@Z
 *
 * What it does:
 * Rebinds one audio-engine weak/shared pair from a source shared pair by
 * copying the pointee lane, retaining the incoming control lane, and
 * weak-releasing any previously bound control lane.
 */
boost::SharedCountPair* moho::AssignWeakAudioEnginePairFromShared(
  boost::SharedCountPair* const outWeakPair,
  const boost::SharedCountPair* const sourceSharedPair
) noexcept
{
  return boost::AssignWeakPairFromShared(outWeakPair, sourceSharedPair);
}

namespace
{
  struct AudioStartupCleanupRegistrations
  {
    AudioStartupCleanupRegistrations()
    {
      (void)moho::register_SoundConfigurationCleanupAtExit();
    }
  };

  [[maybe_unused]] AudioStartupCleanupRegistrations gAudioStartupCleanupRegistrations;
}

namespace
{
  constexpr int kXactErrCuePreparedOnly = static_cast<int>(0x8AC70008u);
  constexpr int kHresultPointer = static_cast<int>(0x80004003u);
  constexpr int kHresultFail = static_cast<int>(0x80004005u);
  constexpr std::uint32_t kX3dCalculateFlags = 0x61u;
  constexpr std::uint16_t kInvalidCategoryId = 0xFFFFu;
  constexpr std::uint16_t kInvalidVariableId = 0xFFFFu;
  constexpr float kDefaultCategoryVolume = 1.0f;
  constexpr const char* kGlobalCategoryName = "Global";

  struct AudioDistanceCurvePoint
  {
    float mDistance;
    float mDspSetting;
  };

  struct AudioDistanceCurve
  {
    const AudioDistanceCurvePoint* mPoints;
    std::uint32_t mPointCount;
  };

  constexpr std::array<AudioDistanceCurvePoint, 2> kDefaultDistanceCurvePoints = {
    AudioDistanceCurvePoint{0.0f, 1.0f},
    AudioDistanceCurvePoint{1.0f, 1.0f},
  };

  constexpr AudioDistanceCurve kDefaultDistanceCurve = {kDefaultDistanceCurvePoints.data(), 2u};

  constexpr std::array<float, 2> kDefaultAzimuths2 = {4.71238899f, 1.57079637f};
  constexpr std::array<float, 3> kDefaultAzimuths3 = {4.71238899f, 1.57079637f, 6.28318548f};
  constexpr std::array<float, 4> kDefaultAzimuths4 = {5.49778748f, 0.785398185f, 3.92699075f, 2.3561945f};
  constexpr std::array<float, 5> kDefaultAzimuths5 = {5.49778748f, 0.785398185f, 6.28318548f, 3.92699075f, 2.3561945f};
  constexpr std::array<float, 6> kDefaultAzimuths6 = {
    5.49778748f,
    0.785398185f,
    0.0f,
    6.28318548f,
    3.92699075f,
    2.3561945f,
  };
  constexpr std::array<float, 8> kDefaultAzimuths8 = {
    5.49778748f,
    0.785398185f,
    0.0f,
    6.28318548f,
    3.92699075f,
    2.3561945f,
    4.71238899f,
    1.57079637f,
  };

  struct AudioSoundBankLoader
  {
    gpg::MemBuffer<char> mBuffer; // +0x00
    moho::IXACTSoundBank* mBank;  // +0x10
    msvc8::string mName;          // +0x14
    moho::AudioEngineImpl* mEngine; // +0x30

    /**
     * Address: 0x004DA8E0 (FUN_004DA8E0, struct_SoundLoader::Load)
     *
     * gpg::StrArg
     *
     * What it does:
     * Resolves one sound-bank path, reads the bank bytes, creates an XACT
     * sound bank, and stores the base filename for diagnostics.
     */
    bool Load(gpg::StrArg soundBankPath);
  };
  static_assert(offsetof(AudioSoundBankLoader, mBuffer) == 0x00, "AudioSoundBankLoader::mBuffer offset must be 0x00");
  static_assert(offsetof(AudioSoundBankLoader, mBank) == 0x10, "AudioSoundBankLoader::mBank offset must be 0x10");
  static_assert(offsetof(AudioSoundBankLoader, mName) == 0x14, "AudioSoundBankLoader::mName offset must be 0x14");
  static_assert(offsetof(AudioSoundBankLoader, mEngine) == 0x30, "AudioSoundBankLoader::mEngine offset must be 0x30");
  static_assert(sizeof(AudioSoundBankLoader) == 0x34, "AudioSoundBankLoader size must be 0x34");

  class AudioStreamingWaveBankLoader;
  class AudioInMemoryWaveBankLoader;

  class AudioWaveBankLoaderBase
  {
  public:
    explicit AudioWaveBankLoaderBase(moho::AudioEngineImpl* const engine)
      : mWaveBank(nullptr)
      , mReserved08(0u)
      , mName()
      , mEngine(engine)
    {
    }

    virtual ~AudioWaveBankLoaderBase() = default;

    [[nodiscard]] virtual bool Load(gpg::StrArg waveBankPath) = 0;

    moho::IXACTWaveBank* mWaveBank; // +0x04
    std::uint32_t mReserved08;      // +0x08
    msvc8::string mName;            // +0x0C
    moho::AudioEngineImpl* mEngine; // +0x24
  };

  struct AudioWaveBankLoaderBaseRuntimeView
  {
    void* mVftable;                 // +0x00
    moho::IXACTWaveBank* mWaveBank; // +0x04
    std::uint32_t mReserved08;      // +0x08
    msvc8::string mName;            // +0x0C
    moho::AudioEngineImpl* mEngine; // +0x24
  };
  static_assert(
    sizeof(AudioWaveBankLoaderBaseRuntimeView) == sizeof(AudioWaveBankLoaderBase),
    "AudioWaveBankLoaderBaseRuntimeView size must match AudioWaveBankLoaderBase"
  );
  static_assert(
    offsetof(AudioWaveBankLoaderBaseRuntimeView, mWaveBank) == 0x04,
    "AudioWaveBankLoaderBaseRuntimeView::mWaveBank offset must be 0x04"
  );
  static_assert(
    offsetof(AudioWaveBankLoaderBaseRuntimeView, mName) == 0x0C,
    "AudioWaveBankLoaderBaseRuntimeView::mName offset must be 0x0C"
  );
  static_assert(
    offsetof(AudioWaveBankLoaderBaseRuntimeView, mEngine) == offsetof(AudioWaveBankLoaderBase, mEngine),
    "AudioWaveBankLoaderBaseRuntimeView::mEngine offset must match AudioWaveBankLoaderBase"
  );
  static_assert(
    sizeof(AudioWaveBankLoaderBase) == sizeof(AudioWaveBankLoaderBaseRuntimeView),
    "AudioWaveBankLoaderBase size must match AudioWaveBankLoaderBaseRuntimeView"
  );

  class AudioStreamingWaveBankLoader final : public AudioWaveBankLoaderBase
  {
  public:
    explicit AudioStreamingWaveBankLoader(moho::AudioEngineImpl* const engine)
      : AudioWaveBankLoaderBase(engine)
      , mFileHandle(INVALID_HANDLE_VALUE)
    {
    }

    ~AudioStreamingWaveBankLoader() override;

    /**
     * Address: 0x004DADF0 (FUN_004DADF0, Moho::RWaveBankResStreaming::LoadBank)
     *
     * gpg::StrArg
     *
     * What it does:
     * Resolves one streaming wave-bank path, opens its backing file handle,
     * creates one XACT streaming wave-bank instance, stores base-name metadata,
     * and registers the per-wavebank notification lane.
     */
    [[nodiscard]] bool Load(gpg::StrArg waveBankPath) override;

    HANDLE mFileHandle; // +0x28
  };

  struct AudioStreamingWaveBankLoaderRuntimeView
  {
    AudioWaveBankLoaderBaseRuntimeView mBase; // +0x00
    HANDLE mFileHandle;                       // +0x28
  };
  static_assert(
    offsetof(AudioStreamingWaveBankLoaderRuntimeView, mFileHandle) == offsetof(AudioStreamingWaveBankLoader, mFileHandle),
    "AudioStreamingWaveBankLoaderRuntimeView::mFileHandle offset must match AudioStreamingWaveBankLoader"
  );
  static_assert(
    sizeof(AudioStreamingWaveBankLoaderRuntimeView) == sizeof(AudioStreamingWaveBankLoader),
    "AudioStreamingWaveBankLoaderRuntimeView size must match AudioStreamingWaveBankLoader"
  );

  class AudioInMemoryWaveBankLoader final : public AudioWaveBankLoaderBase
  {
  public:
    explicit AudioInMemoryWaveBankLoader(moho::AudioEngineImpl* const engine)
      : AudioWaveBankLoaderBase(engine)
      , mMappedBuffer()
    {
    }

    ~AudioInMemoryWaveBankLoader() override;

    /**
     * Address: 0x004DAB70 (FUN_004DAB70, Moho::RWaveBankResInMemory::Load)
     *
     * gpg::StrArg
     *
     * What it does:
     * Memory-maps one wave-bank file into the resource-owned buffer, creates
     * one in-memory XACT wave-bank lane, and stores the base filename.
     */
    [[nodiscard]] bool Load(gpg::StrArg waveBankPath) override;

    gpg::MemBuffer<const char> mMappedBuffer; // +0x28
  };

  struct AudioInMemoryWaveBankLoaderRuntimeView
  {
    AudioWaveBankLoaderBaseRuntimeView mBase; // +0x00
    gpg::MemBuffer<const char> mMappedBuffer; // +0x28
  };
  static_assert(
    offsetof(AudioInMemoryWaveBankLoaderRuntimeView, mMappedBuffer) == offsetof(AudioInMemoryWaveBankLoader, mMappedBuffer),
    "AudioInMemoryWaveBankLoaderRuntimeView::mMappedBuffer offset must match AudioInMemoryWaveBankLoader"
  );
  static_assert(
    sizeof(AudioInMemoryWaveBankLoaderRuntimeView) == sizeof(AudioInMemoryWaveBankLoader),
    "AudioInMemoryWaveBankLoaderRuntimeView size must match AudioInMemoryWaveBankLoader"
  );

  struct AudioStreamingWaveBankCreateParams
  {
    HANDLE mFileHandle;        // +0x00
    std::uint32_t mOffset;     // +0x04
    std::uint32_t mReserved08; // +0x08
    std::uint16_t mPacketSize; // +0x0C
    std::uint16_t mReserved0E; // +0x0E
  };
  static_assert(
    offsetof(AudioStreamingWaveBankCreateParams, mPacketSize) == 0x0C,
    "AudioStreamingWaveBankCreateParams::mPacketSize offset must be 0x0C"
  );
  static_assert(sizeof(AudioStreamingWaveBankCreateParams) == 0x10, "AudioStreamingWaveBankCreateParams size must be 0x10");

  struct AudioCategoryVolumeNode
  {
    AudioCategoryVolumeNode* mLeft;   // +0x00
    AudioCategoryVolumeNode* mParent; // +0x04
    AudioCategoryVolumeNode* mRight;  // +0x08
    std::uint16_t mCategory;          // +0x0C
    std::uint16_t mPad0E;             // +0x0E
    float mVolume;                    // +0x10
    std::uint8_t mColor;              // +0x14
    std::uint8_t mIsNil;              // +0x15
    std::uint8_t mPad16[2];           // +0x16
  };
  static_assert(sizeof(AudioCategoryVolumeNode) == 0x18, "AudioCategoryVolumeNode size must be 0x18");

  struct AudioMap1CategoryNode
  {
    AudioMap1CategoryNode* mLeft;   // +0x00
    AudioMap1CategoryNode* mParent; // +0x04
    AudioMap1CategoryNode* mRight;  // +0x08
    msvc8::string mCategoryName;    // +0x0C
    std::uint8_t mColor;            // +0x28
    std::uint8_t mIsNil;            // +0x29
    std::uint8_t mPad2A[2];         // +0x2A
  };
  static_assert(sizeof(AudioMap1CategoryNode) == 0x2C, "AudioMap1CategoryNode size must be 0x2C");
  static_assert(
    offsetof(AudioMap1CategoryNode, mCategoryName) == 0x0C, "AudioMap1CategoryNode::mCategoryName offset must be 0x0C"
  );
  static_assert(offsetof(AudioMap1CategoryNode, mColor) == 0x28, "AudioMap1CategoryNode::mColor offset must be 0x28");
  static_assert(offsetof(AudioMap1CategoryNode, mIsNil) == 0x29, "AudioMap1CategoryNode::mIsNil offset must be 0x29");

  [[nodiscard]] bool IsCategoryArgValid(const gpg::StrArg category)
  {
    return category != nullptr && *category != '\0';
  }

  [[nodiscard]] AudioCategoryVolumeNode* AsCategoryMapHead(const moho::AudioMapStorage& map)
  {
    return static_cast<AudioCategoryVolumeNode*>(map.mHead);
  }

  void AdvanceCategoryIterator(AudioCategoryVolumeNode*& node) noexcept;
  [[nodiscard]] float* FindOrInsertCategoryVolume(moho::AudioMapStorage& map, std::uint16_t category);
  [[nodiscard]] AudioCategoryVolumeNode** EraseCategoryVolumeNodeAndStoreNext(
    moho::AudioMapStorage& map,
    AudioCategoryVolumeNode** outNext,
    AudioCategoryVolumeNode* eraseNode
  );

  template <typename Node>
  struct AudioMapInsertStatus
  {
    Node* mNode;
    std::uint8_t mInserted;
    std::uint8_t mPad05[3];
  };

  struct AudioCategoryLookupCursor
  {
    std::uint16_t mCategory;
    std::uint16_t mPad02;
    AudioCategoryVolumeNode* mNode;
  };

  /**
   * Address: 0x004DC250 (FUN_004DC250)
   *
   * What it does:
   * Stores one category-map node pointer plus insertion-status byte.
   */
  [[nodiscard]] AudioMapInsertStatus<AudioCategoryVolumeNode>* AssignCategoryInsertStatus(
    AudioMapInsertStatus<AudioCategoryVolumeNode>* const outResult,
    AudioCategoryVolumeNode* const node,
    const std::uint8_t inserted
  ) noexcept
  {
    outResult->mNode = node;
    outResult->mInserted = inserted;
    return outResult;
  }

  /**
   * Address: 0x004DC260 (FUN_004DC260)
   *
   * What it does:
   * Stores one pointer lane into one destination slot.
   */
  [[nodiscard]] void** StorePointerLaneA(void** const outSlot, void* const value) noexcept
  {
    *outSlot = value;
    return outSlot;
  }

  /**
   * Address: 0x004DC2A0 (FUN_004DC2A0)
   *
   * What it does:
   * Stores one pointer lane into one destination slot.
   */
  [[nodiscard]] void** StorePointerLaneB(void** const outSlot, void* const value) noexcept
  {
    *outSlot = value;
    return outSlot;
  }

  /**
   * Address: 0x004DC320 (FUN_004DC320)
   *
   * What it does:
   * Returns one pointer slot value and clears the slot to null.
   */
  [[nodiscard]] void* TakeAndClearPointerLaneA(void*& lane) noexcept
  {
    void* const previous = lane;
    lane = nullptr;
    return previous;
  }

  /**
   * Address: 0x004DC340 (FUN_004DC340)
   *
   * What it does:
   * Returns one pointer slot value and clears the slot to null.
   */
  [[nodiscard]] void* TakeAndClearPointerLaneB(void*& lane) noexcept
  {
    void* const previous = lane;
    lane = nullptr;
    return previous;
  }

  /**
   * Address: 0x004DC380 (FUN_004DC380)
   *
   * What it does:
   * Stores one category key plus one node lane into one lookup cursor.
   */
  [[nodiscard]] AudioCategoryLookupCursor* AssignCategoryLookupCursor(
    AudioCategoryLookupCursor* const outCursor,
    const std::uint16_t category,
    AudioCategoryVolumeNode* const node
  ) noexcept
  {
    outCursor->mCategory = category;
    outCursor->mPad02 = 0u;
    outCursor->mNode = node;
    return outCursor;
  }

  /**
   * Address: 0x004DC760 (FUN_004DC760)
   *
   * What it does:
   * Stores one map-head pointer lane from one `AudioMapStorage`.
   */
  [[nodiscard]] void** StoreMapHeadPointerA(void** const outHead, const moho::AudioMapStorage& map) noexcept
  {
    *outHead = map.mHead;
    return outHead;
  }

  /**
   * Address: 0x004DC770 (FUN_004DC770)
   *
   * What it does:
   * Stores one map-size lane from one `AudioMapStorage`.
   */
  [[nodiscard]] std::uint32_t* StoreMapSizeLaneA(std::uint32_t* const outSize, const moho::AudioMapStorage& map) noexcept
  {
    *outSize = map.mSize;
    return outSize;
  }

  /**
   * Address: 0x004DC7E0 (FUN_004DC7E0)
   *
   * What it does:
   * Stores one map-head pointer lane from one `AudioMapStorage`.
   */
  [[nodiscard]] void** StoreMapHeadPointerB(void** const outHead, const moho::AudioMapStorage& map) noexcept
  {
    *outHead = map.mHead;
    return outHead;
  }

  /**
   * Address: 0x004DC7F0 (FUN_004DC7F0)
   *
   * What it does:
   * Stores one map-size lane from one `AudioMapStorage`.
   */
  [[nodiscard]] std::uint32_t* StoreMapSizeLaneB(std::uint32_t* const outSize, const moho::AudioMapStorage& map) noexcept
  {
    *outSize = map.mSize;
    return outSize;
  }

  /**
   * Address: 0x004DC830 (FUN_004DC830)
   *
   * What it does:
   * Stores one map-head pointer lane from one `AudioMapStorage`.
   */
  [[nodiscard]] void** StoreMapHeadPointerC(void** const outHead, const moho::AudioMapStorage& map) noexcept
  {
    *outHead = map.mHead;
    return outHead;
  }

  /**
   * Address: 0x004DCDC0 (FUN_004DCDC0)
   *
   * What it does:
   * Stores the left-most tree lane from one non-null map head.
   */
  [[nodiscard]] void** StoreMapLeftmostPointer(void** const outNode, const moho::AudioMapStorage& map) noexcept
  {
    const auto* const head = AsCategoryMapHead(map);
    *outNode = head != nullptr ? static_cast<void*>(head->mLeft) : nullptr;
    return outNode;
  }

  /**
   * Address: 0x004DE120 (FUN_004DE120, func_newS6N)
   *
   * What it does:
   * Allocates one contiguous category-volume node array and throws
   * `std::bad_alloc` when multiplication overflows.
   */
  [[nodiscard]] AudioCategoryVolumeNode* AllocateCategoryNodeArrayChecked(const std::uint32_t count)
  {
    if (count != 0u && (std::numeric_limits<std::uint32_t>::max() / count) < sizeof(AudioCategoryVolumeNode)) {
      throw std::bad_alloc{};
    }

    return static_cast<AudioCategoryVolumeNode*>(operator new(sizeof(AudioCategoryVolumeNode) * count));
  }

  /**
   * Address: 0x004DDBA0 (FUN_004DDBA0)
   *
   * What it does:
   * Allocates raw storage for one category-volume node.
   */
  [[nodiscard]] AudioCategoryVolumeNode* AllocateSingleCategoryNodeRaw()
  {
    return AllocateCategoryNodeArrayChecked(1u);
  }

  /**
   * Address: 0x004DD8B0 (FUN_004DD8B0)
   *
   * What it does:
   * Allocates one zero-initialized category-volume node storage lane.
   */
  [[nodiscard]] AudioCategoryVolumeNode* AllocateCategoryVolumeNodeStorage()
  {
    auto* const node = ::new (AllocateSingleCategoryNodeRaw()) AudioCategoryVolumeNode{};
    node->mLeft = nullptr;
    node->mParent = nullptr;
    node->mRight = nullptr;
    node->mColor = 1u;
    node->mIsNil = 0u;
    return node;
  }

  /**
   * Address: 0x004DD8F0 (FUN_004DD8F0)
   *
   * What it does:
   * Allocates one category-volume node and initializes tree links plus payload
   * value lanes.
   */
  [[nodiscard]] AudioCategoryVolumeNode* ConstructCategoryVolumeNode(
    AudioCategoryVolumeNode* const left,
    AudioCategoryVolumeNode* const parent,
    AudioCategoryVolumeNode* const right,
    const std::uint16_t category,
    const float volume
  )
  {
    auto* const node = AllocateCategoryVolumeNodeStorage();
    node->mLeft = left;
    node->mParent = parent;
    node->mRight = right;
    node->mCategory = category;
    node->mPad0E = 0;
    node->mVolume = volume;
    node->mColor = 0u;
    node->mIsNil = 0u;
    node->mPad16[0] = 0;
    node->mPad16[1] = 0;
    return node;
  }

  /**
   * Address: 0x004DDB00 (FUN_004DDB00)
   *
   * What it does:
   * Recursively destroys one category-volume RB-tree subtree and frees each
   * node allocation.
   */
  void DestroyCategoryMapSubtree(AudioCategoryVolumeNode* node, const AudioCategoryVolumeNode* head)
  {
    if (node == nullptr || node == head || node->mIsNil != 0u) {
      return;
    }

    DestroyCategoryMapSubtree(node->mLeft, head);
    DestroyCategoryMapSubtree(node->mRight, head);
    delete node;
  }

  /**
   * Address: 0x004DCEA0 (FUN_004DCEA0)
   *
   * What it does:
   * Erases one half-open range from the category-volume map and returns the
   * post-erase iterator lane.
   */
  [[nodiscard]] AudioCategoryVolumeNode** EraseCategoryVolumeRange(
    moho::AudioMapStorage& map,
    AudioCategoryVolumeNode** const outNext,
    AudioCategoryVolumeNode* first,
    AudioCategoryVolumeNode* const last
  )
  {
    AudioCategoryVolumeNode* const head = AsCategoryMapHead(map);
    if (head == nullptr) {
      *outNext = first;
      return outNext;
    }

    if (first == head->mLeft && last == head) {
      DestroyCategoryMapSubtree(head->mParent, head);
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      map.mSize = 0u;
      *outNext = head->mLeft;
      return outNext;
    }

    AudioCategoryVolumeNode* cursor = first;
    if (cursor != last) {
      do {
        AudioCategoryVolumeNode* const eraseNode = cursor;
        if (cursor != nullptr && cursor->mIsNil == 0u) {
          AdvanceCategoryIterator(cursor);
        }

        AudioCategoryVolumeNode* throwaway = nullptr;
        (void)EraseCategoryVolumeNodeAndStoreNext(map, &throwaway, eraseNode);
      } while (cursor != last);
    }

    *outNext = cursor;
    return outNext;
  }

  /**
   * Address: 0x004DA250 (FUN_004DA250)
   *
   * What it does:
   * Releases one category-volume tree head/subtree pair and resets map lanes
   * to the empty state.
   */
  void ResetCategoryMap(moho::AudioMapStorage& map)
  {
    auto* const head = AsCategoryMapHead(map);
    if (head == nullptr) {
      map.mSize = 0;
      return;
    }

    AudioCategoryVolumeNode* next = nullptr;
    (void)EraseCategoryVolumeRange(map, &next, head->mLeft, head);
    delete head;
    map.mHead = nullptr;
    map.mSize = 0;
  }

  /**
   * Address: 0x004DB870 (FUN_004DB870)
   *
   * What it does:
   * Clears one category-volume map by erasing `[begin,end)` from the current
   * head, deleting the head node storage, and nulling the head/size lanes.
   */
  [[maybe_unused]] int ResetCategoryMapAlias(moho::AudioMapStorage& map)
  {
    AudioCategoryVolumeNode* const head = AsCategoryMapHead(map);
    AudioCategoryVolumeNode* next = nullptr;
    (void)EraseCategoryVolumeRange(map, &next, head->mLeft, head);
    operator delete(head);
    map.mHead = nullptr;
    map.mSize = 0u;
    return 0;
  }

  void InitCategoryMap(moho::AudioMapStorage& map)
  {
    map.mAllocatorCookie = nullptr;
    map.mSize = 0;

    auto* const head = AllocateCategoryVolumeNodeStorage();
    head->mLeft = head;
    head->mParent = head;
    head->mRight = head;
    head->mCategory = 0;
    head->mPad0E = 0;
    head->mVolume = kDefaultCategoryVolume;
    head->mColor = 1;
    head->mIsNil = 1;
    head->mPad16[0] = 0;
    head->mPad16[1] = 0;
    map.mHead = head;
  }

  /**
   * Address: 0x004DC080 (FUN_004DC080)
   *
   * What it does:
   * Resolves one category-volume node by key or inserts a defaulted node
   * (`1.0f`) into the category-volume RB-tree.
   */
  [[nodiscard]] AudioCategoryVolumeNode* FindOrInsertCategoryVolumeNode(
    moho::AudioMapStorage& map, const std::uint16_t category
  )
  {
    auto* head = AsCategoryMapHead(map);
    if (head == nullptr) {
      InitCategoryMap(map);
      head = AsCategoryMapHead(map);
    }

    AudioCategoryVolumeNode* parent = head;
    AudioCategoryVolumeNode* node = head->mParent;
    bool goLeft = true;

    while (node != nullptr && node != head && node->mIsNil == 0u) {
      parent = node;
      if (category < node->mCategory) {
        goLeft = true;
        node = node->mLeft;
      } else if (category > node->mCategory) {
        goLeft = false;
        node = node->mRight;
      } else {
        return node;
      }
    }

    auto* const inserted = ConstructCategoryVolumeNode(
      head,
      (parent == head) ? head : parent,
      head,
      category,
      kDefaultCategoryVolume
    );

    if (parent == head) {
      head->mParent = inserted;
      head->mLeft = inserted;
      head->mRight = inserted;
    } else if (goLeft) {
      parent->mLeft = inserted;
      if (head->mLeft == parent) {
        head->mLeft = inserted;
      }
    } else {
      parent->mRight = inserted;
      if (head->mRight == parent) {
        head->mRight = inserted;
      }
    }

    ++map.mSize;
    return inserted;
  }

  /**
   * Address: 0x004DB7E0 (FUN_004DB7E0)
   *
   * What it does:
   * Finds one category-volume slot by category id or inserts a defaulted slot
   * (`1.0f`) and returns its volume lane.
   */
  [[nodiscard]] float* FindOrInsertCategoryVolume(moho::AudioMapStorage& map, const std::uint16_t category)
  {
    AudioCategoryVolumeNode* const node = FindOrInsertCategoryVolumeNode(map, category);
    return node != nullptr ? &node->mVolume : nullptr;
  }

  [[nodiscard]] AudioCategoryVolumeNode*
  FindCategoryVolumeNode(const moho::AudioMapStorage& map, const std::uint16_t category) noexcept
  {
    AudioCategoryVolumeNode* const head = AsCategoryMapHead(map);
    if (head == nullptr) {
      return nullptr;
    }

    AudioCategoryVolumeNode* node = head->mParent;
    while (node != nullptr && node != head && node->mIsNil == 0u) {
      if (category < node->mCategory) {
        node = node->mLeft;
      } else if (category > node->mCategory) {
        node = node->mRight;
      } else {
        return node;
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x004DCDE0 (FUN_004DCDE0)
   *
   * What it does:
   * Resolves one category-map key to a node and reports whether a new node was
   * inserted.
   */
  [[nodiscard]] AudioMapInsertStatus<AudioCategoryVolumeNode>* FindOrInsertCategoryVolumeStatus(
    moho::AudioMapStorage& map,
    const std::uint16_t* const categoryKey,
    AudioMapInsertStatus<AudioCategoryVolumeNode>* const outResult
  )
  {
    if (categoryKey == nullptr || outResult == nullptr) {
      return outResult;
    }

    AudioCategoryVolumeNode* node = FindCategoryVolumeNode(map, *categoryKey);
    std::uint8_t inserted = 0u;
    if (node == nullptr) {
      node = FindOrInsertCategoryVolumeNode(map, *categoryKey);
      inserted = 1u;
    }

    return AssignCategoryInsertStatus(outResult, node, inserted);
  }

  [[nodiscard]] const float* FindCategoryVolume(const moho::AudioMapStorage& map, const std::uint16_t category)
  {
    const AudioCategoryVolumeNode* const node = FindCategoryVolumeNode(map, category);
    return node != nullptr ? &node->mVolume : nullptr;
  }

  /**
   * Address: 0x004DD800 (FUN_004DD800)
   *
   * What it does:
   * Performs one left-rotation around one category-volume RB-tree node.
   */
  [[nodiscard]] AudioCategoryVolumeNode*
  RotateCategoryVolumeNodeLeft(AudioCategoryVolumeNode* const node, moho::AudioMapStorage& map)
  {
    AudioCategoryVolumeNode* const pivot = node->mRight;
    node->mRight = pivot->mLeft;
    if (pivot->mLeft != nullptr && pivot->mLeft->mIsNil == 0u) {
      pivot->mLeft->mParent = node;
    }

    pivot->mParent = node->mParent;
    AudioCategoryVolumeNode* const head = AsCategoryMapHead(map);
    if (node == head->mParent) {
      head->mParent = pivot;
    } else {
      AudioCategoryVolumeNode* const parent = node->mParent;
      if (node == parent->mLeft) {
        parent->mLeft = pivot;
      } else {
        parent->mRight = pivot;
      }
    }

    pivot->mLeft = node;
    node->mParent = pivot;
    return pivot;
  }

  /**
   * Address: 0x004DD860 (FUN_004DD860)
   *
   * What it does:
   * Performs one right-rotation around one category-volume RB-tree node.
   */
  [[nodiscard]] AudioCategoryVolumeNode*
  RotateCategoryVolumeNodeRight(AudioCategoryVolumeNode* const node, moho::AudioMapStorage& map)
  {
    AudioCategoryVolumeNode* const pivot = node->mLeft;
    node->mLeft = pivot->mRight;
    if (pivot->mRight != nullptr && pivot->mRight->mIsNil == 0u) {
      pivot->mRight->mParent = node;
    }

    pivot->mParent = node->mParent;
    AudioCategoryVolumeNode* const head = AsCategoryMapHead(map);
    if (node == head->mParent) {
      head->mParent = pivot;
    } else {
      AudioCategoryVolumeNode* const parent = node->mParent;
      if (node == parent->mRight) {
        parent->mRight = pivot;
      } else {
        parent->mLeft = pivot;
      }
    }

    pivot->mRight = node;
    node->mParent = pivot;
    return pivot;
  }

  /**
   * Address: 0x004DDB40 (FUN_004DDB40)
   *
   * What it does:
   * Returns the right-most descendant from one category-volume tree node.
   */
  [[nodiscard]] AudioCategoryVolumeNode* RightmostCategoryDescendant(AudioCategoryVolumeNode* node) noexcept
  {
    while (node != nullptr && node->mRight != nullptr && node->mRight->mIsNil == 0u) {
      node = node->mRight;
    }
    return node;
  }

  /**
   * Address: 0x004DDB60 (FUN_004DDB60)
   *
   * What it does:
   * Returns the left-most descendant from one category-volume tree node.
   */
  [[nodiscard]] AudioCategoryVolumeNode* LeftmostCategoryDescendant(AudioCategoryVolumeNode* node) noexcept
  {
    while (node != nullptr && node->mLeft != nullptr && node->mLeft->mIsNil == 0u) {
      node = node->mLeft;
    }
    return node;
  }

  /**
   * Address: 0x004DDC30 (FUN_004DDC30)
   *
   * What it does:
   * Retreats one category-volume tree iterator to in-order predecessor.
   */
  void RetreatCategoryIterator(AudioCategoryVolumeNode*& node) noexcept
  {
    if (node == nullptr) {
      return;
    }

    if (node->mIsNil != 0u) {
      node = node->mRight;
      return;
    }

    AudioCategoryVolumeNode* prev = node->mLeft;
    if (prev != nullptr && prev->mIsNil == 0u) {
      prev = RightmostCategoryDescendant(prev);
      node = prev != nullptr ? prev : node;
      return;
    }

    AudioCategoryVolumeNode* parent = node->mParent;
    while (parent != nullptr && parent->mIsNil == 0u && node == parent->mLeft) {
      node = parent;
      parent = parent->mParent;
    }
    if (parent != nullptr) {
      node = parent;
    }
  }

  /**
   * Address: 0x004DDC90 (FUN_004DDC90)
   *
   * What it does:
   * Advances one category-volume tree iterator to in-order successor.
   */
  void AdvanceCategoryIterator(AudioCategoryVolumeNode*& node) noexcept
  {
    if (node == nullptr || node->mIsNil != 0u) {
      return;
    }

    AudioCategoryVolumeNode* next = node->mRight;
    if (next != nullptr && next->mIsNil == 0u) {
      next = LeftmostCategoryDescendant(next);
      node = next != nullptr ? next : node;
      return;
    }

    AudioCategoryVolumeNode* parent = node->mParent;
    while (parent != nullptr && parent->mIsNil == 0u && node == parent->mRight) {
      node = parent;
      parent = parent->mParent;
    }
    if (parent != nullptr) {
      node = parent;
    }
  }

  [[nodiscard]] bool IsCategoryMapSentinel(const AudioCategoryVolumeNode* const node) noexcept
  {
    return node == nullptr || node->mIsNil != 0u;
  }

  [[nodiscard]] bool IsCategoryNodeBlack(const AudioCategoryVolumeNode* const node) noexcept
  {
    return IsCategoryMapSentinel(node) || node->mColor != 0u;
  }

  [[nodiscard]] bool IsCategoryNodeRed(const AudioCategoryVolumeNode* const node) noexcept
  {
    return !IsCategoryNodeBlack(node);
  }

  void SetCategoryNodeBlack(AudioCategoryVolumeNode* const node) noexcept
  {
    if (!IsCategoryMapSentinel(node)) {
      node->mColor = 1u;
    }
  }

  void SetCategoryNodeRed(AudioCategoryVolumeNode* const node) noexcept
  {
    if (!IsCategoryMapSentinel(node)) {
      node->mColor = 0u;
    }
  }

  void SetCategoryNodeColor(AudioCategoryVolumeNode* const node, const std::uint8_t color) noexcept
  {
    if (!IsCategoryMapSentinel(node)) {
      node->mColor = color;
    }
  }

  [[nodiscard]] AudioCategoryVolumeNode* CategoryMapHead(const moho::AudioMapStorage& map) noexcept
  {
    return AsCategoryMapHead(map);
  }

  [[nodiscard]] AudioCategoryVolumeNode* CategoryMapRoot(const moho::AudioMapStorage& map) noexcept
  {
    AudioCategoryVolumeNode* const head = CategoryMapHead(map);
    if (IsCategoryMapSentinel(head)) {
      return head;
    }
    return head->mParent;
  }

  void TransplantCategoryNode(
    moho::AudioMapStorage& map,
    AudioCategoryVolumeNode* const replacedNode,
    AudioCategoryVolumeNode* const replacementNode
  ) noexcept
  {
    AudioCategoryVolumeNode* const head = CategoryMapHead(map);
    if (replacedNode->mParent == head) {
      head->mParent = replacementNode;
    } else if (replacedNode == replacedNode->mParent->mLeft) {
      replacedNode->mParent->mLeft = replacementNode;
    } else {
      replacedNode->mParent->mRight = replacementNode;
    }

    if (!IsCategoryMapSentinel(replacementNode)) {
      replacementNode->mParent = replacedNode->mParent;
    }
  }

  void RebuildCategoryMapHeadLinks(moho::AudioMapStorage& map) noexcept
  {
    AudioCategoryVolumeNode* const head = CategoryMapHead(map);
    if (IsCategoryMapSentinel(head)) {
      return;
    }

    AudioCategoryVolumeNode* root = head->mParent;
    if (IsCategoryMapSentinel(root)) {
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      return;
    }

    head->mParent = root;
    root->mParent = head;
    head->mLeft = LeftmostCategoryDescendant(root);
    head->mRight = RightmostCategoryDescendant(root);
  }

  void FixupCategoryMapAfterErase(
    moho::AudioMapStorage& map,
    AudioCategoryVolumeNode* node,
    AudioCategoryVolumeNode* parent
  ) noexcept
  {
    while (node != CategoryMapRoot(map) && IsCategoryNodeBlack(node)) {
      if (!IsCategoryMapSentinel(parent) && node == parent->mLeft) {
        AudioCategoryVolumeNode* sibling = parent->mRight;
        if (IsCategoryNodeRed(sibling)) {
          SetCategoryNodeBlack(sibling);
          SetCategoryNodeRed(parent);
          (void)RotateCategoryVolumeNodeLeft(parent, map);
          sibling = parent->mRight;
        }

        if (
          IsCategoryMapSentinel(sibling) ||
          (IsCategoryNodeBlack(sibling->mLeft) && IsCategoryNodeBlack(sibling->mRight))
        ) {
          SetCategoryNodeRed(sibling);
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsCategoryNodeBlack(sibling->mRight)) {
          SetCategoryNodeBlack(sibling->mLeft);
          SetCategoryNodeRed(sibling);
          (void)RotateCategoryVolumeNodeRight(sibling, map);
          sibling = parent->mRight;
        }

        SetCategoryNodeColor(sibling, parent->mColor);
        SetCategoryNodeBlack(parent);
        SetCategoryNodeBlack(sibling->mRight);
        (void)RotateCategoryVolumeNodeLeft(parent, map);
        node = CategoryMapRoot(map);
        parent = CategoryMapHead(map);
      } else {
        AudioCategoryVolumeNode* sibling = IsCategoryMapSentinel(parent) ? CategoryMapHead(map) : parent->mLeft;
        if (IsCategoryNodeRed(sibling)) {
          SetCategoryNodeBlack(sibling);
          SetCategoryNodeRed(parent);
          (void)RotateCategoryVolumeNodeRight(parent, map);
          sibling = parent->mLeft;
        }

        if (
          IsCategoryMapSentinel(sibling) ||
          (IsCategoryNodeBlack(sibling->mRight) && IsCategoryNodeBlack(sibling->mLeft))
        ) {
          SetCategoryNodeRed(sibling);
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsCategoryNodeBlack(sibling->mLeft)) {
          SetCategoryNodeBlack(sibling->mRight);
          SetCategoryNodeRed(sibling);
          (void)RotateCategoryVolumeNodeLeft(sibling, map);
          sibling = parent->mLeft;
        }

        SetCategoryNodeColor(sibling, parent->mColor);
        SetCategoryNodeBlack(parent);
        SetCategoryNodeBlack(sibling->mLeft);
        (void)RotateCategoryVolumeNodeRight(parent, map);
        node = CategoryMapRoot(map);
        parent = CategoryMapHead(map);
      }
    }

    SetCategoryNodeBlack(node);
  }

  /**
   * Address: 0x004DD510 (FUN_004DD510)
   *
   * What it does:
   * Erases one category-volume map iterator node, restores red-black tree
   * invariants, decrements map size, and stores the successor iterator lane.
   */
  [[nodiscard]] AudioCategoryVolumeNode** EraseCategoryVolumeNodeAndStoreNext(
    moho::AudioMapStorage& map,
    AudioCategoryVolumeNode** const outNext,
    AudioCategoryVolumeNode* const eraseNode
  )
  {
    if (IsCategoryMapSentinel(eraseNode)) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    AudioCategoryVolumeNode* nextNode = eraseNode;
    AdvanceCategoryIterator(nextNode);

    AudioCategoryVolumeNode* removedNode = eraseNode;
    AudioCategoryVolumeNode* fixupNode = CategoryMapHead(map);
    AudioCategoryVolumeNode* fixupParent = CategoryMapHead(map);
    bool removedNodeWasBlack = IsCategoryNodeBlack(removedNode);

    if (IsCategoryMapSentinel(eraseNode->mLeft)) {
      fixupNode = eraseNode->mRight;
      fixupParent = eraseNode->mParent;
      TransplantCategoryNode(map, eraseNode, eraseNode->mRight);
    } else if (IsCategoryMapSentinel(eraseNode->mRight)) {
      fixupNode = eraseNode->mLeft;
      fixupParent = eraseNode->mParent;
      TransplantCategoryNode(map, eraseNode, eraseNode->mLeft);
    } else {
      removedNode = LeftmostCategoryDescendant(eraseNode->mRight);
      removedNodeWasBlack = IsCategoryNodeBlack(removedNode);
      fixupNode = removedNode->mRight;

      if (removedNode->mParent == eraseNode) {
        fixupParent = removedNode;
      } else {
        fixupParent = removedNode->mParent;
        TransplantCategoryNode(map, removedNode, removedNode->mRight);
        removedNode->mRight = eraseNode->mRight;
        removedNode->mRight->mParent = removedNode;
      }

      TransplantCategoryNode(map, eraseNode, removedNode);
      removedNode->mLeft = eraseNode->mLeft;
      removedNode->mLeft->mParent = removedNode;
      std::swap(removedNode->mColor, eraseNode->mColor);
    }

    if (removedNodeWasBlack) {
      FixupCategoryMapAfterErase(map, fixupNode, fixupParent);
    }

    operator delete(eraseNode);
    if (map.mSize != 0u) {
      --map.mSize;
    }

    RebuildCategoryMapHeadLinks(map);
    *outNext = nextNode;
    return outNext;
  }

  [[nodiscard]] AudioSoundBankLoader* FindBankLoader(moho::AudioEngineImpl* impl, const std::uint16_t bankId)
  {
    if (impl == nullptr || impl->mBanks.mStart == nullptr || impl->mBanks.mFinish == nullptr) {
      return nullptr;
    }

    const std::size_t bankCount = static_cast<std::size_t>(impl->mBanks.mFinish - impl->mBanks.mStart);
    if (static_cast<std::size_t>(bankId) >= bankCount) {
      return nullptr;
    }

    return static_cast<AudioSoundBankLoader*>(impl->mBanks.mStart[bankId]);
  }

  [[nodiscard]] std::uint32_t ResolveDstChannelCount(const moho::SoundConfiguration* configuration)
  {
    if (configuration == nullptr) {
      return 2;
    }

    switch (configuration->mSpeakerConfiguration) {
    case 0x3F:
      return 6;
    case 0x0B:
      return 3;
    case 0xFF:
      return 7;
    case 0x03:
    case 0x33:
    case 0x107:
      return 2;
    default:
      gpg::Warnf("Invalid speaker configuration supplied: %i", configuration->mSpeakerConfiguration);
      return 2;
    }
  }

  /**
   * Address: 0x004DA8E0 (FUN_004DA8E0, struct_SoundLoader::Load)
   *
   * gpg::StrArg
   *
   * What it does:
   * Resolves one sound-bank path, reads the bank bytes, creates an XACT
   * sound bank, and stores the base filename for diagnostics.
   */
  bool AudioSoundBankLoader::Load(const gpg::StrArg soundBankPath)
  {
    moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
    msvc8::string mountedPath{};
    const msvc8::string* const resolvedPath = waitHandleSet->mHandle->FindFile(&mountedPath, soundBankPath, nullptr);

    mBuffer = moho::DISK_ReadFile(resolvedPath->c_str());
    if (mBuffer.mBegin == nullptr) {
      gpg::Warnf("Error loading soundbank '%s'", soundBankPath);
      return false;
    }

    const int createResult = mEngine->mInstance->CreateSoundBank(
      mBuffer.mBegin,
      static_cast<std::int32_t>(mBuffer.mEnd - mBuffer.mBegin),
      0u,
      0u,
      &mBank
    );
    if (createResult < 0) {
      gpg::Warnf("Error loading soundbank '%s': %s", soundBankPath, moho::func_SoundErrorCodeToMsg(createResult));
      return false;
    }

    mName = moho::FILE_Base(soundBankPath, true);
    gpg::Debugf("SND: Loaded SoundBank '%s'", mName.c_str());
    return true;
  }

#pragma pack(push, 1)
  struct AudioStreamingWaveBankNotificationDesc
  {
    std::uint8_t mType;         // +0x00
    std::uint32_t mWaveBankId;  // +0x01
    std::uint8_t mReserved[20]; // +0x05
  };
#pragma pack(pop)
  static_assert(
    offsetof(AudioStreamingWaveBankNotificationDesc, mWaveBankId) == 0x01,
    "AudioStreamingWaveBankNotificationDesc::mWaveBankId offset must be 0x01"
  );
  static_assert(sizeof(AudioStreamingWaveBankNotificationDesc) == 0x19, "AudioStreamingWaveBankNotificationDesc size must be 0x19");

  /**
   * Address: 0x004DADF0 (FUN_004DADF0, Moho::RWaveBankResStreaming::LoadBank)
   *
   * gpg::StrArg
   *
   * What it does:
   * Resolves one streaming wave-bank path, opens its backing file handle,
   * creates one XACT streaming wave-bank instance, stores base-name metadata,
   * and registers one wave-bank notification payload.
   */
  bool AudioStreamingWaveBankLoader::Load(const gpg::StrArg waveBankPath)
  {
    moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
    if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr || mEngine == nullptr || mEngine->mInstance == nullptr) {
      gpg::Warnf("Error loading WaveBank '%s'", waveBankPath);
      return false;
    }

    msvc8::string mountedPath{};
    const msvc8::string* const resolvedPath = waitHandleSet->mHandle->FindFile(&mountedPath, waveBankPath, nullptr);
    mFileHandle = ::CreateFileA(
      resolvedPath->c_str(),
      GENERIC_READ,
      FILE_SHARE_READ,
      nullptr,
      OPEN_EXISTING,
      0x60000000u,
      nullptr
    );
    if (mFileHandle == INVALID_HANDLE_VALUE) {
      gpg::Warnf("Error loading WaveBank '%s'", waveBankPath);
      return false;
    }

    AudioStreamingWaveBankCreateParams createParams{};
    createParams.mFileHandle = mFileHandle;
    createParams.mOffset = 0u;
    createParams.mReserved08 = 0u;
    createParams.mPacketSize = 0x12u;
    createParams.mReserved0E = 0u;

    const int createResult = mEngine->mInstance->CreateStreamingWaveBank(&createParams, &mWaveBank);
    if (createResult < 0) {
      gpg::Warnf("Error loading WaveBank '%s'", waveBankPath);
      return false;
    }

    mName = moho::FILE_Base(waveBankPath, true);

    AudioStreamingWaveBankNotificationDesc notification{};
    notification.mType = 17u;
    notification.mWaveBankId = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(mWaveBank));
    const int registerResult = mEngine->mInstance->RegisterNotification(&notification);
    if (registerResult < 0) {
      gpg::Warnf("SND: Error registering notification.\n%s", moho::func_SoundErrorCodeToMsg(registerResult));
    }

    gpg::Debugf("SND: Loaded WaveBank '%s' at %x", mName.c_str(), notification.mWaveBankId);
    return true;
  }

  /**
   * Address: 0x004DAB70 (FUN_004DAB70, Moho::RWaveBankResInMemory::Load)
   *
   * gpg::StrArg
   *
   * What it does:
   * Memory-maps one non-streaming wave-bank file, creates one in-memory XACT
   * wave-bank lane from the mapped bytes, and stores the base filename.
   */
  bool AudioInMemoryWaveBankLoader::Load(const gpg::StrArg waveBankPath)
  {
    moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
    if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr || mEngine == nullptr || mEngine->mInstance == nullptr) {
      return false;
    }

    msvc8::string mountedPath{};
    const msvc8::string* const resolvedPath = waitHandleSet->mHandle->FindFile(&mountedPath, waveBankPath, nullptr);
    mMappedBuffer = moho::DISK_MemoryMapFile(resolvedPath->c_str());
    if (mMappedBuffer.mBegin == nullptr) {
      return false;
    }

    const int createResult = mEngine->mInstance->CreateInMemoryWaveBank(
      mMappedBuffer.mBegin,
      static_cast<std::int32_t>(mMappedBuffer.mEnd - mMappedBuffer.mBegin),
      0u,
      0u,
      &mWaveBank
    );
    if (createResult < 0) {
      gpg::Warnf("Error loading WaveBank '%s': %s", waveBankPath, moho::func_SoundErrorCodeToMsg(createResult));
      return false;
    }

    mName = moho::FILE_Base(waveBankPath, true);
    gpg::Debugf(
      "SND: Loaded WaveBank '%s' at %x",
      mName.c_str(),
      static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(mWaveBank))
    );
    return true;
  }

  /**
   * Address: 0x004D8660 (FUN_004D8660, IsStreamingWaveBank)
   *
   * What it does:
   * Opens one resolved wave-bank file, reads the header and metadata lanes,
   * and returns whether the metadata streaming bit (`bit0`) is set.
   */
  [[maybe_unused]] [[nodiscard]] bool IsStreamingWaveBank(const gpg::StrArg waveBankPath)
  {
    moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
    if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr || waveBankPath == nullptr) {
      return false;
    }

    msvc8::string mountedPath{};
    const msvc8::string* const resolvedPath = waitHandleSet->mHandle->FindFile(&mountedPath, waveBankPath, nullptr);

    msvc8::auto_ptr<gpg::Stream> openedStream = moho::DISK_OpenFileRead(resolvedPath->c_str());
    gpg::Stream* const stream = openedStream.get();
    if (stream == nullptr) {
      return false;
    }

    gpg::BinaryReader reader(stream);

    std::array<std::uint32_t, 13> waveBankHeaderWords{};
    reader.ReadExactArray(waveBankHeaderWords.data(), waveBankHeaderWords.size());

    const std::uint32_t metadataOffset = waveBankHeaderWords[3];
    (void)stream->VirtSeek(
      gpg::Stream::ModeReceive,
      gpg::Stream::OriginBegin,
      static_cast<std::int64_t>(metadataOffset)
    );

    std::array<std::uint8_t, 0x60> metadata{};
    reader.ReadExactArray(metadata.data(), metadata.size());
    return (metadata[0] & 0x01u) != 0u;
  }

  [[nodiscard]] AudioMap1CategoryNode* AsMap1Head(const moho::AudioMapStorage& map)
  {
    return static_cast<AudioMap1CategoryNode*>(map.mHead);
  }

  /**
   * Address: 0x004DE060 (FUN_004DE060, func_NewS11N)
   *
   * What it does:
   * Allocates one contiguous paused-category node array and throws
   * `std::bad_alloc` when multiplication overflows.
   */
  [[nodiscard]] AudioMap1CategoryNode* AllocatePausedCategoryNodeArrayChecked(const std::uint32_t count)
  {
    if (count != 0u && (std::numeric_limits<std::uint32_t>::max() / count) < sizeof(AudioMap1CategoryNode)) {
      throw std::bad_alloc{};
    }

    return static_cast<AudioMap1CategoryNode*>(operator new(sizeof(AudioMap1CategoryNode) * count));
  }

  /**
   * Address: 0x004DD4B0 (FUN_004DD4B0)
   *
   * What it does:
   * Allocates raw storage for one paused-category node.
   */
  [[nodiscard]] AudioMap1CategoryNode* AllocateSinglePausedCategoryNodeRaw()
  {
    return AllocatePausedCategoryNodeArrayChecked(1u);
  }

  /**
   * Address: 0x004DCBE0 (FUN_004DCBE0)
   *
   * What it does:
   * Performs one left-rotation around one paused-category RB-tree node.
   */
  [[nodiscard]] AudioMap1CategoryNode* RotatePausedCategoryNodeLeft(AudioMap1CategoryNode* const node, moho::AudioMapStorage& map)
  {
    AudioMap1CategoryNode* const pivot = node->mRight;
    node->mRight = pivot->mLeft;
    if (pivot->mLeft != nullptr && pivot->mLeft->mIsNil == 0u) {
      pivot->mLeft->mParent = node;
    }

    pivot->mParent = node->mParent;
    AudioMap1CategoryNode* const head = AsMap1Head(map);
    if (node == head->mParent) {
      head->mParent = pivot;
    } else {
      AudioMap1CategoryNode* const parent = node->mParent;
      if (node == parent->mLeft) {
        parent->mLeft = pivot;
      } else {
        parent->mRight = pivot;
      }
    }

    pivot->mLeft = node;
    node->mParent = pivot;
    return pivot;
  }

  /**
   * Address: 0x004DCC40 (FUN_004DCC40)
   *
   * What it does:
   * Performs one right-rotation around one paused-category RB-tree node.
   */
  [[nodiscard]] AudioMap1CategoryNode* RotatePausedCategoryNodeRight(
    AudioMap1CategoryNode* const node, moho::AudioMapStorage& map
  )
  {
    AudioMap1CategoryNode* const pivot = node->mLeft;
    node->mLeft = pivot->mRight;
    if (pivot->mRight != nullptr && pivot->mRight->mIsNil == 0u) {
      pivot->mRight->mParent = node;
    }

    pivot->mParent = node->mParent;
    AudioMap1CategoryNode* const head = AsMap1Head(map);
    if (node == head->mParent) {
      head->mParent = pivot;
    } else {
      AudioMap1CategoryNode* const parent = node->mParent;
      if (node == parent->mRight) {
        parent->mRight = pivot;
      } else {
        parent->mLeft = pivot;
      }
    }

    pivot->mRight = node;
    node->mParent = pivot;
    return pivot;
  }

  /**
   * Address: 0x004DD460 (FUN_004DD460)
   *
   * What it does:
   * Allocates one zero-initialized paused-category node storage lane.
   */
  [[nodiscard]] AudioMap1CategoryNode* AllocatePausedCategoryNodeStorage()
  {
    auto* const node = ::new (AllocateSinglePausedCategoryNodeRaw()) AudioMap1CategoryNode{};
    node->mLeft = nullptr;
    node->mParent = nullptr;
    node->mRight = nullptr;
    node->mColor = 1u;
    node->mIsNil = 0u;
    return node;
  }

  /**
   * Address: 0x004DCC90 (FUN_004DCC90)
   *
   * What it does:
   * Allocates one paused-category node and copies link/key lanes into it.
   */
  [[nodiscard]] AudioMap1CategoryNode* ConstructPausedCategoryNode(
    AudioMap1CategoryNode* const left,
    AudioMap1CategoryNode* const parent,
    AudioMap1CategoryNode* const right,
    const char* const categoryName,
    const std::uint8_t color
  )
  {
    auto* const node = AllocatePausedCategoryNodeStorage();
    node->mLeft = left;
    node->mParent = parent;
    node->mRight = right;
    node->mCategoryName.assign_owned(categoryName != nullptr ? categoryName : "");
    node->mColor = color;
    node->mIsNil = 0u;
    node->mPad2A[0] = 0;
    node->mPad2A[1] = 0;
    return node;
  }

  /**
   * Address: 0x004DDAD0 (FUN_004DDAD0)
   *
   * What it does:
   * Stores one paused-category node pointer plus insertion-status byte.
   */
  [[nodiscard]] AudioMapInsertStatus<AudioMap1CategoryNode>* AssignPausedCategoryInsertStatus(
    AudioMapInsertStatus<AudioMap1CategoryNode>* const outResult,
    AudioMap1CategoryNode* const node,
    const std::uint8_t inserted
  ) noexcept
  {
    outResult->mNode = node;
    outResult->mInserted = inserted;
    return outResult;
  }

  [[nodiscard]] AudioMap1CategoryNode*
  FindMap1CategoryNode(const moho::AudioMapStorage& map, const char* const categoryName)
  {
    const AudioMap1CategoryNode* const head = AsMap1Head(map);
    if (head == nullptr || categoryName == nullptr) {
      return nullptr;
    }

    AudioMap1CategoryNode* node = head->mParent;
    while (node != nullptr && node != head && node->mIsNil == 0u) {
      const int compare = std::strcmp(categoryName, node->mCategoryName.c_str());
      if (compare < 0) {
        node = node->mLeft;
      } else if (compare > 0) {
        node = node->mRight;
      } else {
        return node;
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x004DD3D0 (FUN_004DD3D0)
   *
   * What it does:
   * Returns the right-most descendant from one paused-category tree node.
   */
  [[nodiscard]] AudioMap1CategoryNode* RightmostPausedDescendant(AudioMap1CategoryNode* node) noexcept
  {
    while (node != nullptr && node->mRight != nullptr && node->mRight->mIsNil == 0u) {
      node = node->mRight;
    }
    return node;
  }

  /**
   * Address: 0x004DD3F0 (FUN_004DD3F0)
   *
   * What it does:
   * Returns the left-most descendant from one paused-category tree node.
   */
  [[nodiscard]] AudioMap1CategoryNode* LeftmostPausedDescendant(AudioMap1CategoryNode* node) noexcept
  {
    while (node != nullptr && node->mLeft != nullptr && node->mLeft->mIsNil == 0u) {
      node = node->mLeft;
    }
    return node;
  }

  /**
   * Address: 0x004DD380 (FUN_004DD380)
   *
   * What it does:
   * Finds one lower-bound node for a paused-category name key.
   */
  [[nodiscard]] AudioMap1CategoryNode*
  LowerBoundPausedCategoryNode(const moho::AudioMapStorage& map, const char* const categoryName)
  {
    AudioMap1CategoryNode* const head = AsMap1Head(map);
    if (head == nullptr || categoryName == nullptr) {
      return nullptr;
    }

    AudioMap1CategoryNode* candidate = head;
    AudioMap1CategoryNode* node = head->mParent;
    while (node != nullptr && node != head && node->mIsNil == 0u) {
      if (std::strcmp(node->mCategoryName.c_str(), categoryName) >= 0) {
        candidate = node;
        node = node->mLeft;
      } else {
        node = node->mRight;
      }
    }

    return candidate;
  }

  /**
   * Address: 0x004DD410 (FUN_004DD410)
   *
   * What it does:
   * Finds one upper-bound node for a paused-category name key.
   */
  [[nodiscard]] AudioMap1CategoryNode*
  UpperBoundPausedCategoryNode(const moho::AudioMapStorage& map, const char* const categoryName)
  {
    AudioMap1CategoryNode* const head = AsMap1Head(map);
    if (head == nullptr || categoryName == nullptr) {
      return nullptr;
    }

    AudioMap1CategoryNode* candidate = head;
    AudioMap1CategoryNode* node = head->mParent;
    while (node != nullptr && node != head && node->mIsNil == 0u) {
      if (std::strcmp(categoryName, node->mCategoryName.c_str()) >= 0) {
        node = node->mRight;
      } else {
        candidate = node;
        node = node->mLeft;
      }
    }

    return candidate;
  }

  /**
   * Address: 0x004DDD30 (FUN_004DDD30)
   *
   * What it does:
   * Advances one paused-category tree iterator to in-order successor.
   */
  void AdvancePausedCategoryIterator(AudioMap1CategoryNode*& node) noexcept
  {
    if (node == nullptr || node->mIsNil != 0u) {
      return;
    }

    AudioMap1CategoryNode* next = node->mRight;
    if (next != nullptr && next->mIsNil == 0u) {
      next = LeftmostPausedDescendant(next);
      node = next != nullptr ? next : node;
      return;
    }

    AudioMap1CategoryNode* parent = node->mParent;
    while (parent != nullptr && parent->mIsNil == 0u && node == parent->mRight) {
      node = parent;
      parent = parent->mParent;
    }
    if (parent != nullptr) {
      node = parent;
    }
  }

  /**
   * Address: 0x004DD950 (FUN_004DD950)
   *
   * What it does:
   * Retreats one paused-category tree iterator to in-order predecessor.
   */
  void RetreatPausedCategoryIterator(AudioMap1CategoryNode*& node) noexcept
  {
    if (node == nullptr) {
      return;
    }

    if (node->mIsNil != 0u) {
      node = node->mRight;
      return;
    }

    AudioMap1CategoryNode* prev = node->mLeft;
    if (prev != nullptr && prev->mIsNil == 0u) {
      prev = RightmostPausedDescendant(prev);
      node = prev != nullptr ? prev : node;
      return;
    }

    AudioMap1CategoryNode* parent = node->mParent;
    while (parent != nullptr && parent->mIsNil == 0u && node == parent->mLeft) {
      node = parent;
      parent = parent->mParent;
    }
    if (parent != nullptr) {
      node = parent;
    }
  }

  /**
   * Address: 0x004DD320 (FUN_004DD320)
   *
   * What it does:
   * Recursively destroys one paused-category RB-tree subtree including string
   * payload lanes.
   */
  void DestroyMap1Subtree(AudioMap1CategoryNode* node, const AudioMap1CategoryNode* const head)
  {
    if (node == nullptr || node == head || node->mIsNil != 0u) {
      return;
    }

    DestroyMap1Subtree(node->mLeft, head);
    DestroyMap1Subtree(node->mRight, head);
    node->mCategoryName.tidy(true);
    delete node;
  }

  [[nodiscard]] bool IsPausedCategoryMapSentinel(const AudioMap1CategoryNode* const node) noexcept
  {
    return node == nullptr || node->mIsNil != 0u;
  }

  [[nodiscard]] bool IsPausedCategoryNodeBlack(const AudioMap1CategoryNode* const node) noexcept
  {
    return IsPausedCategoryMapSentinel(node) || node->mColor != 0u;
  }

  [[nodiscard]] bool IsPausedCategoryNodeRed(const AudioMap1CategoryNode* const node) noexcept
  {
    return !IsPausedCategoryNodeBlack(node);
  }

  void SetPausedCategoryNodeBlack(AudioMap1CategoryNode* const node) noexcept
  {
    if (!IsPausedCategoryMapSentinel(node)) {
      node->mColor = 1u;
    }
  }

  void SetPausedCategoryNodeRed(AudioMap1CategoryNode* const node) noexcept
  {
    if (!IsPausedCategoryMapSentinel(node)) {
      node->mColor = 0u;
    }
  }

  void SetPausedCategoryNodeColor(AudioMap1CategoryNode* const node, const std::uint8_t color) noexcept
  {
    if (!IsPausedCategoryMapSentinel(node)) {
      node->mColor = color;
    }
  }

  [[nodiscard]] AudioMap1CategoryNode* PausedCategoryMapHead(const moho::AudioMapStorage& map) noexcept
  {
    return AsMap1Head(map);
  }

  [[nodiscard]] AudioMap1CategoryNode* PausedCategoryMapRoot(const moho::AudioMapStorage& map) noexcept
  {
    AudioMap1CategoryNode* const head = PausedCategoryMapHead(map);
    if (IsPausedCategoryMapSentinel(head)) {
      return head;
    }
    return head->mParent;
  }

  void TransplantPausedCategoryNode(
    moho::AudioMapStorage& map,
    AudioMap1CategoryNode* const replacedNode,
    AudioMap1CategoryNode* const replacementNode
  ) noexcept
  {
    AudioMap1CategoryNode* const head = PausedCategoryMapHead(map);
    if (replacedNode->mParent == head) {
      head->mParent = replacementNode;
    } else if (replacedNode == replacedNode->mParent->mLeft) {
      replacedNode->mParent->mLeft = replacementNode;
    } else {
      replacedNode->mParent->mRight = replacementNode;
    }

    if (!IsPausedCategoryMapSentinel(replacementNode)) {
      replacementNode->mParent = replacedNode->mParent;
    }
  }

  void RebuildPausedCategoryMapHeadLinks(moho::AudioMapStorage& map) noexcept
  {
    AudioMap1CategoryNode* const head = PausedCategoryMapHead(map);
    if (IsPausedCategoryMapSentinel(head)) {
      return;
    }

    AudioMap1CategoryNode* root = head->mParent;
    if (IsPausedCategoryMapSentinel(root)) {
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      return;
    }

    head->mParent = root;
    root->mParent = head;
    head->mLeft = LeftmostPausedDescendant(root);
    head->mRight = RightmostPausedDescendant(root);
  }

  void FixupPausedCategoryMapAfterErase(
    moho::AudioMapStorage& map,
    AudioMap1CategoryNode* node,
    AudioMap1CategoryNode* parent
  ) noexcept
  {
    while (node != PausedCategoryMapRoot(map) && IsPausedCategoryNodeBlack(node)) {
      if (!IsPausedCategoryMapSentinel(parent) && node == parent->mLeft) {
        AudioMap1CategoryNode* sibling = parent->mRight;
        if (IsPausedCategoryNodeRed(sibling)) {
          SetPausedCategoryNodeBlack(sibling);
          SetPausedCategoryNodeRed(parent);
          (void)RotatePausedCategoryNodeLeft(parent, map);
          sibling = parent->mRight;
        }

        if (
          IsPausedCategoryMapSentinel(sibling) ||
          (IsPausedCategoryNodeBlack(sibling->mLeft) && IsPausedCategoryNodeBlack(sibling->mRight))
        ) {
          SetPausedCategoryNodeRed(sibling);
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsPausedCategoryNodeBlack(sibling->mRight)) {
          SetPausedCategoryNodeBlack(sibling->mLeft);
          SetPausedCategoryNodeRed(sibling);
          (void)RotatePausedCategoryNodeRight(sibling, map);
          sibling = parent->mRight;
        }

        SetPausedCategoryNodeColor(sibling, parent->mColor);
        SetPausedCategoryNodeBlack(parent);
        SetPausedCategoryNodeBlack(sibling->mRight);
        (void)RotatePausedCategoryNodeLeft(parent, map);
        node = PausedCategoryMapRoot(map);
        parent = PausedCategoryMapHead(map);
      } else {
        AudioMap1CategoryNode* sibling = IsPausedCategoryMapSentinel(parent) ? PausedCategoryMapHead(map) : parent->mLeft;
        if (IsPausedCategoryNodeRed(sibling)) {
          SetPausedCategoryNodeBlack(sibling);
          SetPausedCategoryNodeRed(parent);
          (void)RotatePausedCategoryNodeRight(parent, map);
          sibling = parent->mLeft;
        }

        if (
          IsPausedCategoryMapSentinel(sibling) ||
          (IsPausedCategoryNodeBlack(sibling->mRight) && IsPausedCategoryNodeBlack(sibling->mLeft))
        ) {
          SetPausedCategoryNodeRed(sibling);
          node = parent;
          parent = parent->mParent;
          continue;
        }

        if (IsPausedCategoryNodeBlack(sibling->mLeft)) {
          SetPausedCategoryNodeBlack(sibling->mRight);
          SetPausedCategoryNodeRed(sibling);
          (void)RotatePausedCategoryNodeLeft(sibling, map);
          sibling = parent->mLeft;
        }

        SetPausedCategoryNodeColor(sibling, parent->mColor);
        SetPausedCategoryNodeBlack(parent);
        SetPausedCategoryNodeBlack(sibling->mLeft);
        (void)RotatePausedCategoryNodeRight(parent, map);
        node = PausedCategoryMapRoot(map);
        parent = PausedCategoryMapHead(map);
      }
    }

    SetPausedCategoryNodeBlack(node);
  }

  /**
   * Address: 0x004DC850 (FUN_004DC850)
   *
   * What it does:
   * Erases one paused-category map iterator node, restores red-black tree
   * invariants, releases the node string payload, decrements map size, and
   * stores the successor iterator lane.
   */
  [[nodiscard]] AudioMap1CategoryNode** ErasePausedCategoryNodeAndStoreNext(
    moho::AudioMapStorage& map,
    AudioMap1CategoryNode** const outNext,
    AudioMap1CategoryNode* const eraseNode
  )
  {
    if (IsPausedCategoryMapSentinel(eraseNode)) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    AudioMap1CategoryNode* nextNode = eraseNode;
    AdvancePausedCategoryIterator(nextNode);

    AudioMap1CategoryNode* removedNode = eraseNode;
    AudioMap1CategoryNode* fixupNode = PausedCategoryMapHead(map);
    AudioMap1CategoryNode* fixupParent = PausedCategoryMapHead(map);
    bool removedNodeWasBlack = IsPausedCategoryNodeBlack(removedNode);

    if (IsPausedCategoryMapSentinel(eraseNode->mLeft)) {
      fixupNode = eraseNode->mRight;
      fixupParent = eraseNode->mParent;
      TransplantPausedCategoryNode(map, eraseNode, eraseNode->mRight);
    } else if (IsPausedCategoryMapSentinel(eraseNode->mRight)) {
      fixupNode = eraseNode->mLeft;
      fixupParent = eraseNode->mParent;
      TransplantPausedCategoryNode(map, eraseNode, eraseNode->mLeft);
    } else {
      removedNode = LeftmostPausedDescendant(eraseNode->mRight);
      removedNodeWasBlack = IsPausedCategoryNodeBlack(removedNode);
      fixupNode = removedNode->mRight;

      if (removedNode->mParent == eraseNode) {
        fixupParent = removedNode;
      } else {
        fixupParent = removedNode->mParent;
        TransplantPausedCategoryNode(map, removedNode, removedNode->mRight);
        removedNode->mRight = eraseNode->mRight;
        removedNode->mRight->mParent = removedNode;
      }

      TransplantPausedCategoryNode(map, eraseNode, removedNode);
      removedNode->mLeft = eraseNode->mLeft;
      removedNode->mLeft->mParent = removedNode;
      std::swap(removedNode->mColor, eraseNode->mColor);
    }

    if (removedNodeWasBlack) {
      FixupPausedCategoryMapAfterErase(map, fixupNode, fixupParent);
    }

    eraseNode->mCategoryName.tidy(true);
    operator delete(eraseNode);
    if (map.mSize != 0u) {
      --map.mSize;
    }

    RebuildPausedCategoryMapHeadLinks(map);
    *outNext = nextNode;
    return outNext;
  }

  /**
   * Address: 0x004DBD30 (FUN_004DBD30)
   *
   * What it does:
   * Erases one paused-category map half-open range `[first,last)` and stores
   * the post-erase iterator lane.
   */
  [[nodiscard]] AudioMap1CategoryNode** ErasePausedCategoryRangeAndStoreNext(
    moho::AudioMapStorage& map,
    AudioMap1CategoryNode** const outNext,
    AudioMap1CategoryNode* first,
    AudioMap1CategoryNode* const last
  )
  {
    AudioMap1CategoryNode* const head = AsMap1Head(map);
    if (head == nullptr) {
      *outNext = first;
      return outNext;
    }

    if (first == head->mLeft && last == head) {
      DestroyMap1Subtree(head->mParent, head);
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      map.mSize = 0u;
      *outNext = head->mLeft;
      return outNext;
    }

    AudioMap1CategoryNode* cursor = first;
    if (cursor != last) {
      do {
        AudioMap1CategoryNode* const eraseNode = cursor;
        if (!IsPausedCategoryMapSentinel(cursor)) {
          AdvancePausedCategoryIterator(cursor);
        }

        AudioMap1CategoryNode* throwaway = nullptr;
        (void)ErasePausedCategoryNodeAndStoreNext(map, &throwaway, eraseNode);
      } while (cursor != last);
    }

    *outNext = cursor;
    return outNext;
  }

  void RefreshMap1Bounds(AudioMap1CategoryNode* const head)
  {
    if (head == nullptr) {
      return;
    }

    AudioMap1CategoryNode* root = head->mParent;
    if (root == nullptr || root == head || root->mIsNil != 0u) {
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
      return;
    }

    AudioMap1CategoryNode* leftMost = root;
    while (leftMost->mLeft != nullptr && leftMost->mLeft != head && leftMost->mLeft->mIsNil == 0u) {
      leftMost = leftMost->mLeft;
    }

    AudioMap1CategoryNode* rightMost = root;
    while (rightMost->mRight != nullptr && rightMost->mRight != head && rightMost->mRight->mIsNil == 0u) {
      rightMost = rightMost->mRight;
    }

    head->mLeft = leftMost;
    head->mRight = rightMost;
  }

  void InitMap1Head(moho::AudioMapStorage& map)
  {
    map.mAllocatorCookie = nullptr;
    map.mSize = 0;

    auto* const head = AllocatePausedCategoryNodeStorage();
    head->mLeft = head;
    head->mParent = head;
    head->mRight = head;
    head->mCategoryName.clear();
    head->mColor = 1;
    head->mIsNil = 1;
    head->mPad2A[0] = 0;
    head->mPad2A[1] = 0;
    map.mHead = head;
  }

  [[nodiscard]] int ResetPausedCategoryMapStorageCore(moho::AudioMapStorage& map)
  {
    AudioMap1CategoryNode* const head = AsMap1Head(map);
    if (head == nullptr) {
      map.mSize = 0u;
      return 0;
    }

    AudioMap1CategoryNode* next = nullptr;
    (void)ErasePausedCategoryRangeAndStoreNext(map, &next, head->mLeft, head);
    operator delete(head);
    map.mHead = nullptr;
    map.mSize = 0u;
    return 0;
  }

  /**
   * Address: 0x004DA220 (FUN_004DA220)
   *
   * What it does:
   * Releases one paused-category tree head/subtree pair and resets map lanes
   * to the empty state.
   */
  void ResetMap1(moho::AudioMapStorage& map)
  {
    (void)ResetPausedCategoryMapStorageCore(map);
  }

  /**
   * Address: 0x004DB5D0 (FUN_004DB5D0)
   *
   * What it does:
   * Clears one paused-category map storage lane by erasing all RB-tree nodes,
   * deleting the head node storage, and nulling head/size lanes.
   */
  [[maybe_unused]] int ResetPausedCategoryMapStorageAliasA(moho::AudioMapStorage& map)
  {
    return ResetPausedCategoryMapStorageCore(map);
  }

  /**
   * Address: 0x004DBFF0 (FUN_004DBFF0)
   *
   * What it does:
   * Secondary paused-category map clear lane with the same erase+head-reset
   * semantics as `FUN_004DB5D0`.
   */
  [[maybe_unused]] int ResetPausedCategoryMapStorageAliasB(moho::AudioMapStorage& map)
  {
    return ResetPausedCategoryMapStorageCore(map);
  }

  /**
   * Address: 0x004DB600 (FUN_004DB600)
   *
   * What it does:
   * Inserts one paused-category name into the paused-category tree when absent.
   */
  [[nodiscard]] bool InsertPausedCategoryName(moho::AudioMapStorage& map, const char* const categoryName)
  {
    if (categoryName == nullptr || *categoryName == '\0') {
      return false;
    }

    AudioMap1CategoryNode* head = AsMap1Head(map);
    if (head == nullptr) {
      InitMap1Head(map);
      head = AsMap1Head(map);
    }

    AudioMap1CategoryNode* parent = head;
    AudioMap1CategoryNode* node = head->mParent;
    bool goLeft = true;

    while (node != nullptr && node != head && node->mIsNil == 0u) {
      parent = node;

      const int compare = std::strcmp(categoryName, node->mCategoryName.c_str());
      if (compare < 0) {
        goLeft = true;
        node = node->mLeft;
      } else if (compare > 0) {
        goLeft = false;
        node = node->mRight;
      } else {
        return false;
      }
    }

    auto* const inserted = ConstructPausedCategoryNode(
      head,
      (parent == head) ? head : parent,
      head,
      categoryName,
      0u
    );

    if (parent == head) {
      head->mParent = inserted;
    } else if (goLeft) {
      parent->mLeft = inserted;
    } else {
      parent->mRight = inserted;
    }

    ++map.mSize;
    RefreshMap1Bounds(head);
    return true;
  }

  void CollectRetainedPausedCategoryNames(
    const AudioMap1CategoryNode* node,
    const AudioMap1CategoryNode* const head,
    const char* const categoryToRemove,
    std::vector<std::string>& retainedNames
  )
  {
    if (node == nullptr || node == head || node->mIsNil != 0u) {
      return;
    }

    CollectRetainedPausedCategoryNames(node->mLeft, head, categoryToRemove, retainedNames);
    if (std::strcmp(node->mCategoryName.c_str(), categoryToRemove) != 0) {
      retainedNames.emplace_back(node->mCategoryName.c_str());
    }
    CollectRetainedPausedCategoryNames(node->mRight, head, categoryToRemove, retainedNames);
  }

  /**
   * Address: 0x004DB710 (FUN_004DB710)
   *
   * What it does:
   * Erases one paused-category name range resolved by lower/upper bound and
   * returns the number of erased entries.
   */
  [[nodiscard]] int ErasePausedCategoryName(moho::AudioMapStorage& map, const char* const categoryName)
  {
    if (categoryName == nullptr || *categoryName == '\0') {
      return 0;
    }

    AudioMap1CategoryNode* const upperBound = UpperBoundPausedCategoryNode(map, categoryName);
    AudioMap1CategoryNode* const lowerBound = LowerBoundPausedCategoryNode(map, categoryName);
    int erasedCount = 0;
    for (AudioMap1CategoryNode* cursor = lowerBound; cursor != upperBound; AdvancePausedCategoryIterator(cursor)) {
      ++erasedCount;
    }

    AudioMap1CategoryNode* next = nullptr;
    (void)ErasePausedCategoryRangeAndStoreNext(map, &next, lowerBound, upperBound);
    return erasedCount;
  }

  /**
   * Address: 0x004DB770 (FUN_004DB770)
   *
   * What it does:
   * Counts paused-category entries matching one category name.
   */
  [[nodiscard]] int CountPausedCategoryMatches(const moho::AudioMapStorage& map, const char* const categoryName)
  {
    if (categoryName == nullptr || *categoryName == '\0') {
      return 0;
    }

    AudioMap1CategoryNode* const endNode = AsMap1Head(map);
    if (endNode == nullptr) {
      return 0;
    }

    AudioMap1CategoryNode* node = LowerBoundPausedCategoryNode(map, categoryName);
    AudioMap1CategoryNode* const upper = UpperBoundPausedCategoryNode(map, categoryName);
    int count = 0;
    while (node != nullptr && node != endNode && node != upper) {
      ++count;
      AdvancePausedCategoryIterator(node);
    }
    return count;
  }

  [[nodiscard]] moho::SoundConfiguration* EnsureSoundConfigurationForCreate()
  {
    if (moho::sSoundConfiguration != nullptr) {
      return moho::sSoundConfiguration;
    }

    auto* const configuration = new moho::SoundConfiguration{};
    configuration->mEngines.mAllocatorCookie = nullptr;
    configuration->mEngines.mStart = nullptr;
    configuration->mEngines.mFinish = nullptr;
    configuration->mEngines.mCapacity = nullptr;
    configuration->mNoSound = 1u;
    configuration->mSpeakerConfiguration = 0x03u;
    configuration->mAudioRuntimeModule = nullptr;
    configuration->mLookAheadTimeMs = 250u;
    configuration->mGlobalSettingsStart = nullptr;
    configuration->mGlobalSettingsLength = 0u;
    configuration->mRuntimeFlags = 0u;
    configuration->mHandleSoundEvent = nullptr;
    configuration->mAudition = 0u;
    moho::sSoundConfiguration = configuration;
    return configuration;
  }

  /**
   * Address: 0x004DC230 (FUN_004DC230)
   *
   * What it does:
   * Atomically swaps the process-global `sSoundConfiguration` lane with the
   * caller-provided pointer slot.
   */
  void SwapSoundConfigurationSingletonPointer(moho::SoundConfiguration*& replacementOrOutPrevious) noexcept
  {
    moho::SoundConfiguration* const previous = moho::sSoundConfiguration;
    moho::sSoundConfiguration = replacementOrOutPrevious;
    replacementOrOutPrevious = previous;
  }

  /**
   * Address: 0x004DDFE0 (FUN_004DDFE0)
   *
   * What it does:
   * Allocates one contiguous array of 8-byte elements and raises
   * `std::bad_alloc` when element-count multiplication overflows.
   */
  [[nodiscard]] void* AllocateEightByteElementArrayChecked(const std::uint32_t elementCount)
  {
    if (elementCount != 0u && (std::numeric_limits<std::uint32_t>::max() / elementCount) < 8u) {
      throw std::bad_alloc{};
    }

    return operator new(static_cast<std::size_t>(elementCount) * 8u);
  }

  /**
   * Address: 0x004DD1E0 (FUN_004DD1E0)
   *
   * What it does:
   * Stores one pointer lane into one destination slot.
   */
  [[nodiscard]] void** StorePointerLaneC(void** const outSlot, void* const value) noexcept
  {
    *outSlot = value;
    return outSlot;
  }

  /**
   * Address: 0x004DD210 (FUN_004DD210)
   *
   * What it does:
   * Stores one `AudioEngineRef*` advanced by one element index.
   */
  [[nodiscard]] moho::AudioEngineRef** ComputeAudioEngineRefOffset(
    moho::AudioEngineRef** const outSlot,
    moho::AudioEngineRef* const* const base,
    const int index
  ) noexcept
  {
    *outSlot = *base + index;
    return outSlot;
  }

  /**
   * Address: 0x004DD230 (FUN_004DD230)
   *
   * What it does:
   * Stores one pointer lane into one destination slot.
   */
  [[nodiscard]] void** StorePointerLaneD(void** const outSlot, void* const value) noexcept
  {
    *outSlot = value;
    return outSlot;
  }

  /**
   * Address: 0x004DD290 (FUN_004DD290)
   *
   * What it does:
   * Copies one `AudioEngineRef` from engine/control source lanes.
   */
  [[nodiscard]] moho::AudioEngineRef* AssignAudioEngineRefLaneA(
    moho::AudioEngineRef* const outRef,
    moho::AudioEngine* const* const engineLane,
    void* const* const controlLane
  ) noexcept
  {
    outRef->mEngine = *engineLane;
    outRef->mControl = *controlLane;
    return outRef;
  }

  /**
   * Address: 0x004DD2A0 (FUN_004DD2A0)
   *
   * What it does:
   * Copies one `AudioEngineRef` from engine/control source lanes.
   */
  [[nodiscard]] moho::AudioEngineRef* AssignAudioEngineRefLaneB(
    moho::AudioEngineRef* const outRef,
    moho::AudioEngine* const* const engineLane,
    void* const* const controlLane
  ) noexcept
  {
    outRef->mEngine = *engineLane;
    outRef->mControl = *controlLane;
    return outRef;
  }

  /**
   * Address: 0x004DD2B0 (FUN_004DD2B0)
   *
   * What it does:
   * Clears one pointer lane to null.
   */
  [[nodiscard]] void** ZeroPointerLaneA(void** const outSlot) noexcept
  {
    *outSlot = nullptr;
    return outSlot;
  }

  /**
   * Address: 0x004DD2C0 (FUN_004DD2C0)
   *
   * What it does:
   * Stores one pointer lane into one destination slot.
   */
  [[nodiscard]] void** StorePointerLaneE(void** const outSlot, void* const value) noexcept
  {
    *outSlot = value;
    return outSlot;
  }

  /**
   * Address: 0x004DDA20 (FUN_004DDA20)
   *
   * What it does:
   * Clears one pointer lane to null.
   */
  [[nodiscard]] void** ZeroPointerLaneB(void** const outSlot) noexcept
  {
    *outSlot = nullptr;
    return outSlot;
  }

  /**
   * Address: 0x004DDA30 (FUN_004DDA30)
   *
   * What it does:
   * Stores one pointer lane into one destination slot.
   */
  [[nodiscard]] void** StorePointerLaneF(void** const outSlot, void* const value) noexcept
  {
    *outSlot = value;
    return outSlot;
  }

  /**
   * Address: 0x004DDA70 (FUN_004DDA70)
   *
   * What it does:
   * Stores one pointer lane into one destination slot.
   */
  [[nodiscard]] void** StorePointerLaneG(void** const outSlot, void* const value) noexcept
  {
    *outSlot = value;
    return outSlot;
  }

  /**
   * Address: 0x004DDA80 (FUN_004DDA80)
   *
   * What it does:
   * Stores one pointer lane into one destination slot.
   */
  [[nodiscard]] void** StorePointerLaneH(void** const outSlot, void* const value) noexcept
  {
    *outSlot = value;
    return outSlot;
  }

  /**
   * Address: 0x004DDDF0 (FUN_004DDDF0)
   *
   * What it does:
   * Stores one pointer lane into one destination slot.
   */
  [[nodiscard]] void** StorePointerLaneI(void** const outSlot, void* const value) noexcept
  {
    *outSlot = value;
    return outSlot;
  }

  /**
   * Address: 0x004DDE00 (FUN_004DDE00)
   *
   * What it does:
   * Stores one pointer lane into one destination slot.
   */
  [[nodiscard]] void** StorePointerLaneJ(void** const outSlot, void* const value) noexcept
  {
    *outSlot = value;
    return outSlot;
  }

  [[maybe_unused]] void ReserveEngineRefCapacity(moho::AudioEngineRefVector& engines, const std::size_t requiredCount)
  {
    const std::size_t currentCount =
      engines.mStart == nullptr || engines.mFinish == nullptr ? 0u : static_cast<std::size_t>(engines.mFinish - engines.mStart);
    const std::size_t currentCapacity = engines.mStart == nullptr || engines.mCapacity == nullptr
      ? 0u
      : static_cast<std::size_t>(engines.mCapacity - engines.mStart);
    if (requiredCount <= currentCapacity) {
      return;
    }

    const std::size_t targetCapacity = (std::max)(requiredCount, currentCapacity == 0u ? 4u : currentCapacity * 2u);
    if (targetCapacity > std::numeric_limits<std::uint32_t>::max()) {
      throw std::bad_alloc{};
    }

    auto* const newStorage = static_cast<moho::AudioEngineRef*>(
      AllocateEightByteElementArrayChecked(static_cast<std::uint32_t>(targetCapacity))
    );
    if (currentCount != 0u) {
      std::memcpy(newStorage, engines.mStart, currentCount * sizeof(moho::AudioEngineRef));
    }

    operator delete(engines.mStart);
    engines.mStart = newStorage;
    engines.mFinish = newStorage + currentCount;
    engines.mCapacity = newStorage + targetCapacity;
  }

  [[nodiscard]] const boost::SharedPtrLayoutView<moho::AudioEngine>&
  AsSharedLayout(const boost::shared_ptr<moho::AudioEngine>& value)
  {
    return *reinterpret_cast<const boost::SharedPtrLayoutView<moho::AudioEngine>*>(&value);
  }

  static_assert(sizeof(moho::AudioEngineRef) == sizeof(boost::SharedCountPair), "AudioEngineRef size must match SharedCountPair");

  [[nodiscard]] boost::SharedCountPair* AsSharedCountPair(moho::AudioEngineRef* const ref) noexcept
  {
    return reinterpret_cast<boost::SharedCountPair*>(ref);
  }

  [[nodiscard]] const boost::SharedCountPair* AsSharedCountPair(const moho::AudioEngineRef* const ref) noexcept
  {
    return reinterpret_cast<const boost::SharedCountPair*>(ref);
  }

  /**
   * Address: 0x004D9230 (FUN_004D9230)
   *
   * What it does:
   * Copies one `shared_ptr<AudioEngine>` layout from one stored engine-ref
   * lane and retains the shared control block when present.
   */
  [[nodiscard]] boost::shared_ptr<moho::AudioEngine> CopyEngineRefShared(const moho::AudioEngineRef& ref)
  {
    boost::shared_ptr<moho::AudioEngine> result;
    auto& view = *reinterpret_cast<boost::SharedPtrLayoutView<moho::AudioEngine>*>(&result);
    view.px = ref.mEngine;
    view.pi = static_cast<boost::detail::sp_counted_base*>(ref.mControl);
    if (view.pi != nullptr) {
      view.pi->add_ref_copy();
    }
    return result;
  }

  /**
   * Address: 0x004DC3B0 (FUN_004DC3B0)
   *
   * What it does:
   * Inserts one shared audio-engine pair at the requested vector position,
   * shifting existing lanes or reallocating storage as needed while preserving
   * shared-control retain/release semantics.
   */
  void InsertAudioEngineRefAt(
    moho::AudioEngineRefVector& refs,
    moho::AudioEngineRef* insertAt,
    const boost::shared_ptr<moho::AudioEngine>& engineRef
  )
  {
    constexpr std::size_t kMaxAudioEngineRefs = 0x1FFFFFFFu;

    const auto& incoming = AsSharedLayout(engineRef);
    struct SharedPairRetainGuard
    {
      boost::SharedCountPair value;
      ~SharedPairRetainGuard()
      {
        if (value.pi != nullptr) {
          value.pi->release();
        }
      }
    } retained{{incoming.px, incoming.pi}};
    if (retained.value.pi != nullptr) {
      retained.value.pi->add_ref_copy();
    }

    const std::size_t size =
      refs.mStart == nullptr || refs.mFinish == nullptr ? 0u : static_cast<std::size_t>(refs.mFinish - refs.mStart);
    const std::size_t capacity =
      refs.mStart == nullptr || refs.mCapacity == nullptr ? 0u : static_cast<std::size_t>(refs.mCapacity - refs.mStart);

    if (size >= kMaxAudioEngineRefs) {
      throw std::length_error("vector<T> too long");
    }

    std::size_t insertIndex = size;
    if (refs.mStart != nullptr && insertAt != nullptr) {
      insertIndex = static_cast<std::size_t>(insertAt - refs.mStart);
      if (insertIndex > size) {
        insertIndex = size;
      }
    }

    if (size < capacity && refs.mStart != nullptr) {
      moho::AudioEngineRef* const position = refs.mStart + insertIndex;
      if (position != refs.mFinish) {
        for (moho::AudioEngineRef* dst = refs.mFinish; dst != position; --dst) {
          moho::AudioEngineRef* const src = dst - 1;
          if (dst != refs.mFinish && dst->mControl != nullptr) {
            static_cast<boost::detail::sp_counted_base*>(dst->mControl)->release();
          }
          dst->mEngine = src->mEngine;
          dst->mControl = src->mControl;
          if (dst->mControl != nullptr) {
            static_cast<boost::detail::sp_counted_base*>(dst->mControl)->add_ref_copy();
          }
        }

        if (position->mControl != nullptr) {
          static_cast<boost::detail::sp_counted_base*>(position->mControl)->release();
        }
      }

      position->mEngine = static_cast<moho::AudioEngine*>(retained.value.px);
      position->mControl = retained.value.pi;
      if (position->mControl != nullptr) {
        static_cast<boost::detail::sp_counted_base*>(position->mControl)->add_ref_copy();
      }
      ++refs.mFinish;
      return;
    }

    std::size_t newCapacity = 0u;
    if (kMaxAudioEngineRefs - (capacity >> 1u) >= capacity) {
      newCapacity = capacity + (capacity >> 1u);
    }
    if (newCapacity < size + 1u) {
      newCapacity = size + 1u;
    }
    if (newCapacity > kMaxAudioEngineRefs) {
      throw std::length_error("vector<T> too long");
    }

    auto* const newStorage = static_cast<moho::AudioEngineRef*>(
      AllocateEightByteElementArrayChecked(static_cast<std::uint32_t>(newCapacity))
    );

    moho::AudioEngineRef* write = newStorage;
    for (std::size_t i = 0; i < insertIndex; ++i, ++write) {
      write->mEngine = refs.mStart[i].mEngine;
      write->mControl = refs.mStart[i].mControl;
      if (write->mControl != nullptr) {
        static_cast<boost::detail::sp_counted_base*>(write->mControl)->add_ref_copy();
      }
    }

    write->mEngine = static_cast<moho::AudioEngine*>(retained.value.px);
    write->mControl = retained.value.pi;
    if (write->mControl != nullptr) {
      static_cast<boost::detail::sp_counted_base*>(write->mControl)->add_ref_copy();
    }
    ++write;

    for (std::size_t i = insertIndex; i < size; ++i, ++write) {
      write->mEngine = refs.mStart[i].mEngine;
      write->mControl = refs.mStart[i].mControl;
      if (write->mControl != nullptr) {
        static_cast<boost::detail::sp_counted_base*>(write->mControl)->add_ref_copy();
      }
    }

    if (refs.mStart != nullptr) {
      (void)ReleaseAudioEngineRefControlRange(refs.mStart, refs.mFinish);
      operator delete(refs.mStart);
    }

    refs.mStart = newStorage;
    refs.mFinish = newStorage + size + 1u;
    refs.mCapacity = newStorage + newCapacity;
  }

  /**
   * Address: 0x004DB1D0 (FUN_004DB1D0)
   *
   * What it does:
   * Appends one shared engine reference into the global sound-configuration
   * engine vector, growing storage and retaining shared ownership as needed.
   */
  void RegisterEngineRef(
    moho::SoundConfiguration& configuration, const boost::shared_ptr<moho::AudioEngine>& engineRef
  )
  {
    const auto& engineLayout = AsSharedLayout(engineRef);
    if (engineLayout.px == nullptr) {
      return;
    }

    moho::AudioEngineRefVector& engines = configuration.mEngines;
    InsertAudioEngineRefAt(engines, engines.mFinish, engineRef);
  }

  /**
   * Address: 0x004DB240 (FUN_004DB240)
   *
   * What it does:
   * Erases one `AudioEngineRef` lane at `eraseAt` by shifting the tail
   * `[eraseAt + 1, mFinish)` left, releasing the final duplicated control lane,
   * decrementing `mFinish`, and returning/storing the next iterator lane.
   */
  [[maybe_unused]] [[nodiscard]] moho::AudioEngineRef** EraseAudioEngineRefAndStoreNext(
    moho::AudioEngineRefVector& refs,
    moho::AudioEngineRef** const outNext,
    moho::AudioEngineRef* const eraseAt
  )
  {
    const moho::AudioEngineRef* const oldFinish = refs.mFinish;
    boost::SharedCountPair* destination = AsSharedCountPair(eraseAt);
    const boost::SharedCountPair* source = AsSharedCountPair(eraseAt + 1);
    const boost::SharedCountPair* const sourceEnd = AsSharedCountPair(oldFinish);
    while (source != sourceEnd) {
      (void)boost::AssignSharedPairRetain(destination, source);
      ++destination;
      ++source;
    }

    (void)ReleaseAudioEngineRefControlRange(refs.mFinish - 1, refs.mFinish);
    refs.mFinish -= 1;
    *outNext = eraseAt;
    return outNext;
  }

  /**
   * Address: 0x004DB090 (FUN_004DB090)
   *
   * What it does:
   * Stores one replacement `AudioEngineImpl*` lane and destroys the previously
   * installed implementation object when present.
   */
  void ReplaceAudioEngineImplPointer(moho::AudioEngineImpl*& destination, moho::AudioEngineImpl* const replacement)
  {
    moho::AudioEngineImpl* const previous = destination;
    destination = replacement;
    if (previous == nullptr) {
      return;
    }

    previous->~AudioEngineImpl();
    operator delete(previous);
  }

  /**
   * Address: 0x004DB900 (FUN_004DB900)
   *
   * What it does:
   * Returns the process-global sound-configuration singleton lane.
   */
  [[nodiscard]] moho::SoundConfiguration* GetSoundConfigurationSingletonA() noexcept
  {
    return moho::sSoundConfiguration;
  }

  /**
   * Address: 0x004DB910 (FUN_004DB910)
   *
   * What it does:
   * Returns the process-global sound-configuration singleton lane.
   */
  [[nodiscard]] moho::SoundConfiguration* GetSoundConfigurationSingletonB() noexcept
  {
    return moho::sSoundConfiguration;
  }

  /**
   * Address: 0x004DA890 (FUN_004DA890)
   *
   * What it does:
   * Applies one mute/unmute transition for the `"Global"` category on one
   * active engine implementation and stores/restores the cached global volume.
   */
  void ApplyGlobalMuteToEngine(moho::AudioEngineImpl& impl, const bool doMute)
  {
    if (impl.mInstance == nullptr || impl.mEngine == nullptr) {
      return;
    }

    const float volume = doMute ? (impl.mGlobalCategoryVolume = impl.mEngine->GetVolume(kGlobalCategoryName), 0.0f)
                                : impl.mGlobalCategoryVolume;
    impl.mEngine->SetVolume(kGlobalCategoryName, volume);
  }

  /**
   * Address: 0x004DAAC0 (FUN_004DAAC0)
   *
   * What it does:
   * Tears down one `AudioSoundBankLoader` payload in place: destroys the
   * active XACT sound-bank lane, resets the filename string to empty SSO
   * state, and releases the shared mem-buffer control lane.
   */
  void DestroyAudioSoundBankLoaderNoDelete(AudioSoundBankLoader* const loader) noexcept
  {
    if (loader == nullptr) {
      return;
    }

    if (loader->mBank != nullptr) {
      loader->mBank->Destroy();
    }

    if (loader->mName.myRes >= 0x10u) {
      operator delete(loader->mName.bx.ptr);
    }
    loader->mName.myRes = 15u;
    loader->mName.mySize = 0u;
    loader->mName.bx.buf[0] = '\0';

    auto& bufferOwner = reinterpret_cast<boost::SharedPtrLayoutView<char>&>(loader->mBuffer.mData);
    if (bufferOwner.pi != nullptr) {
      bufferOwner.pi->release();
    }
  }

  struct AudioStreamingRuntimeHandle
  {
    virtual void __stdcall Release() = 0;
  };

  /**
   * Address: 0x004DAD40 (FUN_004DAD40)
   *
   * What it does:
   * Destroys one in-memory-wavebank payload in place: releases the active
   * wave-bank runtime handle, clears the mapped-file shared buffer lanes, and
   * resets the stored bank-name string to empty SSO state.
   */
  [[maybe_unused]] void DestroyInMemoryWaveBankResourceNoDelete(
    AudioInMemoryWaveBankLoader* const inMemoryResource
  ) noexcept
  {
    if (inMemoryResource == nullptr) {
      return;
    }

    if (inMemoryResource->mWaveBank != nullptr) {
      auto* const runtimeHandle = reinterpret_cast<AudioStreamingRuntimeHandle*>(inMemoryResource->mWaveBank);
      runtimeHandle->Release();
      inMemoryResource->mWaveBank = nullptr;
    }

    inMemoryResource->mMappedBuffer.Reset();
    inMemoryResource->mName.tidy(true, 0u);
  }

  /**
   * Address: 0x004DAFD0 (FUN_004DAFD0)
   *
   * What it does:
   * Destroys one streaming-wavebank payload in place: releases the active
   * wave-bank runtime handle, closes the Win32 file handle when valid, and
   * resets the stored bank-name string to empty SSO state.
   */
  [[maybe_unused]] void DestroyStreamingWaveBankResourceNoDelete(
    AudioStreamingWaveBankLoader* const streamingResource
  ) noexcept
  {
    if (streamingResource == nullptr) {
      return;
    }

    if (streamingResource->mWaveBank != nullptr) {
      auto* const runtimeHandle = reinterpret_cast<AudioStreamingRuntimeHandle*>(streamingResource->mWaveBank);
      runtimeHandle->Release();
      streamingResource->mWaveBank = nullptr;
    }
    if (streamingResource->mFileHandle != INVALID_HANDLE_VALUE) {
      (void)::CloseHandle(streamingResource->mFileHandle);
      streamingResource->mFileHandle = INVALID_HANDLE_VALUE;
    }

    streamingResource->mName.tidy(true, 0u);
  }

  AudioInMemoryWaveBankLoader::~AudioInMemoryWaveBankLoader()
  {
    DestroyInMemoryWaveBankResourceNoDelete(this);
  }

  AudioStreamingWaveBankLoader::~AudioStreamingWaveBankLoader()
  {
    DestroyStreamingWaveBankResourceNoDelete(this);
  }

  /**
   * Address: 0x004DDED0 (FUN_004DDED0)
   *
   * What it does:
   * Destroys one contiguous range of audio sound-bank loader pointers.
   */
  void DestroyAudioSoundBankLoaderRange(void** const first, void** const last) noexcept
  {
    if (first == nullptr || last == nullptr) {
      return;
    }

    for (void** cursor = first; cursor != last; ++cursor) {
      auto* const loader = static_cast<AudioSoundBankLoader*>(*cursor);
      if (loader == nullptr) {
        continue;
      }

      DestroyAudioSoundBankLoaderNoDelete(loader);
      operator delete(loader);
      *cursor = nullptr;
    }
  }

  /**
   * Address: 0x004DDF10 (FUN_004DDF10)
   *
   * What it does:
   * Destroys one contiguous range of audio runtime handle objects through
   * their deleting-destructor vtable lane.
   */
  void DestroyAudioRuntimeHandleRange(void** const first, void** const last) noexcept
  {
    if (first == nullptr || last == nullptr) {
      return;
    }

    for (void** cursor = first; cursor != last; ++cursor) {
      if (*cursor == nullptr) {
        continue;
      }

      auto* const vtable = *reinterpret_cast<void***>(*cursor);
      if (vtable == nullptr || vtable[0] == nullptr) {
        continue;
      }

      using DeletingDtorFn = void(__thiscall*)(void*, std::uint8_t);
      reinterpret_cast<DeletingDtorFn>(vtable[0])(*cursor, 1u);
      *cursor = nullptr;
    }
  }

  struct AudioPointerVectorStorageRuntimeView
  {
    std::uint32_t allocatorProxy = 0; // +0x00
    void** begin = nullptr;           // +0x04
    void** end = nullptr;             // +0x08
    void** capacity = nullptr;        // +0x0C
  };
  static_assert(
    offsetof(AudioPointerVectorStorageRuntimeView, begin) == 0x04,
    "AudioPointerVectorStorageRuntimeView::begin offset must be 0x04"
  );
  static_assert(
    offsetof(AudioPointerVectorStorageRuntimeView, end) == 0x08,
    "AudioPointerVectorStorageRuntimeView::end offset must be 0x08"
  );
  static_assert(
    offsetof(AudioPointerVectorStorageRuntimeView, capacity) == 0x0C,
    "AudioPointerVectorStorageRuntimeView::capacity offset must be 0x0C"
  );

  [[nodiscard]] void** AppendNonNullAudioPointerVectorEntry(
    AudioPointerVectorStorageRuntimeView& vectorRuntime,
    void* const entry
  )
  {
    if (entry == nullptr) {
      throw boost::bad_pointer();
    }

    moho::CWaitHandle waitHandleStorage{};
    waitHandleStorage.begin = reinterpret_cast<HANDLE*>(vectorRuntime.begin);
    waitHandleStorage.end = reinterpret_cast<HANDLE*>(vectorRuntime.end);
    waitHandleStorage.cap = reinterpret_cast<HANDLE*>(vectorRuntime.capacity);

    const HANDLE handleEntry = static_cast<HANDLE>(entry);
    if (waitHandleStorage.begin == nullptr || waitHandleStorage.size() >= waitHandleStorage.capacity()) {
      HANDLE* const appendedEnd = waitHandleStorage.AppendHandle(waitHandleStorage.end, 1u, &handleEntry);
      vectorRuntime.begin = reinterpret_cast<void**>(waitHandleStorage.begin);
      vectorRuntime.end = reinterpret_cast<void**>(appendedEnd);
      vectorRuntime.capacity = reinterpret_cast<void**>(waitHandleStorage.cap);
      return vectorRuntime.end;
    }

    *waitHandleStorage.end = handleEntry;
    ++waitHandleStorage.end;
    vectorRuntime.end = reinterpret_cast<void**>(waitHandleStorage.end);
    return vectorRuntime.end;
  }

  /**
   * Address: 0x004DB2A0 (FUN_004DB2A0)
   *
   * What it does:
   * Pushes one non-null pointer lane into one vector-like handle set used by
   * sound-path loading, growing the backing storage through the canonical
   * wait-handle append helper when the current capacity is exhausted.
   */
  [[maybe_unused]] [[nodiscard]] void** PushBackNonNullAudioHandleStorageEntryA(
    AudioPointerVectorStorageRuntimeView& vectorRuntime,
    void* const entry
  )
  {
    return AppendNonNullAudioPointerVectorEntry(vectorRuntime, entry);
  }

  /**
   * Address: 0x004DB440 (FUN_004DB440)
   *
   * What it does:
   * Secondary non-null pointer push-back lane with the same growth and
   * `boost::bad_pointer` throw semantics as `FUN_004DB2A0`.
   */
  [[maybe_unused]] [[nodiscard]] void** PushBackNonNullAudioHandleStorageEntryB(
    AudioPointerVectorStorageRuntimeView& vectorRuntime,
    void* const entry
  )
  {
    return AppendNonNullAudioPointerVectorEntry(vectorRuntime, entry);
  }

  /**
   * Address: 0x004DB370 (FUN_004DB370)
   *
   * What it does:
   * Destroys all sound-bank loader pointers stored in one vector-like storage
   * lane, then releases the pointer-array buffer and clears begin/end/capacity.
   */
  [[maybe_unused]] void ResetAudioSoundBankLoaderPointerVectorStorageRuntime(
    AudioPointerVectorStorageRuntimeView* const vectorRuntime
  ) noexcept
  {
    if (vectorRuntime == nullptr) {
      return;
    }

    DestroyAudioSoundBankLoaderRange(vectorRuntime->begin, vectorRuntime->end);
    if (vectorRuntime->begin != nullptr) {
      operator delete(vectorRuntime->begin);
    }

    vectorRuntime->begin = nullptr;
    vectorRuntime->end = nullptr;
    vectorRuntime->capacity = nullptr;
  }

  /**
   * Address: 0x004DB500 (FUN_004DB500)
   *
   * What it does:
   * Destroys all runtime-handle pointers stored in one vector-like storage
   * lane, then releases the pointer-array buffer and clears begin/end/capacity.
   */
  [[maybe_unused]] void ResetAudioRuntimeHandlePointerVectorStorageRuntime(
    AudioPointerVectorStorageRuntimeView* const vectorRuntime
  ) noexcept
  {
    if (vectorRuntime == nullptr) {
      return;
    }

    DestroyAudioRuntimeHandleRange(vectorRuntime->begin, vectorRuntime->end);
    if (vectorRuntime->begin != nullptr) {
      operator delete(vectorRuntime->begin);
    }

    vectorRuntime->begin = nullptr;
    vectorRuntime->end = nullptr;
    vectorRuntime->capacity = nullptr;
  }

  /**
   * Address: 0x004DA280 (FUN_004DA280)
   *
   * What it does:
   * Pure jump-thunk adapter into `ResetAudioSoundBankLoaderPointerVectorStorageRuntime`.
   */
  [[maybe_unused]] void ResetAudioSoundBankLoaderPointerVectorStorageRuntimeThunk(
    AudioPointerVectorStorageRuntimeView* const vectorRuntime
  ) noexcept
  {
    ResetAudioSoundBankLoaderPointerVectorStorageRuntime(vectorRuntime);
  }

  /**
   * Address: 0x004DA290 (FUN_004DA290)
   *
   * What it does:
   * Pure jump-thunk adapter into `ResetAudioRuntimeHandlePointerVectorStorageRuntime`.
   */
  [[maybe_unused]] void ResetAudioRuntimeHandlePointerVectorStorageRuntimeThunk(
    AudioPointerVectorStorageRuntimeView* const vectorRuntime
  ) noexcept
  {
    ResetAudioRuntimeHandlePointerVectorStorageRuntime(vectorRuntime);
  }

  [[nodiscard]] Wm3::Vec3f NormalizeOrDefault(Wm3::Vec3f value, const Wm3::Vec3f& fallback)
  {
    if (Wm3::Vec3f::LengthSq(value) <= 1.0e-8f) {
      return fallback;
    }

    Wm3::Vec3f::Normalize(&value);
    return value;
  }

  [[nodiscard]] Wm3::Quatf QuaternionFromBasis(const Wm3::Vec3f& right, const Wm3::Vec3f& up, const Wm3::Vec3f& forward)
  {
    const float m00 = right.x;
    const float m01 = up.x;
    const float m02 = forward.x;
    const float m10 = right.y;
    const float m11 = up.y;
    const float m12 = forward.y;
    const float m20 = right.z;
    const float m21 = up.z;
    const float m22 = forward.z;
    const float trace = m00 + m11 + m22;

    Wm3::Quatf out{};
    if (trace > 0.0f) {
      const float s = std::sqrt(trace + 1.0f) * 2.0f;
      out.w = 0.25f * s;
      out.x = (m21 - m12) / s;
      out.y = (m02 - m20) / s;
      out.z = (m10 - m01) / s;
    } else if (m00 > m11 && m00 > m22) {
      const float s = std::sqrt(1.0f + m00 - m11 - m22) * 2.0f;
      out.w = (m21 - m12) / s;
      out.x = 0.25f * s;
      out.y = (m01 + m10) / s;
      out.z = (m02 + m20) / s;
    } else if (m11 > m22) {
      const float s = std::sqrt(1.0f + m11 - m00 - m22) * 2.0f;
      out.w = (m02 - m20) / s;
      out.x = (m01 + m10) / s;
      out.y = 0.25f * s;
      out.z = (m12 + m21) / s;
    } else {
      const float s = std::sqrt(1.0f + m22 - m00 - m11) * 2.0f;
      out.w = (m10 - m01) / s;
      out.x = (m02 + m20) / s;
      out.y = (m12 + m21) / s;
      out.z = 0.25f * s;
    }

    out.Normalize();
    return out;
  }

  [[nodiscard]] Wm3::Quatf BuildListenerOrientation(const moho::Audio3DListener& listener)
  {
    Wm3::Vec3f forward{listener.mOrientFront.x, listener.mOrientFront.y, listener.mOrientFront.z};
    Wm3::Vec3f top{listener.mOrientTop.x, listener.mOrientTop.y, listener.mOrientTop.z};

    forward = NormalizeOrDefault(forward, Wm3::Vec3f{0.0f, 0.0f, 1.0f});

    // Binary SetListenerTransform stores the second axis in inverted world-up space.
    Wm3::Vec3f up{-top.x, -top.y, -top.z};
    up = NormalizeOrDefault(up, Wm3::Vec3f{0.0f, 1.0f, 0.0f});

    Wm3::Vec3f right = Wm3::Vec3f::Cross(up, forward);
    right = NormalizeOrDefault(right, Wm3::Vec3f{1.0f, 0.0f, 0.0f});
    up = Wm3::Vec3f::Cross(forward, right);
    up = NormalizeOrDefault(up, Wm3::Vec3f{0.0f, 1.0f, 0.0f});

    return QuaternionFromBasis(right, up, forward);
  }

  /**
   * Address: 0x004D82A0 (FUN_004D82A0, func_ApplySettingsToCue)
   *
   * What it does:
   * Applies one X3DAudio matrix and per-cue runtime variables (`Distance`,
   * `DopplerPitchScalar`, `OrientationAngle`) to the target cue.
   */
  int ApplySettingsToCue(const moho::Audio3DDspSettings* settings, moho::IXACTCue* cue)
  {
    if (settings == nullptr || cue == nullptr) {
      return static_cast<int>(0x80004003u);
    }

    int result =
      cue->SetMatrixCoefficients(settings->mSrcChannelCount, settings->mDstChannelCount, settings->mMatrixCoefficients);
    if (result < 0) {
      return result;
    }

    const std::uint16_t distanceVariable = cue->GetVariableIndex("Distance");
    result = cue->SetVariable(distanceVariable, settings->mEmitterToListenerDistance);
    if (result < 0) {
      return result;
    }

    const std::uint16_t dopplerVariable = cue->GetVariableIndex("DopplerPitchScalar");
    result = cue->SetVariable(dopplerVariable, settings->mDopplerFactor);
    if (result < 0) {
      return result;
    }

    const std::uint16_t orientationVariable = cue->GetVariableIndex("OrientationAngle");
    return cue->SetVariable(orientationVariable, settings->mEmitterToListenerAngle * 57.295776f);
  }
} // namespace

namespace moho
{
  namespace
  {
    const IID kXactAuditionComInterfaceClsid =
      {0xcedde475u, 0x50b5u, 0x47efu, {0x91u, 0xa7u, 0x3bu, 0x49u, 0xa0u, 0xe8u, 0xe5u, 0x88u}};
    const IID kXactDebugComInterfaceClsid =
      {0x3cbb606bu, 0x06f1u, 0x473eu, {0x9du, 0xd5u, 0x0eu, 0x4au, 0x3bu, 0x47u, 0x14u, 0x13u}};
    const IID kXactComInterfaceClsid =
      {0x343e68e6u, 0x8f82u, 0x4a8du, {0xa2u, 0xdau, 0x6eu, 0x9au, 0x94u, 0x4bu, 0x37u, 0x8cu}};
    const IID kXactComInterfaceRiid =
      {0x893ff2e4u, 0x8d03u, 0x4d5fu, {0xb0u, 0xaau, 0x36u, 0x3au, 0x9cu, 0xbbu, 0xf4u, 0x37u}};
  } // namespace

  /**
   * Address: 0x004D8090 (FUN_004D8090, func_CreateXACTinstance)
   *
   * What it does:
   * Chooses XACT engine CLSID from debug/audition mode + optional
   * `HKLM\\Software\\Microsoft\\XACT\\DebugEngine`, creates the COM instance,
   * and retries with retail CLSID when debug creation fails.
   */
  int func_CreateXACTinstance(const std::uint32_t mode, void** const outEngine)
  {
    std::uint32_t debug = (mode >> 1u) & 1u;
    const std::uint32_t audition = mode & 1u;
    const std::uint32_t auditionMode = audition;

    DWORD type = REG_DWORD;
    DWORD cbData = sizeof(DWORD);
    DWORD data = 0u;

    const IID* selectedClsid = nullptr;
    if (debug != 0u) {
      selectedClsid = (audition != 0u) ? &kXactAuditionComInterfaceClsid : &kXactDebugComInterfaceClsid;
    } else if (audition != 0u) {
      selectedClsid = &kXactAuditionComInterfaceClsid;
    } else {
      HKEY openedKey = nullptr;
      if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\XACT", 0u, 0x20019u, &openedKey) != ERROR_SUCCESS) {
        selectedClsid = &kXactComInterfaceClsid;
      } else {
        if (
          RegQueryValueExW(
            openedKey,
            L"DebugEngine",
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(&data),
            &cbData
          ) == ERROR_SUCCESS
        ) {
          debug = (data != 0u) ? 1u : 0u;
        }
        RegCloseKey(openedKey);
        selectedClsid = (debug != 0u) ? &kXactDebugComInterfaceClsid : &kXactComInterfaceClsid;
      }
    }

    int result = CoCreateInstance(*selectedClsid, nullptr, CLSCTX_INPROC_SERVER, kXactComInterfaceRiid, outEngine);
    if (result < 0 && debug != 0u && auditionMode == 0u) {
      result = CoCreateInstance(kXactComInterfaceClsid, nullptr, CLSCTX_INPROC_SERVER, kXactComInterfaceRiid, outEngine);
    }
    return result;
  }

  void func_RetreiveXACTCOMInterface(AudioEngineImpl* impl);
  void func_LoadSoundPath(AudioEngineImpl* impl, gpg::StrArg voicePath);
  msvc8::string SND_GetVariableName(int variableId);

  /**
   * Address: 0x004D8A50 (FUN_004D8A50, func_SoundErrorCodeToMsg)
   *
   * What it does:
   * Maps common HRESULT/XACT failure codes to stable diagnostic text.
   */
  const char* func_SoundErrorCodeToMsg(int errorCode);

  struct AudioFinalMixFormatRuntimeView
  {
    std::array<std::uint8_t, 0x14> mReserved00{};
    std::uint32_t mSpeakerChannelMask = 0; // +0x14
  };
  static_assert(
    offsetof(AudioFinalMixFormatRuntimeView, mSpeakerChannelMask) == 0x14,
    "AudioFinalMixFormatRuntimeView::mSpeakerChannelMask offset must be 0x14"
  );
  static_assert(sizeof(AudioFinalMixFormatRuntimeView) == 0x18, "AudioFinalMixFormatRuntimeView size must be 0x18");

  /**
   * Address: 0x004D8170 (FUN_004D8170, func_AudioInitialize)
   *
   * What it does:
   * Reads XACT global `SpeedOfSound`, fetches final mix speaker-channel mask,
   * and initializes the 3D-audio handle with those two lanes.
   */
  int func_AudioInitialize(IXACTEngine* const engine, void* const audioHandle)
  {
    if (engine == nullptr) {
      return kHresultPointer;
    }

    const std::uint16_t speedOfSoundVariable = engine->GetGlobalVariableIndex("SpeedOfSound");
    float speedOfSound = 0.0f;
    int result = engine->GetGlobalVariable(speedOfSoundVariable, &speedOfSound);
    if (result < 0) {
      return result;
    }

    AudioFinalMixFormatRuntimeView finalMixFormat{};
    result = engine->GetFinalMixFormat(&finalMixFormat);
    if (result < 0) {
      return result;
    }

    X3DAudioInitialize(finalMixFormat.mSpeakerChannelMask, speedOfSound, audioHandle);
    return result;
  }

  /**
   * Address: 0x004D81E0 (FUN_004D81E0, func_X3DAudioCalculate)
   *
   * What it does:
   * Applies default channel azimuth/curve lanes for multi-channel emitters
   * and forwards one 3D-audio solve call into `X3DAudioCalculate`.
   */
  int func_X3DAudioCalculate(
    Audio3DEmitter* emitter,
    const Audio3DListener* listener,
    Audio3DDspSettings* settings,
    const void* audioHandle
  );

  /**
   * Address: 0x004D8970 (FUN_004D8970, func_RetreiveXACTCOMInterface)
   *
   * What it does:
   * Chooses XACT creation mode from `/xactdebug` + audition settings, creates
   * the engine COM instance, and throws `XAudioError` on failure.
   */
  void func_RetreiveXACTCOMInterface(AudioEngineImpl* const impl)
  {
    if (impl == nullptr) {
      return;
    }

    std::uint32_t mode = 0u;
    if (CFG_GetArgOption("/xactdebug", 0, nullptr)) {
      mode = 2u;
    } else if (sSoundConfiguration != nullptr && sSoundConfiguration->mAudition != 0u) {
      mode = 1u;
    }

    const int errorCode = func_CreateXACTinstance(mode, reinterpret_cast<void**>(&impl->mInstance));
    if (errorCode < 0) {
      const char* const errorMessage = func_SoundErrorCodeToMsg(errorCode);
      const msvc8::string fullMessage =
        gpg::STR_Printf("SND: Error retrieving XACT COM interface. %s", errorMessage ? errorMessage : "Unknown XACT Error");
      throw XAudioError(fullMessage.c_str());
    }
  }

  /**
   * Address: 0x004DA500 (FUN_004DA500, func_LoadSoundPath)
   *
   * gpg::StrArg voicePath
   *
   * What it does:
   * Enumerates wave-bank (`*.xwb`) and sound-bank (`*.xsb`) files under one
   * voice-path lane, constructs the corresponding loader objects, loads each
   * bank, and appends successful resources into `mHandles`/`mBanks`.
   */
  void func_LoadSoundPath(AudioEngineImpl* const impl, const gpg::StrArg voicePath)
  {
    if (impl == nullptr || voicePath == nullptr) {
      return;
    }

    FWaitHandleSet* waitHandleSet = FILE_GetWaitHandleSet();
    if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr) {
      return;
    }

    msvc8::vector<msvc8::string> waveBankPaths{};
    waitHandleSet->mHandle->EnumerateFiles(voicePath, "*.xwb", false, &waveBankPaths);

    auto& waveBankStorage = reinterpret_cast<AudioPointerVectorStorageRuntimeView&>(impl->mHandles);
    for (const msvc8::string& waveBankPath : waveBankPaths) {
      const bool streamingWaveBank = IsStreamingWaveBank(waveBankPath.c_str());
      gpg::Logf(
        "IsStreamingWaveBank(\"%s\") => %s",
        waveBankPath.c_str(),
        streamingWaveBank ? "true" : "false"
      );

      AudioWaveBankLoaderBase* waveBankLoader = nullptr;
      if (streamingWaveBank) {
        waveBankLoader = new (std::nothrow) AudioStreamingWaveBankLoader(impl);
      } else {
        waveBankLoader = new (std::nothrow) AudioInMemoryWaveBankLoader(impl);
      }

      if (waveBankLoader != nullptr && waveBankLoader->Load(waveBankPath.c_str())) {
        PushBackNonNullAudioHandleStorageEntryB(waveBankStorage, waveBankLoader);
        waveBankLoader = nullptr;
      }

      delete waveBankLoader;
    }

    waitHandleSet = FILE_GetWaitHandleSet();
    if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr) {
      return;
    }

    msvc8::vector<msvc8::string> soundBankPaths{};
    waitHandleSet->mHandle->EnumerateFiles(voicePath, "*.xsb", false, &soundBankPaths);

    auto& soundBankStorage = reinterpret_cast<AudioPointerVectorStorageRuntimeView&>(impl->mBanks);
    for (const msvc8::string& soundBankPath : soundBankPaths) {
      auto* soundBankLoader = new (std::nothrow) AudioSoundBankLoader{};
      if (soundBankLoader != nullptr) {
        soundBankLoader->mEngine = impl;
      }

      if (soundBankLoader != nullptr && soundBankLoader->Load(soundBankPath.c_str())) {
        PushBackNonNullAudioHandleStorageEntryA(soundBankStorage, soundBankLoader);
        soundBankLoader = nullptr;
      }

      if (soundBankLoader != nullptr) {
        DestroyAudioSoundBankLoaderNoDelete(soundBankLoader);
        operator delete(soundBankLoader);
      }
    }
  }

  /**
   * Address: 0x004D8A50 (FUN_004D8A50, func_SoundErrorCodeToMsg)
   *
   * What it does:
   * Translates XACT/HRESULT error codes into user-facing warning strings.
   */
  const char* func_SoundErrorCodeToMsg(const int errorCode)
  {
    const std::uint32_t code = static_cast<std::uint32_t>(errorCode);
    switch (code) {
    case 0x8007000Eu:
      return "Out of memory";
    case 0x80004001u:
      return "Not implemented";
    case 0x80004005u:
      return "Unknown error";
    case 0x80070057u:
      return "Invalid arg";

    case 0x8AC70001u:
      return "The engine is already initialized";
    case 0x8AC70002u:
      return "The engine has not been initialized";
    case 0x8AC70003u:
      return "The engine has expired (demo or pre-release version)";
    case 0x8AC70004u:
      return "No notification callback";
    case 0x8AC70005u:
      return "Notification already registered";
    case 0x8AC70006u:
      return "Invalid usage";
    case 0x8AC70007u:
      return "Invalid data";
    case 0x8AC70008u:
      return "Fail to play due to instance limit";
    case 0x8AC70009u:
      return "Global Settings not loaded";
    case 0x8AC7000Au:
      return "Invalid variable index";
    case 0x8AC7000Bu:
      return "Invalid category";
    case 0x8AC7000Cu:
      return "Invalid cue index";
    case 0x8AC7000Du:
      return "Invalid wave index";
    case 0x8AC7000Eu:
      return "Invalid track index";
    case 0x8AC7000Fu:
      return "Invalid sound offset or index";
    case 0x8AC70010u:
      return "Error reading a file";
    case 0x8AC70011u:
      return "Unknown event type";
    case 0x8AC70012u:
      return "Invalid call of method of function from callback";
    case 0x8AC70013u:
      return "No wavebank exists for desired operation";
    case 0x8AC70014u:
      return "Unable to select a variation";
    case 0x8AC70015u:
      return "There can be only one audition engine";
    case 0x8AC70016u:
      return "The wavebank is not prepared";
    case 0x8AC70017u:
      return "No audio device found on.";
    case 0x8AC70018u:
      return "Invalid entry count for channel maps";

    case 0x8AC70101u:
      return "Error writing a file during auditioning";
    case 0x8AC70102u:
      return "Missing a soundbank";
    case 0x8AC70103u:
      return "Missing an RPC curve";
    case 0x8AC70104u:
      return "Missing data for an audition command";
    case 0x8AC70105u:
      return "Unknown command";
    case 0x8AC70106u:
      return "Missing a DSP parameter";

    default:
      return "Unknown XACT Error";
    }
  }

  /**
   * Address: 0x004D81E0 (FUN_004D81E0, func_X3DAudioCalculate)
   *
   * What it does:
   * Validates listener/emitter/settings pointers, injects default azimuth
   * layouts for common channel counts when missing, applies default flat
   * distance curves, and dispatches one `X3DAudioCalculate` solve.
   */
  int func_X3DAudioCalculate(
    Audio3DEmitter* const emitter,
    const Audio3DListener* const listener,
    Audio3DDspSettings* const settings,
    const void* const audioHandle
  )
  {
    if (listener == nullptr || emitter == nullptr || settings == nullptr) {
      return kHresultPointer;
    }

    if (emitter->mChannelCount > 1u && emitter->mChannelAzimuths == nullptr) {
      emitter->mChannelRadius = 1.0f;
      switch (emitter->mChannelCount) {
      case 2u:
        emitter->mChannelAzimuths = const_cast<float*>(kDefaultAzimuths2.data());
        break;
      case 3u:
        emitter->mChannelAzimuths = const_cast<float*>(kDefaultAzimuths3.data());
        break;
      case 4u:
        emitter->mChannelAzimuths = const_cast<float*>(kDefaultAzimuths4.data());
        break;
      case 5u:
        emitter->mChannelAzimuths = const_cast<float*>(kDefaultAzimuths5.data());
        break;
      case 6u:
        emitter->mChannelAzimuths = const_cast<float*>(kDefaultAzimuths6.data());
        break;
      case 8u:
        emitter->mChannelAzimuths = const_cast<float*>(kDefaultAzimuths8.data());
        break;
      default:
        return kHresultFail;
      }
    }

    if (emitter->mVolumeCurve == nullptr) {
      emitter->mVolumeCurve = const_cast<AudioDistanceCurve*>(&kDefaultDistanceCurve);
    }
    if (emitter->mLfeCurve == nullptr) {
      emitter->mLfeCurve = const_cast<AudioDistanceCurve*>(&kDefaultDistanceCurve);
    }

    X3DAudioCalculate(audioHandle, listener, emitter, kX3dCalculateFlags, settings);
    return 0;
  }

  namespace
  {
    struct SoundNotificationEventData
    {
      std::uint8_t mType;                                 // +0x00
      std::array<std::uint8_t, 0x08> mReserved01{};      // +0x01
      std::array<std::uint8_t, 0x04> mWaveBankToken{};   // +0x09
      std::array<std::uint8_t, 0x06> mReserved0D{};      // +0x0D
      std::array<std::uint8_t, 0x02> mVariableId{};      // +0x13
      std::array<std::uint8_t, 0x04> mVariableValue{};   // +0x15

      [[nodiscard]] std::uint16_t VariableId() const noexcept
      {
        std::uint16_t value = 0;
        std::memcpy(&value, mVariableId.data(), sizeof(value));
        return value;
      }

      [[nodiscard]] float VariableValue() const noexcept
      {
        float value = 0.0f;
        std::memcpy(&value, mVariableValue.data(), sizeof(value));
        return value;
      }

      [[nodiscard]] std::uint32_t WaveBankId() const noexcept
      {
        std::uint32_t value = 0;
        std::memcpy(&value, mWaveBankToken.data(), sizeof(value));
        return value;
      }
    };
    static_assert(offsetof(SoundNotificationEventData, mType) == 0x00, "SoundNotificationEventData::mType offset must be 0x00");
    static_assert(
      offsetof(SoundNotificationEventData, mWaveBankToken) == 0x09,
      "SoundNotificationEventData::mWaveBankToken offset must be 0x09"
    );
    static_assert(
      offsetof(SoundNotificationEventData, mVariableId) == 0x13,
      "SoundNotificationEventData::mVariableId offset must be 0x13"
    );
    static_assert(
      offsetof(SoundNotificationEventData, mVariableValue) == 0x15,
      "SoundNotificationEventData::mVariableValue offset must be 0x15"
    );
    static_assert(sizeof(SoundNotificationEventData) == 0x19, "SoundNotificationEventData size must be 0x19");

    struct AudioNotificationDesc
    {
      std::uint8_t type;
      std::uint8_t flags;
      std::uint8_t reserved[0x18];
    };

    void RegisterNotificationOrWarn(AudioEngineImpl* const impl, const std::uint8_t notificationType)
    {
      if (impl == nullptr || impl->mInstance == nullptr) {
        return;
      }

      AudioNotificationDesc notification{};
      notification.type = notificationType;
      notification.flags = 1u;

      const int result = impl->mInstance->RegisterNotification(&notification);
      if (result < 0) {
        gpg::Warnf("SND: Error registering notification.\n%s", func_SoundErrorCodeToMsg(result));
      }
    }
  } // namespace

  /**
   * Address: 0x004D84D0 (FUN_004D84D0, func_SoundConfigInit)
   *
   * IDA signature:
   * struct_SoundConfig *__usercall func_SoundConfigInit@<eax>(struct_SoundConfig *this@<esi>);
   *
   * What it does:
   * Default-initializes a freshly allocated `SoundConfiguration`:
   * default-constructs the embedded `gpg::time::Timer`, zeros the
   * engine-pointer vector lanes, zeros the global settings memory
   * buffer lanes, primes the speaker-configuration field to `3`, and
   * clears every remaining flag, runtime-module pointer, and reserved
   * trailing dword. The binary returns `this`; the C++ ctor returns
   * implicitly.
   */
  SoundConfiguration::SoundConfiguration() noexcept
    : mTime{}
    , mEngines{}
    , mGlobalSettingsBuffer{}
    , mNoSound(0u)
    , mReserved29{}
    , mSpeakerConfiguration(3u)
    , mAudioRuntimeModule(nullptr)
    , mLookAheadTimeMs(0u)
    , mGlobalSettingsStart(nullptr)
    , mGlobalSettingsLength(0u)
    , mRuntimeFlags(0u)
    , mReserved44{}
    , mHandleSoundEvent(nullptr)
    , mReserved54{}
    , mAudition(0u)
    , mReserved59{}
  {
  }

  /**
   * Address: 0x004D9250 (FUN_004D9250, ??1struct_SoundConfig@@QAE@@Z)
   * Mangled: ??1struct_SoundConfig@@QAE@@Z
   *
   * What it does:
   * Clears all active `AudioEngineImpl` lanes, unloads optional audio runtime
   * module state, and releases retained shared engine references.
   */
  SoundConfiguration::~SoundConfiguration()
  {
    if (mEngines.mStart != nullptr && mEngines.mFinish != nullptr) {
      for (AudioEngineRef* entry = mEngines.mStart; entry != mEngines.mFinish; ++entry) {
        AudioEngine* const engine = entry->mEngine;
        if (engine == nullptr) {
          continue;
        }

        AudioEngineImpl* const impl = engine->mImpl;
        engine->mImpl = nullptr;
        if (impl != nullptr) {
          impl->~AudioEngineImpl();
          operator delete(impl);
        }
      }
    }

    if (mAudioRuntimeModule != nullptr) {
      (void)::FreeLibrary(static_cast<HMODULE>(mAudioRuntimeModule));
      mAudioRuntimeModule = nullptr;
    }

    if (mEngines.mStart != nullptr) {
      for (AudioEngineRef* entry = mEngines.mStart; entry != mEngines.mFinish; ++entry) {
        auto* const control = static_cast<boost::detail::sp_counted_base*>(entry->mControl);
        if (control != nullptr) {
          control->release();
        }
        entry->mEngine = nullptr;
        entry->mControl = nullptr;
      }
      operator delete[](mEngines.mStart);
    }

    mEngines.mAllocatorCookie = nullptr;
    mEngines.mStart = nullptr;
    mEngines.mFinish = nullptr;
    mEngines.mCapacity = nullptr;
  }

  std::uint32_t SoundConfiguration::EngineCount() const
  {
    if (mEngines.mStart == nullptr || mEngines.mFinish == nullptr) {
      return 0u;
    }

    return static_cast<std::uint32_t>(mEngines.mFinish - mEngines.mStart);
  }

  AudioEngineImpl* SoundConfiguration::EngineImplAt(const std::uint32_t index) const
  {
    const std::uint32_t engineCount = EngineCount();
    if (index >= engineCount) {
      return nullptr;
    }

    AudioEngine* const engine = mEngines.mStart[index].mEngine;
    if (engine == nullptr) {
      return nullptr;
    }

    return engine->mImpl;
  }

  /**
   * Address: 0x004D8810 (FUN_004D8810, func_HandleSoundEvent)
   *
   * What it does:
   * Handles XACT notification event payloads and emits diagnostics for
   * variable-value changes, GUI connect/disconnect signals, and wavebank
   * streaming state changes.
   */
  void __stdcall func_HandleSoundEvent(const std::uint8_t* const eventDataBytes)
  {
    if (eventDataBytes == nullptr) {
      return;
    }

    const auto& eventData = *reinterpret_cast<const SoundNotificationEventData*>(eventDataBytes);
    switch (eventData.mType) {
    case 0x08:
      gpg::Logf("SND: Local var changed %i = %f", eventData.VariableId(), eventData.VariableValue());
      break;

    case 0x09: {
      const msvc8::string variableName = SND_GetVariableName(static_cast<int>(eventData.VariableId()));
      gpg::Logf("SND: Global var changed [%s] = %f", variableName.c_str(), eventData.VariableValue());
      break;
    }

    case 0x0A:
      gpg::Logf("SND: Gui Connected");
      break;

    case 0x0B:
      gpg::Logf("SND: Gui Disconnected");
      break;

    case 0x11:
      gpg::Debugf("Wavebank prepared: %x", eventData.WaveBankId());
      break;

    case 0x12:
      gpg::Logf("Error streaming from wavebank %x, invalid content", eventData.WaveBankId());
      break;

    default:
      break;
    }
  }

  /**
   * Address: 0x004D8C00 (FUN_004D8C00, func_InitSound)
   *
   * IDA signature:
   * void callcnv_33 func_InitSound();
   *
   * What it does:
   * Allocates and initializes a fresh `SoundConfiguration` slot,
   * replaces any existing global, parses the `/audition` and
   * `/nosound` CLI flags. When sound is enabled it also primes the
   * lookahead time to 250ms, wires the XACT notification handler,
   * loads the global settings buffer from `/sounds/SupCom.xgs` via
   * the file wait handle set + VFS, exposes the loaded buffer's
   * range through `mGlobalSettingsStart`/`mGlobalSettingsLength`,
   * then queries DirectSound for the current speaker channel mode
   * and stores it in `mSpeakerConfiguration`.
   */
  void func_InitSound()
  {
    auto* const freshConfiguration = new (std::nothrow) SoundConfiguration();

    SoundConfiguration* previousConfiguration = freshConfiguration;
    SwapSoundConfigurationSingletonPointer(previousConfiguration);
    if (previousConfiguration != nullptr) {
      previousConfiguration->~SoundConfiguration();
      ::operator delete(previousConfiguration);
    }

    if (sSoundConfiguration == nullptr) {
      return;
    }

    sSoundConfiguration->mAudition = static_cast<std::uint8_t>(
      moho::CFG_GetArgOption("/audition", 0u, nullptr) ? 1u : 0u
    );
    sSoundConfiguration->mNoSound = static_cast<std::uint8_t>(
      moho::CFG_GetArgOption("/nosound", 0u, nullptr) ? 1u : 0u
    );

    if (sSoundConfiguration->mNoSound == 0u) {
      sSoundConfiguration->mLookAheadTimeMs = 250u;
      sSoundConfiguration->mHandleSoundEvent =
        reinterpret_cast<std::uint32_t (__cdecl*)(int*)>(&moho::func_HandleSoundEvent);
      sSoundConfiguration->mRuntimeFlags = 0u;

      moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
      msvc8::string mountedPath{};
      const msvc8::string* const resolvedPath =
        waitHandleSet->mHandle->FindFile(&mountedPath, "/sounds/SupCom.xgs", nullptr);

      gpg::MemBuffer<char> loadedBuffer = moho::DISK_ReadFile(resolvedPath->c_str());
      sSoundConfiguration->mGlobalSettingsBuffer = loadedBuffer;

      if (sSoundConfiguration->mGlobalSettingsBuffer.mBegin != nullptr) {
        sSoundConfiguration->mGlobalSettingsLength = static_cast<std::uint32_t>(
          sSoundConfiguration->mGlobalSettingsBuffer.mEnd -
          sSoundConfiguration->mGlobalSettingsBuffer.mBegin
        );
        sSoundConfiguration->mGlobalSettingsStart =
          sSoundConfiguration->mGlobalSettingsBuffer.mBegin;
      }
    }

    LPDIRECTSOUND directSound = nullptr;
    if (::DirectSoundCreate(nullptr, &directSound, nullptr) >= 0) {
      DWORD speakerConfig = 0;
      directSound->GetSpeakerConfig(&speakerConfig);
      switch (static_cast<std::uint8_t>(speakerConfig)) {
        case 0u:
        case 1u:
        case 2u:
        case 3u:
        case 4u:
        case 5u:
        case 7u:
          sSoundConfiguration->mSpeakerConfiguration = 3u;
          break;
        case 6u:
          sSoundConfiguration->mSpeakerConfiguration = 63u;
          break;
        default:
          gpg::Warnf(
            "Unknown DirectSound speaker configuration %i. Defaulting to Stereo.",
            static_cast<unsigned>(static_cast<std::uint8_t>(speakerConfig))
          );
          sSoundConfiguration->mSpeakerConfiguration = 3u;
          break;
      }
      directSound->Release();
    } else {
      gpg::Warnf("Failed to create DirectSound.");
    }
  }

  /**
   * Address: 0x004D8EE0 (FUN_004D8EE0, ?SND_Shutdown@Moho@@YAXXZ)
   *
   * What it does:
   * Clears and destroys the process-global sound configuration singleton.
   */
  void SND_Shutdown()
  {
    SoundConfiguration* configuration = nullptr;
    SwapSoundConfigurationSingletonPointer(configuration);
    if (configuration == nullptr) {
      return;
    }

    configuration->~SoundConfiguration();
    ::operator delete(configuration);
  }

  /**
   * Address: 0x004D8F10 (FUN_004D8F10, ?SND_Enabled@Moho@@YA_NXZ)
   *
   * What it does:
   * Reports whether at least one audio engine is loaded and no-sound mode is
   * disabled.
   */
  bool SND_Enabled()
  {
    const SoundConfiguration* const configuration = GetSoundConfigurationSingletonA();
    if (configuration == nullptr) {
      return false;
    }

    const AudioEngineRef* const begin = configuration->mEngines.mStart;
    return begin != nullptr && configuration->mEngines.mFinish != begin && configuration->mNoSound == 0u;
  }

  /**
   * Address: 0x004D8F40 (FUN_004D8F40, ?SND_Frame@Moho@@YAXXZ)
   *
   * What it does:
   * Advances XACT engine work queues for each configured audio engine and
   * resets the global sound-configuration frame timer.
   */
  void SND_Frame()
  {
    SoundConfiguration* configuration = GetSoundConfigurationSingletonB();
    if (configuration == nullptr) {
      return;
    }

    for (std::uint32_t index = 0;; ++index) {
      if (index >= configuration->EngineCount()) {
        break;
      }

      if (AudioEngineImpl* const impl = configuration->EngineImplAt(index);
          impl != nullptr && impl->mInstance != nullptr) {
        impl->mInstance->DoWork();
        configuration = GetSoundConfigurationSingletonB();
      }
    }

    configuration->mTime.Reset();
  }

  /**
   * Address: 0x004D8F90 (FUN_004D8F90)
   *
   * What it does:
   * Issues one additional SND frame pass when `snd_ExtraDoWorkCalls` is
   * enabled and the sound frame timer exceeded 100ms.
   */
  void SND_FrameExtraDoWorkTick()
  {
    SoundConfiguration* const configuration = GetSoundConfigurationSingletonA();
    if (configuration == nullptr) {
      return;
    }

    if (moho::snd_ExtraDoWorkCalls && configuration->mTime.ElapsedMilliseconds() > 100.0f) {
      SND_Frame();
    }
  }

  /**
   * Address: 0x004D8FC0 (FUN_004D8FC0, ?SND_Mute@Moho@@YAX_N@Z)
   *
   * What it does:
   * Stores/restores per-engine "Global" category volume while applying
   * process-wide mute transitions.
   */
  void SND_Mute(const bool doMute)
  {
    SoundConfiguration* configuration = GetSoundConfigurationSingletonB();
    if (configuration == nullptr) {
      return;
    }

    for (std::uint32_t index = 0;; ++index) {
      if (index >= configuration->EngineCount()) {
        break;
      }

      AudioEngineImpl* const impl = configuration->EngineImplAt(index);
      if (impl == nullptr || impl->mInstance == nullptr) {
        continue;
      }

      ApplyGlobalMuteToEngine(*impl, doMute);
      configuration = GetSoundConfigurationSingletonB();
    }
  }

  /**
   * Address: 0x004D9040 (FUN_004D9040, ?SND_GetGlobalVarIndex@Moho@@...)
   *
   * gpg::StrArg variableName, std::uint16_t* outVarIndex
   *
   * What it does:
   * Resolves one global XACT variable index from the active primary engine.
   */
  bool SND_GetGlobalVarIndex(const gpg::StrArg variableName, std::uint16_t* const outVarIndex)
  {
    if (outVarIndex == nullptr) {
      return false;
    }

    const SoundConfiguration* const configuration = sSoundConfiguration;
    if (configuration == nullptr || configuration->mEngines.mStart == nullptr ||
        configuration->mEngines.mStart == configuration->mEngines.mFinish || configuration->mNoSound != 0u) {
      return false;
    }

    AudioEngine* const engine = configuration->mEngines.mStart->mEngine;
    if (engine == nullptr || engine->mImpl == nullptr || engine->mImpl->mInstance == nullptr) {
      return false;
    }

    const std::uint16_t variableId = engine->mImpl->mInstance->GetGlobalVariableIndex(variableName);
    *outVarIndex = variableId;
    return variableId != kInvalidVariableId;
  }

  /**
   * Address: 0x004D9090 (FUN_004D9090, ?SND_GetGlobalFloat@Moho@@...)
   *
   * std::uint16_t varIndex
   *
   * What it does:
   * Reads one global XACT variable value from the active primary engine.
   */
  float SND_GetGlobalFloat(const std::uint16_t varIndex)
  {
    const SoundConfiguration* const configuration = sSoundConfiguration;
    if (configuration == nullptr || configuration->mEngines.mStart == nullptr ||
        configuration->mEngines.mStart == configuration->mEngines.mFinish || configuration->mNoSound != 0u) {
      return std::numeric_limits<float>::quiet_NaN();
    }

    AudioEngine* const engine = configuration->mEngines.mStart->mEngine;
    if (engine == nullptr || engine->mImpl == nullptr || engine->mImpl->mInstance == nullptr) {
      return std::numeric_limits<float>::quiet_NaN();
    }

    float value = std::numeric_limits<float>::quiet_NaN();
    if (engine->mImpl->mInstance->GetGlobalVariable(varIndex, &value) < 0) {
      return std::numeric_limits<float>::quiet_NaN();
    }
    return value;
  }

  /**
   * Address: 0x004D90E0 (FUN_004D90E0, ?SND_SetGlobalFloat@Moho@@...)
   *
   * std::uint16_t varIndex, float value
   *
   * What it does:
   * Writes one global XACT variable value on the active primary engine.
   */
  void SND_SetGlobalFloat(const std::uint16_t varIndex, const float value)
  {
    const SoundConfiguration* const configuration = sSoundConfiguration;
    if (configuration == nullptr || configuration->mEngines.mStart == nullptr ||
        configuration->mEngines.mStart == configuration->mEngines.mFinish || configuration->mNoSound != 0u) {
      return;
    }

    AudioEngine* const engine = configuration->mEngines.mStart->mEngine;
    if (engine == nullptr || engine->mImpl == nullptr || engine->mImpl->mInstance == nullptr) {
      return;
    }

    if (engine->mImpl->mInstance->SetGlobalVariable(varIndex, value) < 0) {
      gpg::Warnf("SND: Error setting global variable [index:%i]", varIndex);
    }
  }

  /**
   * Address: 0x004D9140 (FUN_004D9140, ?SND_FindEngine@Moho@@...)
   *
   * gpg::StrArg
   *
   * What it does:
   * Finds one loaded `AudioEngine` that owns a bank matching the supplied
   * bank name.
   */
  boost::shared_ptr<AudioEngine> SND_FindEngine(const gpg::StrArg bankName)
  {
    SoundConfiguration* const configuration = sSoundConfiguration;
    if (configuration == nullptr || bankName == nullptr || configuration->mEngines.mStart == nullptr ||
        configuration->mEngines.mFinish == nullptr) {
      return {};
    }

    const std::size_t engineCount = static_cast<std::size_t>(configuration->mEngines.mFinish - configuration->mEngines.mStart);
    for (std::size_t engineIndex = 0; engineIndex < engineCount; ++engineIndex) {
      const AudioEngineRef& engineRef = configuration->mEngines.mStart[engineIndex];
      AudioEngine* const engine = engineRef.mEngine;
      if (engine == nullptr || engine->mImpl == nullptr || engine->mImpl->mBanks.mStart == nullptr ||
          engine->mImpl->mBanks.mFinish == nullptr) {
        continue;
      }

      const std::size_t bankCount =
        static_cast<std::size_t>(engine->mImpl->mBanks.mFinish - engine->mImpl->mBanks.mStart);
      for (std::size_t bankIndex = 0; bankIndex < bankCount; ++bankIndex) {
        auto* const loader = static_cast<AudioSoundBankLoader*>(engine->mImpl->mBanks.mStart[bankIndex]);
        if (loader == nullptr || ::_stricmp(bankName, loader->mName.c_str()) != 0) {
          continue;
        }
        return CopyEngineRefShared(engineRef);
      }
    }

    return {};
  }

  /**
   * Address: 0x004D9410 (FUN_004D9410, ??0AudioEngine@Moho@@AAE@VStrArg@gpg@@@Z)
   *
   * gpg::StrArg voicePath
   *
   * What it does:
   * Allocates and binds `AudioEngineImpl`, initializes XACT + 3D audio lanes,
   * loads voice/sound path data, and applies startup listener/category state.
   */
  AudioEngine::AudioEngine(const gpg::StrArg voicePath)
    : mImpl(nullptr)
  {
    SoundConfiguration* const configuration = sSoundConfiguration;
    ReplaceAudioEngineImplPointer(mImpl, new AudioEngineImpl(this, configuration));

    if (configuration == nullptr || configuration->mNoSound != 0u || mImpl == nullptr) {
      return;
    }

    func_RetreiveXACTCOMInterface(mImpl);
    if (mImpl->mInstance == nullptr) {
      return;
    }

    gpg::MD5Context md5Context{};
    md5Context.Reset();
    md5Context.Update(configuration->mGlobalSettingsStart, configuration->mGlobalSettingsLength);
    const msvc8::string globalSettingsDigest = md5Context.Digest().ToString();
    gpg::Logf("MD5 of global settings: %s", globalSettingsDigest.c_str());

    const int initializeResult = mImpl->mInstance->Initialize(&configuration->mSpeakerConfiguration);
    if (initializeResult < 0) {
      gpg::Warnf("SND: Error initializing audio engine.\n%s", func_SoundErrorCodeToMsg(initializeResult));
      configuration->mNoSound = 1u;
      return;
    }

    const int audio3dResult = func_AudioInitialize(mImpl->mInstance, mImpl->mAudioHandle);
    if (audio3dResult < 0) {
      gpg::Warnf("SND: Error initializing 3D audio.\n%s", func_SoundErrorCodeToMsg(audio3dResult));
      configuration->mNoSound = 1u;
      return;
    }

    RegisterNotificationOrWarn(mImpl, 10u);
    RegisterNotificationOrWarn(mImpl, 11u);
    RegisterNotificationOrWarn(mImpl, 17u);
    RegisterNotificationOrWarn(mImpl, 18u);

    gpg::Logf("MEM: %i bytes SND", 0);
    func_LoadSoundPath(mImpl, voicePath);

    if (CFG_GetArgOption("/nomusic", 0, nullptr)) {
      SetVolume("Music", 0.0f);
    }

    VTransform listenerTransform{};
    listenerTransform.pos_.x = 0.0f;
    listenerTransform.pos_.y = 0.0f;
    listenerTransform.pos_.z = 0.0f;
    SetListenerTransform(listenerTransform);
  }

  /**
   * Address: 0x004D9340 (FUN_004D9340, ?Create@AudioEngine@Moho@@SA?AV?$shared_ptr@VAudioEngine@Moho@@@boost@@VStrArg@gpg@@@Z)
   *
   * gpg::StrArg voicePath
   *
   * What it does:
   * Ensures global audio configuration exists, creates one `AudioEngine`
   * object through the recovered constructor lane, and registers it into the
   * process-global engine lane used by `SND_Frame`/`SND_Mute`.
   */
  boost::shared_ptr<AudioEngine> AudioEngine::Create(const gpg::StrArg voicePath)
  {
    SoundConfiguration* const configuration = EnsureSoundConfigurationForCreate();
    AudioEngine* const createdEngine = new AudioEngine(voicePath);

    boost::shared_ptr<AudioEngine> result(createdEngine);
    if (configuration != nullptr && createdEngine != nullptr) {
      RegisterEngineRef(*configuration, result);
    }

    return result;
  }

  /**
   * Address: 0x004D93F0 (FUN_004D93F0)
   *
   * What it does:
   * Detaches and destroys the current implementation object.
   */
  void AudioEngine::Shutdown()
  {
    AudioEngineImpl* const impl = mImpl;
    mImpl = nullptr;
    if (impl == nullptr) {
      return;
    }

    impl->~AudioEngineImpl();
    operator delete(impl);
  }

  /**
   * Address: 0x004D9760 (FUN_004D9760)
   *
   * What it does:
   * Releases the active implementation object when present.
   */
  AudioEngine::~AudioEngine()
  {
    if (mImpl == nullptr) {
      return;
    }

    mImpl->~AudioEngineImpl();
    operator delete(mImpl);
  }

  /**
   * Address: 0x004D9780 (FUN_004D9780)
   *
   * What it does:
   * Reconstructs the listener transform from stored 3D listener axes.
   */
  VTransform AudioEngine::GetListenerTransform()
  {
    VTransform out{};
    if (mImpl == nullptr) {
      return out;
    }

    out.pos_.x = mImpl->mListener.mPosition.x;
    out.pos_.y = mImpl->mListener.mPosition.y;
    out.pos_.z = mImpl->mListener.mPosition.z;
    out.orient_ = BuildListenerOrientation(mImpl->mListener);
    return out;
  }

  /**
   * Address: 0x004D9FF0 (FUN_004D9FF0)
   *
   * Moho::AudioEngine*, Moho::SoundConfiguration*
   *
   * What it does:
   * Initializes map/vector sentinels, 3D emitter/listener state, and DSP buffers.
   */
  AudioEngineImpl::AudioEngineImpl(AudioEngine* const engine, SoundConfiguration* const configuration)
    : mConfigs(configuration)
    , mEngine(engine)
    , mBanks{}
    , mHandles{}
    , mMap1{}
    , mInstance(nullptr)
    , mListener{}
    , mMap2{}
    , mGlobalCategoryVolume(0.0f)
    , mSettings{}
    , mEmitter{}
    , mAudioHandle{}
  {
    mBanks.mAllocatorCookie = nullptr;
    mBanks.mStart = nullptr;
    mBanks.mFinish = nullptr;
    mBanks.mEnd = nullptr;

    mHandles.mAllocatorCookie = nullptr;
    mHandles.mStart = nullptr;
    mHandles.mFinish = nullptr;
    mHandles.mEnd = nullptr;

    InitMap1Head(mMap1);
    InitCategoryMap(mMap2);
    mGlobalCategoryVolume = 0.0f;

    std::memset(&mSettings, 0, sizeof(mSettings));
    mSettings.mSrcChannelCount = 1u;
    mSettings.mDstChannelCount = ResolveDstChannelCount(configuration);
    mSettings.mDelayTimes = new float[mSettings.mDstChannelCount];
    mSettings.mMatrixCoefficients = new float[mSettings.mDstChannelCount * mSettings.mSrcChannelCount];

    std::memset(&mEmitter, 0, sizeof(mEmitter));
    mEmitter.mChannelCount = 1u;
    mEmitter.mCone = nullptr;
    mEmitter.mPosition.x = 0.0f;
    mEmitter.mPosition.y = 0.0f;
    mEmitter.mPosition.z = 0.0f;
    mEmitter.mVelocity.x = 0.0f;
    mEmitter.mVelocity.y = 0.0f;
    mEmitter.mVelocity.z = 0.0f;
    mEmitter.mCurveDistanceScaler = 1.0f;
    mEmitter.mOrientFront.z = 1.0f;
    mEmitter.mOrientTop.y = 1.0f;

    std::memset(&mListener, 0, sizeof(mListener));
    std::memset(mAudioHandle, 0, sizeof(mAudioHandle));
  }

  /**
   * Address: 0x004DA2A0 (FUN_004DA2A0)
   *
   * What it does:
   * Releases banks/maps/3D buffers and the active XACT engine instance.
   */
  AudioEngineImpl::~AudioEngineImpl()
  {
    if (mInstance != nullptr) {
      mInstance->ShutDown();
      mInstance->Release();
      mInstance = nullptr;
    }

    delete[] mSettings.mDelayTimes;
    mSettings.mDelayTimes = nullptr;
    delete[] mSettings.mMatrixCoefficients;
    mSettings.mMatrixCoefficients = nullptr;

    if (mHandles.mStart != nullptr) {
      DestroyAudioRuntimeHandleRange(mHandles.mStart, mHandles.mFinish);
      operator delete(mHandles.mStart);
    }
    mHandles.mStart = nullptr;
    mHandles.mFinish = nullptr;
    mHandles.mEnd = nullptr;

    if (mBanks.mStart != nullptr) {
      DestroyAudioSoundBankLoaderRange(mBanks.mStart, mBanks.mFinish);
      operator delete(mBanks.mStart);
    }
    mBanks.mStart = nullptr;
    mBanks.mFinish = nullptr;
    mBanks.mEnd = nullptr;

    ResetMap1(mMap1);

    ResetCategoryMap(mMap2);
    mMap2.mHead = nullptr;
    mMap2.mSize = 0;
  }

  /**
   * Address: 0x004D9B30 (FUN_004D9B30)
   *
   * std::uint16_t bankId, IXACTCue**, AudioEngine*, std::uint16_t cueId, std::int32_t preloadOnly
   *
   * What it does:
   * Dispatches cue playback through the current engine/bank selection.
   */
  int AudioEngine::Play(
    const std::uint16_t bankId,
    IXACTCue** const outCue,
    AudioEngine* const engine,
    const std::uint16_t cueId,
    const std::int32_t preloadOnly
  )
  {
    if (engine == nullptr || engine->mImpl == nullptr || engine->mImpl->mInstance == nullptr) {
      return 1;
    }

    AudioSoundBankLoader* const loader = FindBankLoader(engine->mImpl, bankId);
    if (loader == nullptr || loader->mBank == nullptr) {
      if (outCue != nullptr) {
        *outCue = nullptr;
      }
      return static_cast<int>(0x80004003u);
    }

    const int result =
      preloadOnly != 0 ? loader->mBank->Prepare(cueId, 0u, 0u, outCue) : loader->mBank->Play(cueId, 0u, 0u, outCue);
    if (result >= 0 || result == kXactErrCuePreparedOnly) {
      return result;
    }

    if (outCue != nullptr) {
      *outCue = nullptr;
    }

    gpg::Warnf(
      "SND: Error playing cue %i on bank %i [%s]\nXACT: %s",
      cueId,
      bankId,
      loader->mName.c_str(),
      func_SoundErrorCodeToMsg(result)
    );
    return result;
  }

  /**
   * Address: 0x004D9BD0 (FUN_004D9BD0)
   *
   * gpg::StrArg bankName, std::uint16_t* outBankId
   *
   * What it does:
   * Finds one loaded sound-bank index by case-insensitive bank name.
   */
  bool AudioEngine::GetBankIndex(const gpg::StrArg bankName, std::uint16_t* const outBankId)
  {
    if (bankName == nullptr || outBankId == nullptr || mImpl == nullptr || mImpl->mBanks.mStart == nullptr ||
        mImpl->mBanks.mFinish == nullptr) {
      return false;
    }

    const std::size_t bankCount = static_cast<std::size_t>(mImpl->mBanks.mFinish - mImpl->mBanks.mStart);
    for (std::size_t bankIndex = 0; bankIndex < bankCount; ++bankIndex) {
      auto* const loader = static_cast<AudioSoundBankLoader*>(mImpl->mBanks.mStart[bankIndex]);
      if (loader == nullptr || ::_stricmp(loader->mName.c_str(), bankName) != 0) {
        continue;
      }

      *outBankId = static_cast<std::uint16_t>(bankIndex);
      return true;
    }

    return false;
  }

  /**
   * Address: 0x004D9C40 (FUN_004D9C40)
   *
   * gpg::StrArg cueName, std::uint16_t bankId, std::uint16_t* outCueId
   *
   * What it does:
   * Resolves one cue index from one loaded sound bank.
   */
  bool AudioEngine::GetCueIndex(const gpg::StrArg cueName, const std::uint16_t bankId, std::uint16_t* const outCueId)
  {
    if (cueName == nullptr || outCueId == nullptr || mImpl == nullptr || mImpl->mBanks.mStart == nullptr ||
        mImpl->mBanks.mFinish == nullptr) {
      return false;
    }

    const std::size_t bankCount = static_cast<std::size_t>(mImpl->mBanks.mFinish - mImpl->mBanks.mStart);
    if (static_cast<std::size_t>(bankId) >= bankCount) {
      return false;
    }

    auto* const loader = static_cast<AudioSoundBankLoader*>(mImpl->mBanks.mStart[bankId]);
    if (loader == nullptr || loader->mBank == nullptr) {
      return false;
    }

    const std::uint16_t cueId = loader->mBank->GetCueIndex(cueName);
    *outCueId = cueId;
    return cueId != 0xFFFFu;
  }

  /**
   * Address: 0x004D9C90 (FUN_004D9C90, ?SetPaused@AudioEngine@Moho@@QAEXVStrArg@gpg@@_N@Z)
   *
   * gpg::StrArg category, bool paused
   *
   * What it does:
   * Pauses or unpauses one named sound category and updates the paused
   * category tracking map on success.
   */
  void AudioEngine::SetPaused(const gpg::StrArg category, const bool paused)
  {
    if (mImpl == nullptr || mImpl->mInstance == nullptr || !IsCategoryArgValid(category)) {
      return;
    }

    const std::uint16_t categoryId = mImpl->mInstance->GetCategory(category);
    if (categoryId == kInvalidCategoryId) {
      gpg::Warnf("SND: SetPaused - Invalid Category [%s]", category);
      return;
    }

    const int result = mImpl->mInstance->Pause(categoryId, paused ? 1 : 0);
    if (result < 0) {
      gpg::Warnf("SND: Error pausing category %s\n%s", category, func_SoundErrorCodeToMsg(result));
      return;
    }

    if (paused) {
      (void)InsertPausedCategoryName(mImpl->mMap1, category);
    } else {
      (void)ErasePausedCategoryName(mImpl->mMap1, category);
    }
  }

  /**
   * Address: 0x004D9EC0 (FUN_004D9EC0, ?GetPaused@AudioEngine@Moho@@QAE_NVStrArg@gpg@@@Z)
   *
   * gpg::StrArg category
   *
   * What it does:
   * Returns true when one category name exists in the paused-category map.
   */
  bool AudioEngine::GetPaused(const gpg::StrArg category)
  {
    if (mImpl == nullptr || mImpl->mInstance == nullptr || !IsCategoryArgValid(category)) {
      return false;
    }

    return CountPausedCategoryMatches(mImpl->mMap1, category) != 0;
  }

  /**
   * Address: 0x004D9F50 (FUN_004D9F50, ?StopAllSounds@AudioEngine@Moho@@QAEXVStrArg@gpg@@@Z)
   *
   * gpg::StrArg category
   *
   * What it does:
   * Stops all playing cues in one resolved XACT category.
   */
  void AudioEngine::StopAllSounds(const gpg::StrArg category)
  {
    if (mImpl == nullptr || mImpl->mInstance == nullptr || !IsCategoryArgValid(category)) {
      return;
    }

    const std::uint16_t categoryId = mImpl->mInstance->GetCategory(category);
    if (categoryId == kInvalidCategoryId) {
      gpg::Warnf("SND: StopAllSounds - Invalid Category [%s]", category);
      return;
    }

    mImpl->mInstance->Stop(categoryId, 0);
  }

  /**
   * Address: 0x004D9DB0 (FUN_004D9DB0)
   *
   * gpg::StrArg, float
   *
   * What it does:
   * Sets volume scalar for the named sound category.
   */
  void AudioEngine::SetVolume(const gpg::StrArg category, const float value)
  {
    if (mImpl == nullptr || mImpl->mInstance == nullptr || !IsCategoryArgValid(category)) {
      return;
    }

    const std::uint16_t categoryId = mImpl->mInstance->GetCategory(category);
    if (categoryId == kInvalidCategoryId) {
      gpg::Debugf("SND: SetVolume - InvalidCategory [%s]", category);
      return;
    }

    const int result = mImpl->mInstance->SetVolume(categoryId, value);
    if (result < 0) {
      gpg::Warnf("SND: Error setting volume for category %s\n%s", category, func_SoundErrorCodeToMsg(result));
    }

    *FindOrInsertCategoryVolume(mImpl->mMap2, categoryId) = value;
  }

  /**
   * Address: 0x004D9E50 (FUN_004D9E50)
   *
   * gpg::StrArg
   *
   * What it does:
   * Returns effective volume scalar for a category.
   */
  float AudioEngine::GetVolume(const gpg::StrArg category)
  {
    if (mImpl == nullptr || mImpl->mInstance == nullptr || !IsCategoryArgValid(category)) {
      return kDefaultCategoryVolume;
    }

    const std::uint16_t categoryId = mImpl->mInstance->GetCategory(category);
    if (categoryId == kInvalidCategoryId) {
      gpg::Debugf("SND: GetVolume - Invalid Category [%s]", category);
      return kDefaultCategoryVolume;
    }

    if (const float* const volume = FindCategoryVolume(mImpl->mMap2, categoryId); volume != nullptr) {
      return *volume;
    }

    return kDefaultCategoryVolume;
  }

  /**
   * Address: 0x004D9890 (FUN_004D9890)
   *
   * Moho::VTransform const&
   *
   * What it does:
   * Updates listener transform for 3D cue calculations.
   */
  void AudioEngine::SetListenerTransform(const VTransform& transform)
  {
    if (mImpl == nullptr) {
      return;
    }

    mImpl->mListener.mPosition.x = transform.pos_.x;
    mImpl->mListener.mPosition.y = transform.pos_.y - 4.0f;
    mImpl->mListener.mPosition.z = transform.pos_.z;

    const float x = transform.orient_.x;
    const float y = transform.orient_.y;
    const float z = transform.orient_.z;
    const float w = transform.orient_.w;

    mImpl->mListener.mOrientFront.x = ((x * z) + (w * y)) * 2.0f;
    mImpl->mListener.mOrientFront.y = ((w * z) - (x * y)) * 2.0f;
    mImpl->mListener.mOrientFront.z = 1.0f - (((z * z) + (y * y)) * 2.0f);

    mImpl->mListener.mOrientTop.x = ((z * y) - (x * w)) * 2.0f;
    mImpl->mListener.mOrientTop.y = 1.0f - (((w * w) + (y * y)) * 2.0f);
    mImpl->mListener.mOrientTop.z = ((w * z) + (x * y)) * 2.0f;
  }

  /**
   * Address: 0x004D9A60 (FUN_004D9A60)
   * Address: 0x0128E866 (FUN_0128E866, patch_AudioEngine_Calculate3D)
   *
   * Wm3::Vector3<float> const *, AudioEngine *, IXACTCue *
   *
   * IDA signature:
   * void callcnv_E3 Moho::AudioEngine::Calculate3D(
   *   Wm3::Vector3f *a1@<eax>, Moho::AudioEngine *a2@<ecx>, struct IXACTCue *a3
   * );
   *
   * What it does:
   * Applies 3D listener/emitter transform to an active cue.
   */
  void AudioEngine::Calculate3D(const Wm3::Vec3f* const worldPos, AudioEngine* const engine, IXACTCue* const cue)
  {
    AudioEngineImpl* const impl = engine->mImpl;
    if (impl->mInstance == nullptr) {
      return;
    }

    std::memset(&impl->mEmitter, 0, sizeof(impl->mEmitter));
    impl->mEmitter.mChannelCount = 1;
    impl->mEmitter.mCone = nullptr;
    impl->mEmitter.mPosition.x = worldPos->x;
    impl->mEmitter.mPosition.y = worldPos->y;
    impl->mEmitter.mPosition.z = worldPos->z;
    impl->mEmitter.mVelocity.x = 0.0f;
    impl->mEmitter.mVelocity.y = 0.0f;
    impl->mEmitter.mVelocity.z = 0.0f;
    impl->mEmitter.mCurveDistanceScaler = 1.0f;
    impl->mEmitter.mOrientFront.z = 1.0f;
    impl->mEmitter.mOrientTop.y = 1.0f;

    const int calculateResult = func_X3DAudioCalculate(
      &impl->mEmitter, &impl->mListener, &impl->mSettings, static_cast<const void*>(impl->mAudioHandle)
    );
    if (calculateResult < 0) {
      gpg::Warnf("SND: XACT3DCalculate failed.\n%s", func_SoundErrorCodeToMsg(calculateResult));
      return;
    }

    const int applyResult = ApplySettingsToCue(&impl->mSettings, cue);
    if (applyResult < 0) {
      gpg::Warnf("SND: XACT3DApply failed.\n%s", func_SoundErrorCodeToMsg(applyResult));
    }
  }

  /**
   * Address: 0x004D9FA0 (FUN_004D9FA0, ?IsStopped@AudioEngine@Moho@@QAE_NPAUIXACTCue@@@Z)
   *
   * IXACTCue* cue
   *
   * What it does:
   * Queries one cue state through `IXACTCue::GetState` and returns true when
   * the state equals `0x20` (stopped).
   */
  bool AudioEngine::IsStopped(IXACTCue* const cue) const
  {
    int cueState = static_cast<int>(reinterpret_cast<std::uintptr_t>(this));
    if (mImpl->mInstance == nullptr || cue == nullptr) {
      return false;
    }

    const bool queryFailed = cue->GetState(&cueState) < 0;
    if (queryFailed) {
      const char* const errorText = func_SoundErrorCodeToMsg(static_cast<int>(queryFailed));
      gpg::Warnf("SND: %s", errorText);
    }

    return cueState == 0x20;
  }
} // namespace moho
