#include "moho/audio/AudioEngine.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <vector>
#include <windows.h>
#include <mmreg.h>
#include <mmsystem.h>
#include <dsound.h>

#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/String.h"
#include "moho/audio/XAudioError.h"
#include "moho/misc/CVirtualFileSystem.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/camera/VTransform.h"

moho::SoundConfiguration* moho::sSoundConfiguration = nullptr;

extern "C" __declspec(dllimport) void __stdcall X3DAudioCalculate(
  const void* instance,
  const moho::Audio3DListener* listener,
  const moho::Audio3DEmitter* emitter,
  std::uint32_t flags,
  moho::Audio3DDspSettings* dspSettings
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

  void DestroyCategoryMapSubtree(AudioCategoryVolumeNode* node, const AudioCategoryVolumeNode* head)
  {
    if (node == nullptr || node == head || node->mIsNil != 0u) {
      return;
    }

    DestroyCategoryMapSubtree(node->mLeft, head);
    DestroyCategoryMapSubtree(node->mRight, head);
    delete node;
  }

  void ResetCategoryMap(moho::AudioMapStorage& map)
  {
    auto* const head = AsCategoryMapHead(map);
    if (head == nullptr) {
      map.mSize = 0;
      return;
    }

    DestroyCategoryMapSubtree(head->mLeft, head);
    delete head;
    map.mHead = nullptr;
    map.mSize = 0;
  }

  void InitCategoryMap(moho::AudioMapStorage& map)
  {
    map.mAllocatorCookie = nullptr;
    map.mSize = 0;

    auto* const head = new AudioCategoryVolumeNode{};
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

  [[nodiscard]] float* FindOrInsertCategoryVolume(moho::AudioMapStorage& map, const std::uint16_t category)
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
        return &node->mVolume;
      }
    }

    auto* const inserted = new AudioCategoryVolumeNode{};
    inserted->mLeft = head;
    inserted->mRight = head;
    inserted->mParent = (parent == head) ? head : parent;
    inserted->mCategory = category;
    inserted->mPad0E = 0;
    inserted->mVolume = kDefaultCategoryVolume;
    inserted->mColor = 0;
    inserted->mIsNil = 0;
    inserted->mPad16[0] = 0;
    inserted->mPad16[1] = 0;

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
    return &inserted->mVolume;
  }

  [[nodiscard]] const float* FindCategoryVolume(const moho::AudioMapStorage& map, const std::uint16_t category)
  {
    const auto* const head = AsCategoryMapHead(map);
    if (head == nullptr) {
      return nullptr;
    }

    const AudioCategoryVolumeNode* node = head->mParent;
    while (node != nullptr && node != head && node->mIsNil == 0u) {
      if (category < node->mCategory) {
        node = node->mLeft;
      } else if (category > node->mCategory) {
        node = node->mRight;
      } else {
        return &node->mVolume;
      }
    }

    return nullptr;
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

  [[nodiscard]] AudioMap1CategoryNode* AsMap1Head(const moho::AudioMapStorage& map)
  {
    return static_cast<AudioMap1CategoryNode*>(map.mHead);
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

    auto* const head = new AudioMap1CategoryNode{};
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

  void ResetMap1(moho::AudioMapStorage& map)
  {
    AudioMap1CategoryNode* const head = AsMap1Head(map);
    if (head == nullptr) {
      map.mSize = 0;
      return;
    }

    DestroyMap1Subtree(head->mParent, head);
    head->mCategoryName.tidy(true);
    delete head;
    map.mHead = nullptr;
    map.mSize = 0;
  }

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

    auto* const inserted = new AudioMap1CategoryNode{};
    inserted->mLeft = head;
    inserted->mRight = head;
    inserted->mParent = (parent == head) ? head : parent;
    inserted->mCategoryName.assign_owned(categoryName);
    inserted->mColor = 0;
    inserted->mIsNil = 0;
    inserted->mPad2A[0] = 0;
    inserted->mPad2A[1] = 0;

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

  [[nodiscard]] bool ErasePausedCategoryName(moho::AudioMapStorage& map, const char* const categoryName)
  {
    if (categoryName == nullptr || *categoryName == '\0') {
      return false;
    }

    AudioMap1CategoryNode* const head = AsMap1Head(map);
    if (head == nullptr || FindMap1CategoryNode(map, categoryName) == nullptr) {
      return false;
    }

    std::vector<std::string> retainedNames;
    retainedNames.reserve(map.mSize > 0u ? map.mSize - 1u : 0u);
    CollectRetainedPausedCategoryNames(head->mParent, head, categoryName, retainedNames);

    DestroyMap1Subtree(head->mParent, head);
    head->mParent = head;
    head->mLeft = head;
    head->mRight = head;
    map.mSize = 0;

    for (const std::string& retainedName : retainedNames) {
      (void)InsertPausedCategoryName(map, retainedName.c_str());
    }

    return true;
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

  void ReserveEngineRefCapacity(moho::AudioEngineRefVector& engines, const std::size_t requiredCount)
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
    auto* const newStorage = static_cast<moho::AudioEngineRef*>(operator new[](targetCapacity * sizeof(moho::AudioEngineRef)));
    if (currentCount != 0u) {
      std::memcpy(newStorage, engines.mStart, currentCount * sizeof(moho::AudioEngineRef));
    }

    operator delete[](engines.mStart);
    engines.mStart = newStorage;
    engines.mFinish = newStorage + currentCount;
    engines.mCapacity = newStorage + targetCapacity;
  }

  [[nodiscard]] const boost::SharedPtrLayoutView<moho::AudioEngine>&
  AsSharedLayout(const boost::shared_ptr<moho::AudioEngine>& value)
  {
    return *reinterpret_cast<const boost::SharedPtrLayoutView<moho::AudioEngine>*>(&value);
  }

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

  void RegisterEngineRef(
    moho::SoundConfiguration& configuration, const boost::shared_ptr<moho::AudioEngine>& engineRef
  )
  {
    const auto& engineLayout = AsSharedLayout(engineRef);
    if (engineLayout.px == nullptr) {
      return;
    }

    moho::AudioEngineRefVector& engines = configuration.mEngines;
    const std::size_t currentCount =
      engines.mStart == nullptr || engines.mFinish == nullptr ? 0u : static_cast<std::size_t>(engines.mFinish - engines.mStart);
    ReserveEngineRefCapacity(engines, currentCount + 1u);

    engines.mFinish->mEngine = engineLayout.px;
    engines.mFinish->mControl = engineLayout.pi;
    if (engineLayout.pi != nullptr) {
      engineLayout.pi->add_ref_copy();
    }
    ++engines.mFinish;
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
  int func_CreateXACTinstance(std::uint32_t mode, void** outEngine);
  int func_AudioInitialize(IXACTEngine* engine, void* audioHandle);
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

    SoundConfiguration* const previousConfiguration = sSoundConfiguration;
    sSoundConfiguration = freshConfiguration;
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
    SoundConfiguration* const configuration = sSoundConfiguration;
    sSoundConfiguration = nullptr;
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
    const SoundConfiguration* const configuration = sSoundConfiguration;
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
    SoundConfiguration* configuration = sSoundConfiguration;
    for (std::uint32_t index = 0;; ++index) {
      if (index >= configuration->EngineCount()) {
        break;
      }

      if (AudioEngineImpl* const impl = configuration->EngineImplAt(index);
          impl != nullptr && impl->mInstance != nullptr) {
        impl->mInstance->DoWork();
        configuration = sSoundConfiguration;
      }
    }

    configuration->mTime.Reset();
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
    SoundConfiguration* configuration = sSoundConfiguration;
    for (std::uint32_t index = 0;; ++index) {
      if (index >= configuration->EngineCount()) {
        break;
      }

      AudioEngineImpl* const impl = configuration->EngineImplAt(index);
      if (impl == nullptr || impl->mInstance == nullptr) {
        continue;
      }

      const float volume = doMute
        ? (impl->mGlobalCategoryVolume = impl->mEngine->GetVolume(kGlobalCategoryName), 0.0f)
        : impl->mGlobalCategoryVolume;
      impl->mEngine->SetVolume(kGlobalCategoryName, volume);
      configuration = sSoundConfiguration;
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
    AudioEngineImpl* const previousImpl = mImpl;
    mImpl = new AudioEngineImpl(this, configuration);
    if (previousImpl != nullptr) {
      previousImpl->~AudioEngineImpl();
      operator delete(previousImpl);
    }

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
      for (void** entry = mHandles.mStart; entry != mHandles.mFinish; ++entry) {
        if (*entry == nullptr) {
          continue;
        }

        auto* const vtable = *reinterpret_cast<void***>(*entry);
        if (vtable != nullptr && vtable[0] != nullptr) {
          using DestroyFn = void(__thiscall*)(void*, std::uint8_t);
          reinterpret_cast<DestroyFn>(vtable[0])(*entry, 1u);
        }
      }
      operator delete(mHandles.mStart);
    }
    mHandles.mStart = nullptr;
    mHandles.mFinish = nullptr;
    mHandles.mEnd = nullptr;

    if (mBanks.mStart != nullptr) {
      for (void** entry = mBanks.mStart; entry != mBanks.mFinish; ++entry) {
        auto* const loader = static_cast<AudioSoundBankLoader*>(*entry);
        delete loader;
      }
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

    return FindMap1CategoryNode(mImpl->mMap1, category) != nullptr;
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
