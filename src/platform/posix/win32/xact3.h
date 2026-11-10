#pragma once

// Engine addition (issue #258): <xact3.h> for the Linux client, from FAudio's FACT (FAudio 26.10,
// cmake/FafDependencies.cmake), the XACT reimplementation Wine's XACT engines use. FACT keeps
// XACT's structures field for field, so the XACT names are aliases of FACT's; the engine object
// itself is platform/posix/XactOverFact.cpp, created where Windows calls CoCreateInstance.
//
// Only the Linux client puts FAudio's headers on its include path; the simulation never includes
// this header.

#if defined(_WIN32)
#error "platform/posix/win32/xact3.h is for builds without the Windows SDK"
#endif

#include <cstdint>
#include <type_traits>

#include <FACT.h>

#include <Windows.h>

namespace platform::posix::xact_detail
{
  // The pointee of a two-argument C function's second parameter.
  template <typename Function>
  struct SecondParameter;
  template <typename Result, typename First, typename Second>
  struct SecondParameter<Result (*)(First, Second)>
  {
    using type = std::remove_cv_t<std::remove_pointer_t<Second>>;
  };
} // namespace platform::posix::xact_detail

using XACT_FILEIO_CALLBACKS = FACTFileIOCallbacks;
using XACT_NOTIFICATION_CALLBACK = FACTNotificationCallback;
// The structure FACTAudioEngine_Initialize takes (XACT's own name for it is the alias).
using XACT_RUNTIME_PARAMETERS =
  platform::posix::xact_detail::SecondParameter<decltype(&FACTAudioEngine_Initialize)>::type;
using XACT_STREAMING_PARAMETERS = FACTStreamingParameters;
using XACT_NOTIFICATION_DESCRIPTION = FACTNotificationDescription;
using XACT_NOTIFICATION = FACTNotification;
using XACTINDEX = std::uint16_t;
using XACTCATEGORY = std::uint16_t;
using XACTVARIABLEINDEX = std::uint16_t;

constexpr std::uint8_t XACTNOTIFICATIONTYPE_CUEPREPARED = FACTNOTIFICATIONTYPE_CUEPREPARED;
constexpr std::uint8_t XACTNOTIFICATIONTYPE_CUEPLAY = FACTNOTIFICATIONTYPE_CUEPLAY;
constexpr std::uint8_t XACTNOTIFICATIONTYPE_CUESTOP = FACTNOTIFICATIONTYPE_CUESTOP;
constexpr std::uint8_t XACTNOTIFICATIONTYPE_CUEDESTROYED = FACTNOTIFICATIONTYPE_CUEDESTROYED;
constexpr std::uint8_t XACTNOTIFICATIONTYPE_SOUNDBANKDESTROYED = FACTNOTIFICATIONTYPE_SOUNDBANKDESTROYED;
constexpr std::uint8_t XACTNOTIFICATIONTYPE_WAVEBANKDESTROYED = FACTNOTIFICATIONTYPE_WAVEBANKDESTROYED;
constexpr std::uint8_t XACTNOTIFICATIONTYPE_WAVEBANKPREPARED = FACTNOTIFICATIONTYPE_WAVEBANKPREPARED;
constexpr std::uint8_t XACTNOTIFICATIONTYPE_WAVEBANKSTREAMING_INVALIDCONTENT =
  FACTNOTIFICATIONTYPE_WAVEBANKSTREAMING_INVALIDCONTENT;

constexpr std::uint32_t XACT_FLAG_STOP_RELEASE = FACT_FLAG_STOP_RELEASE;
constexpr std::uint32_t XACT_FLAG_STOP_IMMEDIATE = FACT_FLAG_STOP_IMMEDIATE;
constexpr std::uint32_t XACT_STATE_PLAYING = FACT_STATE_PLAYING;
constexpr std::uint32_t XACT_STATE_STOPPED = FACT_STATE_STOPPED;
constexpr std::uint32_t XACT_STATE_PAUSED = FACT_STATE_PAUSED;
constexpr std::uint32_t XACT_STATE_PREPARED = FACT_STATE_PREPARED;
constexpr std::uint16_t XACTINDEX_INVALID = FACTINDEX_INVALID;
constexpr std::uint16_t XACTVARIABLEINDEX_INVALID = FACTVARIABLEINDEX_INVALID;
constexpr std::uint16_t XACTCATEGORY_INVALID = FACTCATEGORY_INVALID;
