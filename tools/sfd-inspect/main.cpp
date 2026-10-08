#include "moho/audio/SofdecRuntime.h"
#include "moho/movie/sfd/DirectSoundMovieSink.h"
#include "moho/movie/sfd/FfmpegSfdDecoder.h"
#include "moho/movie/sfd/IndependentSfdBackend.h"
#include "moho/movie/sfd/SfdMetadata.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <thread>
// clang-format off
#include <windows.h>
#include <mmsystem.h>
#include <dsound.h>
// clang-format on

using namespace moho::sfd;
namespace
{
  void Require(
    bool success,
    const char* message
  )
  {
    if (!success)
      throw std::runtime_error(message);
  }
  void Inspect(
    const char* filename,
    bool decode
  )
  {
    Metadata metadata;
    std::string error;
    Require(ReadMetadata(filename, metadata, error), error.c_str());
    const auto& h = metadata.header;
    std::cout << filename << "\n  " << h.width << 'x' << h.height << " fps=" << h.fpsMilli / 1000.0
              << " frames=" << h.frameCount << " audio=" << unsigned(h.audioStreams)
              << " video=" << unsigned(h.videoStreams) << " mode=" << h.compositionMode
              << " effect=" << unsigned(h.videos[0].effect) << " pack=" << h.packSize << '\n';
    std::cout << "  IDs:";
    for (unsigned i = 0; i < h.elementCount; ++i)
      std::cout << ' ' << std::hex << unsigned(h.streamIds[i]);
    std::cout << std::dec << " private packet lengths:";
    for (const auto length : metadata.privatePacketLengths)
      std::cout << ' ' << length;
    std::cout << '\n';
    if (!decode)
      return;
    FfmpegDecoder decoder;
    decoder.Open(filename, true);
    std::size_t frames{}, samples{};
    double videoEnd{}, audioEnd{}, lastVideo{-1e9};
    DecodeBatch batch;
    while (decoder.Read(batch)) {
      for (const auto& f : batch.video) {
        Require(f->width == h.width && f->height == h.height, "Dimensions mismatch");
        Require(f->pts >= lastVideo, "Video timestamps out of order");
        lastVideo = f->pts;
        Require(f->bgra.size() == static_cast<std::size_t>(f->pitch) * f->height, "BGRA size mismatch");
        for (std::size_t i = 3; i < f->bgra.size(); i += 4)
          Require(f->bgra[i] == 255, "Nonopaque ordinary frame");
        ++frames;
        videoEnd = f->pts + f->duration;
      }
      for (const auto& f : batch.audio) {
        samples += f.samples.size() / 2;
        audioEnd = f.pts + f.samples.size() / 96000.0;
      }
    }
    Require(frames > 0, "No decoded frames");
    Require(!h.audioStreams || samples > 0, "Missing embedded audio");
    std::cout << "  decoded frames=" << frames << " stereo samples=" << samples << " videoEnd=" << videoEnd
              << " audioEnd=" << audioEnd << " source audio=" << decoder.AudioSampleRate() << "Hz/"
              << decoder.AudioChannels() << '\n';
  }
  void Playback(
    const char* filename,
    bool sound
  )
  {
    IDirectSound* device{};
    if (sound) {
      Require(SUCCEEDED(DirectSoundCreate(nullptr, &device, nullptr)), "No DirectSound device for test");
      Require(
        SUCCEEDED(device->SetCooperativeLevel(GetDesktopWindow(), DSSCL_NORMAL)), "DirectSound cooperative level failed"
      );
      SetSoundDevice(device);
    }
    try {
      moho::MwsfcreCreateParams parameters{};
      auto deleter = [](moho::MwsfdPlaybackStateSubobj* p) {
        mwPlyDestroy(p);
      };
      std::unique_ptr<moho::MwsfdPlaybackStateSubobj, decltype(deleter)> handle(
        mwPlyCreateSofdec(&parameters), deleter
      );
      Require(handle != nullptr, "Create failed");
      auto* p = handle.get();
      mwPlyStartFname(p, filename);
      Require(mwPlyGetStat(p) == 2, "Open failed");
      moho::MwsfdFrameInfo info{};
      mwPlyGetCurFrm(p, &info);
      Require(info.bufferAddress != nullptr, "No initial frame");
      const auto* frame = static_cast<const DecodedVideoFrame*>(info.bufferAddress);
      const int pitch = frame->pitch + 28;
      std::vector<std::uint8_t> destination(static_cast<std::size_t>(pitch) * frame->height + 32, 0xa5);
      mwPlyFxSetOutBufSize(p, pitch, frame->height);
      mwPlyFxCnvFrmARGB8888(p, &info, destination.data());
      for (int y = 0; y < frame->height; ++y) {
        Require(
          std::equal(
            frame->bgra.begin() + static_cast<std::size_t>(y) * frame->pitch,
            frame->bgra.begin() + static_cast<std::size_t>(y + 1) * frame->pitch,
            destination.begin() + static_cast<std::size_t>(y) * pitch
          ),
          "Texture copy mismatch"
        );
        for (int x = frame->pitch; x < pitch; ++x)
          Require(destination[static_cast<std::size_t>(y) * pitch + x] == 0xa5, "Texture padding overwritten");
      }
      Require(
        std::all_of(
          destination.end() - 32,
          destination.end(),
          [](auto b) {
        return b == 0xa5;
      }
        ),
        "Texture overrun"
      );
      mwPlyRelCurFrm(p);
      const auto playbackStart = std::chrono::steady_clock::now();
      Require(mwPlyPause(p, 0) != 0, "Resume failed");
      std::this_thread::sleep_for(std::chrono::milliseconds(3100));
      Require(mwPlyGetStat(p) != 4, "Worker failed");
      Require(mwPlyPause(p, 1) != 0, "Pause failed");
      mwPlyGetCurFrm(p, &info);
      Require(info.bufferAddress != nullptr, "Lost frame");
      const double frozen = static_cast<const DecodedVideoFrame*>(info.bufferAddress)->pts;
      const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - playbackStart).count();
      Require(std::abs(frozen - elapsed) < 0.25, "Playback clock drift exceeds 250 ms");
      mwPlyRelCurFrm(p);
      std::this_thread::sleep_for(std::chrono::milliseconds(200));
      mwPlyGetCurFrm(p, &info);
      Require(static_cast<const DecodedVideoFrame*>(info.bufferAddress)->pts == frozen, "Pause moved video");
      mwPlyRelCurFrm(p);
      SetVolume(-2000);
      Require(mwPlyPause(p, 0) != 0, "Second resume failed");
      std::this_thread::sleep_for(std::chrono::milliseconds(300));
      Require(mwPlyGetStat(p) != 4, "Resume worker failed");
      mwPlyStartFname(p, filename);
      Require(mwPlyGetStat(p) == 2, "Restart failed");
      mwPlyGetCurFrm(p, &info);
      Require(info.bufferAddress != nullptr, "Restart has no frame");
      Require(static_cast<const DecodedVideoFrame*>(info.bufferAddress)->pts < frozen, "Restart clock was not reset");
      mwPlyRelCurFrm(p);
      // Short portrait/video-only fixture also checks final-frame duration and EOF.
      Metadata metadata;
      std::string error;
      ReadMetadata(filename, metadata, error);
      const double duration = metadata.header.frameCount * 1000.0 / metadata.header.fpsMilli;
      if (duration < 15) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
        while (mwPlyGetStat(p) == 2 && std::chrono::steady_clock::now() < deadline)
          std::this_thread::sleep_for(std::chrono::milliseconds(10));
        Require(mwPlyGetStat(p) == 3, "EOF did not report ended");
      }
      for (int i = 0; i < 10; ++i) {
        mwPlyStartFname(p, filename);
        Require(mwPlyGetStat(p) == 2, "Repeated open failed");
      }
      mwPlyStartFname(p, "missing-faf-sfd-test.sfd");
      Require(mwPlyGetStat(p) == 4, "Missing file was accepted");
      Shutdown();
      Shutdown();
      std::cout << "Playback compatibility PASS sound=" << sound << " pausedPTS=" << frozen << '\n';
    } catch (...) {
      Shutdown();
      if (device)
        device->Release();
      throw;
    }
    Shutdown();
    if (device)
      device->Release();
  }
} // namespace
int main(
  int argc,
  char** argv
)
{
  try {
    SetErrorCallback([](std::uint32_t, const char* message) -> int {
      std::cerr << message << '\n';
      return 0;
    }, 0);
    if (argc < 3) {
      std::cerr << "sfd-inspect --metadata|--decode|--play|--play-sound file.sfd [...]\n";
      return 2;
    }
    const std::string mode = argv[1];
    for (int i = 2; i < argc; ++i) {
      if (mode == "--reject") {
        Player player;
        Require(!player.Open(argv[i]) && player.Status() == 4, "Unsupported file was accepted");
        std::cout << "Unsupported file rejected safely\n";
      } else if (mode == "--play" || mode == "--play-sound")
        Playback(argv[i], mode == "--play-sound");
      else
        Inspect(argv[i], mode == "--decode");
    }
    return 0;
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
