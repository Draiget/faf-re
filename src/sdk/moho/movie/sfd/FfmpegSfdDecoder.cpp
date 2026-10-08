#include "FfmpegSfdDecoder.h"
#include <algorithm>
#include <cmath>
#include <stdexcept>
#include <utility>
extern "C" {
#include <libavcodec/avcodec.h>
#include <libavformat/avformat.h>
#include <libavutil/channel_layout.h>
#include <libavutil/error.h>
#include <libswresample/swresample.h>
#include <libswscale/swscale.h>
}

namespace moho::sfd
{
  namespace
  {
    void Check(
      int result,
      const char* operation
    )
    {
      if (result >= 0)
        return;
      char error[AV_ERROR_MAX_STRING_SIZE]{};
      av_strerror(result, error, sizeof(error));
      throw std::runtime_error(std::string(operation) + ": " + error);
    }
    struct FormatDelete
    {
      void operator()(
        AVFormatContext* p
      ) const
      {
        avformat_close_input(&p);
      }
    };
    struct CodecDelete
    {
      void operator()(
        AVCodecContext* p
      ) const
      {
        avcodec_free_context(&p);
      }
    };
    struct FrameDelete
    {
      void operator()(
        AVFrame* p
      ) const
      {
        av_frame_free(&p);
      }
    };
    struct PacketDelete
    {
      void operator()(
        AVPacket* p
      ) const
      {
        av_packet_free(&p);
      }
    };
    struct ScaleDelete
    {
      void operator()(
        SwsContext* p
      ) const
      {
        sws_freeContext(p);
      }
    };
    struct ResampleDelete
    {
      void operator()(
        SwrContext* p
      ) const
      {
        swr_free(&p);
      }
    };
    using Codec = std::unique_ptr<AVCodecContext, CodecDelete>;
    Codec OpenCodec(
      AVFormatContext* format,
      int index
    )
    {
      const auto* parameters = format->streams[index]->codecpar;
      const auto* decoder = avcodec_find_decoder(parameters->codec_id);
      if (!decoder)
        throw std::runtime_error("Required FFmpeg decoder unavailable");
      Codec result(avcodec_alloc_context3(decoder));
      if (!result)
        throw std::bad_alloc();
      Check(avcodec_parameters_to_context(result.get(), parameters), "codec parameters");
      result->thread_count = 2;
      Check(avcodec_open2(result.get(), decoder, nullptr), "open decoder");
      return result;
    }
  } // namespace
  struct FfmpegDecoder::Impl
  {
    std::unique_ptr<AVFormatContext, FormatDelete> format;
    Codec video, audio;
    std::unique_ptr<AVFrame, FrameDelete> frame{av_frame_alloc()};
    std::unique_ptr<AVPacket, PacketDelete> packet{av_packet_alloc()};
    std::unique_ptr<SwsContext, ScaleDelete> scale;
    std::unique_ptr<SwrContext, ResampleDelete> resample;
    int videoIndex{-1}, audioIndex{-1};
    double origin{}, nextVideo{}, nextAudio{}, frameDuration{1.0 / 30.0};
    bool drained{};

    double Timestamp(
      int stream,
      double fallback
    ) const
    {
      const auto pts = frame->best_effort_timestamp;
      return pts == AV_NOPTS_VALUE ? fallback : pts * av_q2d(format->streams[stream]->time_base) - origin;
    }
    void Video(
      DecodeBatch& batch
    )
    {
      if (frame->width <= 0 || frame->width > 4095 || frame->height <= 0 || frame->height > 4095)
        throw std::runtime_error("Unsupported movie dimensions");
      auto output = std::make_shared<DecodedVideoFrame>();
      output->width = frame->width;
      output->height = frame->height;
      output->pitch = frame->width * 4;
      output->pts = Timestamp(videoIndex, nextVideo);
      output->duration = frameDuration;
      nextVideo = output->pts + output->duration;
      output->bgra.resize(static_cast<std::size_t>(output->pitch) * output->height);
      // Recreate when format/geometry changes; cached-context ownership is explicit
      // because sws_getCachedContext may free the old context on failure.
      auto* context = sws_getCachedContext(
        scale.release(),
        frame->width,
        frame->height,
        static_cast<AVPixelFormat>(frame->format),
        frame->width,
        frame->height,
        AV_PIX_FMT_BGRA,
        SWS_BILINEAR,
        nullptr,
        nullptr,
        nullptr
      );
      scale.reset(context);
      if (!scale)
        throw std::runtime_error("Cannot create BGRA converter");
      const int* coefficients =
        sws_getCoefficients(frame->colorspace == AVCOL_SPC_BT709 ? SWS_CS_ITU709 : SWS_CS_ITU601);
      Check(
        sws_setColorspaceDetails(
          scale.get(), coefficients, frame->color_range == AVCOL_RANGE_JPEG, coefficients, 1, 0, 1 << 16, 1 << 16
        ),
        "video colour conversion"
      );
      std::uint8_t* destination[] = {output->bgra.data()};
      const int pitches[] = {output->pitch};
      Check(
        sws_scale(scale.get(), frame->data, frame->linesize, 0, frame->height, destination, pitches), "convert video"
      );
      // MPEG-1/2 has no alpha plane; swscale supplies opaque alpha in BGRA.
      batch.video.push_back(std::move(output));
    }
    void Audio(
      DecodeBatch& batch,
      bool flush = false
    )
    {
      if (!resample)
        return;
      const auto delay = swr_get_delay(resample.get(), audio->sample_rate);
      const int inputCount = flush ? 0 : frame->nb_samples;
      const auto capacity = av_rescale_rnd(delay + inputCount, 48000, audio->sample_rate, AV_ROUND_UP);
      if (capacity <= 0)
        return;
      if (capacity > 48000 * 10)
        throw std::runtime_error("Excessive audio frame size");
      DecodedAudioFrame output;
      output.pts = flush ? nextAudio
                         : Timestamp(audioIndex, nextAudio + static_cast<double>(delay) / audio->sample_rate) -
          static_cast<double>(delay) / audio->sample_rate;
      output.samples.resize(static_cast<std::size_t>(capacity) * 2);
      std::uint8_t* destination[] = {reinterpret_cast<std::uint8_t*>(output.samples.data())};
      const int count = swr_convert(
        resample.get(),
        destination,
        static_cast<int>(capacity),
        flush ? nullptr : const_cast<const std::uint8_t**>(frame->extended_data),
        inputCount
      );
      Check(count, "resample audio");
      output.samples.resize(static_cast<std::size_t>(count) * 2);
      nextAudio = output.pts + static_cast<double>(count) / 48000;
      if (count)
        batch.audio.push_back(std::move(output));
    }
    void Receive(
      AVCodecContext* codec,
      DecodeBatch& batch,
      bool isVideo
    )
    {
      for (;;) {
        const int result = avcodec_receive_frame(codec, frame.get());
        if (result == AVERROR(EAGAIN) || result == AVERROR_EOF)
          return;
        Check(result, "receive frame");
        if (isVideo)
          Video(batch);
        else
          Audio(batch);
        av_frame_unref(frame.get());
      }
    }
    void Send(
      AVCodecContext* codec,
      const AVPacket* input,
      DecodeBatch& batch,
      bool isVideo
    )
    {
      int result = avcodec_send_packet(codec, input);
      if (result == AVERROR(EAGAIN)) {
        Receive(codec, batch, isVideo);
        result = avcodec_send_packet(codec, input);
      }
      Check(result, "send packet");
      Receive(codec, batch, isVideo);
    }
  };
  FfmpegDecoder::FfmpegDecoder() = default;
  FfmpegDecoder::~FfmpegDecoder() = default;
  void FfmpegDecoder::Open(
    const char* filename,
    bool decodeAudio
  )
  {
    impl.reset();
    auto state = std::make_unique<Impl>();
    if (!state->frame || !state->packet)
      throw std::bad_alloc();
    AVFormatContext* format = nullptr;
    const int opened = avformat_open_input(&format, filename, av_find_input_format("mpeg"), nullptr);
    state->format.reset(format);
    Check(opened, "open MPEG program stream");
    Check(avformat_find_stream_info(format, nullptr), "discover streams");
    state->videoIndex = av_find_best_stream(format, AVMEDIA_TYPE_VIDEO, -1, -1, nullptr, 0);
    Check(state->videoIndex, "find movie video");
    const auto videoId = format->streams[state->videoIndex]->codecpar->codec_id;
    if (videoId != AV_CODEC_ID_MPEG1VIDEO && videoId != AV_CODEC_ID_MPEG2VIDEO)
      throw std::runtime_error("FAF SFD requires MPEG-1/2 video");
    state->video = OpenCodec(format, state->videoIndex);
    const AVRational rate = av_guess_frame_rate(format, format->streams[state->videoIndex], nullptr);
    if (rate.num > 0 && rate.den > 0)
      state->frameDuration = av_q2d(av_inv_q(rate));
    state->audioIndex = av_find_best_stream(format, AVMEDIA_TYPE_AUDIO, -1, -1, nullptr, 0);
    if (decodeAudio && state->audioIndex >= 0) {
      const auto id = format->streams[state->audioIndex]->codecpar->codec_id;
      if (id != AV_CODEC_ID_ADPCM_ADX && id != AV_CODEC_ID_MP1 && id != AV_CODEC_ID_MP2 && id != AV_CODEC_ID_MP3)
        throw std::runtime_error("Unsupported embedded SFD audio codec");
      state->audio = OpenCodec(format, state->audioIndex);
      if (state->audio->sample_rate <= 0)
        throw std::runtime_error("Invalid audio sample rate");
      SwrContext* swr = nullptr;
      const AVChannelLayout stereo = AV_CHANNEL_LAYOUT_STEREO;
      const int allocated = swr_alloc_set_opts2(
        &swr,
        &stereo,
        AV_SAMPLE_FMT_S16,
        48000,
        &state->audio->ch_layout,
        state->audio->sample_fmt,
        state->audio->sample_rate,
        0,
        nullptr
      );
      state->resample.reset(swr);
      Check(allocated, "create resampler");
      Check(swr_init(swr), "initialize resampler");
    }
    // One shared origin preserves the relative delay between audio and video.
    state->origin = format->start_time == AV_NOPTS_VALUE ? 0.0 : static_cast<double>(format->start_time) / AV_TIME_BASE;
    impl = std::move(state);
  }
  bool FfmpegDecoder::Read(
    DecodeBatch& batch
  )
  {
    batch = {};
    if (!impl || impl->drained)
      return false;
    auto& s = *impl;
    av_packet_unref(s.packet.get());
    const int result = av_read_frame(s.format.get(), s.packet.get());
    if (result == AVERROR_EOF) {
      s.Send(s.video.get(), nullptr, batch, true);
      if (s.audio) {
        s.Send(s.audio.get(), nullptr, batch, false);
        for (;;) {
          const auto count = batch.audio.size();
          s.Audio(batch, true);
          if (batch.audio.size() == count)
            break;
        }
      }
      s.drained = true;
      return !batch.video.empty() || !batch.audio.empty();
    }
    Check(result, "read movie packet");
    if (s.packet->stream_index == s.videoIndex)
      s.Send(s.video.get(), s.packet.get(), batch, true);
    else if (s.audio && s.packet->stream_index == s.audioIndex)
      s.Send(s.audio.get(), s.packet.get(), batch, false);
    av_packet_unref(s.packet.get());
    return true;
  }
  bool FfmpegDecoder::HasAudio() const
  {
    return impl && impl->audioIndex >= 0;
  }
  int FfmpegDecoder::Width() const
  {
    return impl ? impl->video->width : 0;
  }
  int FfmpegDecoder::Height() const
  {
    return impl ? impl->video->height : 0;
  }
  int FfmpegDecoder::AudioSampleRate() const
  {
    return impl && impl->audio ? impl->audio->sample_rate : 0;
  }
  int FfmpegDecoder::AudioChannels() const
  {
    return impl && impl->audio ? impl->audio->ch_layout.nb_channels : 0;
  }
} // namespace moho::sfd
