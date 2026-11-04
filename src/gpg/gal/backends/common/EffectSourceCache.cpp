#include "gpg/gal/backends/common/EffectSourceCache.h"

#include <Windows.h>
#include <d3dcompiler.h>
#include <wrl/client.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

#include "gpg/core/utils/LocalCache.h"
#include "gpg/gal/EffectContext.hpp"
#include "gpg/gal/backends/common/BackendErrors.h"
#include "gpg/gal/effects/EffectRuntime.h"

namespace gpg::gal::effects
{
  namespace
  {
    // Bump when the cache file's layout changes; the translator itself is keyed by the executable.
    constexpr const char* kTranslationCacheVersion = "faf translated effect 1";

    std::atomic<EffectSourceBuilder> gBuilder{nullptr};

    [[nodiscard]] bool CacheEnabled()
    {
      static const bool startupOff = [] {
        const wchar_t* const commandLine = ::GetCommandLineW();
        return commandLine != nullptr && std::wcsstr(commandLine, L"/noeffectcache") != nullptr;
      }();
      return gEffectSourceCache && !startupOff;
    }

    // Translations PrepareEffectSources made, until CreateEffect takes them.
    std::mutex gWaitingLock;
    std::map<std::uint64_t, d3d11::TranslatedEffectSource> gWaiting;
    thread_local bool tPreparing = false; // on a PrepareEffectSources worker

    // Cached as the notes, one per line, a NUL, then the source.
    [[nodiscard]] bool ReadTranslation(const std::uint64_t key, d3d11::TranslatedEffectSource& out)
    {
      std::vector<std::uint8_t> bytes;
      if (!ReadShaderCache(key, "fxt", bytes)) {
        return false;
      }
      const std::string_view text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
      const std::size_t split = text.find('\0');
      if (split == std::string_view::npos) {
        return false;
      }
      out = {};
      for (std::size_t start = 0U; start < split;) {
        const std::size_t end = text.find('\n', start);
        out.notes.emplace_back(text.substr(start, end - start));
        start = end + 1U;
      }
      out.source.assign(text.substr(split + 1U));
      return true;
    }

    void WriteTranslation(const std::uint64_t key, const d3d11::TranslatedEffectSource& translation)
    {
      std::string text;
      for (const std::string& note : translation.notes) {
        text += note + '\n';
      }
      text += '\0';
      text += translation.source;
      WriteShaderCache(key, "fxt", std::vector<std::uint8_t>(text.begin(), text.end()));
    }
  } // namespace

  bool gEffectSourceCache = true;

  d3d11::TranslatedEffectSource TranslateEffect(const EffectContext& context, const char* const errorFile)
  {
    std::vector<D3D_SHADER_MACRO> defines;
    for (const EffectMacro& macro : context.mMacros) {
      defines.push_back(D3D_SHADER_MACRO{macro.keyText_.c_str(), macro.valueText_.c_str()});
    }
    defines.push_back(D3D_SHADER_MACRO{nullptr, nullptr});
    const char* const sourceName = context.mSourcePath.c_str();
    const std::size_t sourceBytes = static_cast<std::size_t>(context.mSourceBuffer.mEnd - context.mSourceBuffer.mBegin);
    Microsoft::WRL::ComPtr<ID3DBlob> preprocessed;
    Microsoft::WRL::ComPtr<ID3DBlob> errors;
    if (FAILED(::D3DPreprocess(context.mSourceBuffer.mBegin, sourceBytes, sourceName, defines.data(), nullptr, &preprocessed, &errors))) {
      const std::string message = std::string("unable to preprocess effect: ") + sourceName + " reason: " +
        ((errors != nullptr) ? std::string(static_cast<const char*>(errors->GetBufferPointer()), errors->GetBufferSize()) : std::string());
      backend::ThrowError(errorFile, __LINE__, message.c_str());
    }
    const std::string_view source(static_cast<const char*>(preprocessed->GetBufferPointer()), preprocessed->GetBufferSize() - 1U);
    // No original source: the D3D9 alpha test is applied by the effect layer (EffectDescription),
    // and running the translator's copy as well would test twice.
    const auto translate = [&] { return d3d11::TranslateEffectSource(source, true, std::string_view{}); };
    if (!CacheEnabled()) {
      return translate();
    }

    Fnv1a64 hash;
    hash.Add(kTranslationCacheVersion);
    const std::uint64_t identity = gpg::ExecutableIdentity();
    hash.Add(&identity, sizeof(identity));
    hash.Add(source);
    const std::uint64_t key = hash.Value();

    if (!tPreparing) {
      const std::lock_guard<std::mutex> guard(gWaitingLock);
      if (const auto waiting = gWaiting.find(key); waiting != gWaiting.end()) {
        d3d11::TranslatedEffectSource result = std::move(waiting->second);
        gWaiting.erase(waiting);
        return result;
      }
    }
    d3d11::TranslatedEffectSource result;
    if (!ReadTranslation(key, result)) {
      result = translate();
      WriteTranslation(key, result);
    }
    if (tPreparing) {
      const std::lock_guard<std::mutex> guard(gWaitingLock);
      gWaiting.insert_or_assign(key, result);
    }
    return result;
  }

  void SetEffectSourceBuilder(const EffectSourceBuilder builder) noexcept
  {
    gBuilder.store(builder);
  }

  void PrepareEffectSources(const std::vector<EffectContext>& contexts)
  {
    const EffectSourceBuilder builder = gBuilder.load();
    if (builder == nullptr || contexts.empty() || !CacheEnabled()) {
      return;
    }
    {
      const std::lock_guard<std::mutex> guard(gWaitingLock);
      gWaiting.clear(); // whatever an earlier set left untaken is stale by now
    }

    // The longest effects go first; each worker then takes the next one left.
    std::vector<const EffectContext*> order;
    for (const EffectContext& context : contexts) {
      order.push_back(&context);
    }
    std::stable_sort(order.begin(), order.end(), [](const EffectContext* const a, const EffectContext* const b) {
      return (a->mSourceBuffer.mEnd - a->mSourceBuffer.mBegin) > (b->mSourceBuffer.mEnd - b->mSourceBuffer.mBegin);
    });
    std::atomic<std::size_t> next{0U};
    const auto work = [&] {
      tPreparing = true;
      for (std::size_t index = next++; index < order.size(); index = next++) {
        try {
          (void)builder(*order[index]);
        } catch (...) {
          // CreateEffect builds it again and reports the failure.
        }
      }
      tPreparing = false;
    };
    std::vector<std::thread> helpers(std::min<std::size_t>(order.size(), std::max(1U, std::thread::hardware_concurrency())) - 1U);
    for (std::thread& helper : helpers) {
      helper = std::thread(work);
    }
    work();
    for (std::thread& helper : helpers) {
      helper.join();
    }
  }
} // namespace gpg::gal::effects
