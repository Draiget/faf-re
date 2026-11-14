#include "moho/audio/AudioOutputWatch.h"

#if FAFRE_PLATFORM_WINDOWS
#include <Windows.h>
#include <mmdeviceapi.h>

#include <atomic>
#include <mutex>
#include <string>

#include "gpg/core/utils/Logging.h"

namespace moho
{
  namespace
  {
    /**
     * The `IMMNotificationClient` Windows calls. It only counts: the engine is rebuilt later on the
     * main thread, never from inside a callback (Windows forbids waiting on its own audio calls
     * there). It lives until the process ends, registered all that time.
     */
    class OutputWatch final : public AudioOutputWatch, public IMMNotificationClient
    {
    public:
      explicit OutputWatch(
        IMMDeviceEnumerator* const enumerator
      )
        : mEnumerator(enumerator)
      {
        mDefaultId = DefaultId(enumerator, eConsole);
        mMultimediaId = DefaultId(enumerator, eMultimedia);
      }

      [[nodiscard]] std::uint32_t Changes() const override
      {
        return mChanges.load(std::memory_order_acquire);
      }

      HRESULT STDMETHODCALLTYPE QueryInterface(
        REFIID iid,
        void** const object
      ) override
      {
        if (object == nullptr) {
          return E_POINTER;
        }
        if (iid == __uuidof(IUnknown) || iid == __uuidof(IMMNotificationClient)) {
          *object = static_cast<IMMNotificationClient*>(this);
          return S_OK;
        }
        *object = nullptr;
        return E_NOINTERFACE;
      }

      // Lives as long as the process: Windows' references don't own it.
      ULONG STDMETHODCALLTYPE AddRef() override
      {
        return 1;
      }
      ULONG STDMETHODCALLTYPE Release() override
      {
        return 1;
      }

      HRESULT STDMETHODCALLTYPE OnDefaultDeviceChanged(
        const EDataFlow flow,
        const ERole role,
        LPCWSTR const id
      ) override
      {
        // Games and media follow eConsole and eMultimedia; Windows sets both as "Default Device".
        // The communications default (calls) is left alone.
        if (flow != eRender || (role != eConsole && role != eMultimedia)) {
          return S_OK;
        }
        {
          // Windows reports setting the default it already has too; a rebuild would only restart
          // every sound. Each role is compared with its own last default.
          const std::lock_guard<std::mutex> guard(mLock);
          std::wstring& known = role == eConsole ? mDefaultId : mMultimediaId;
          const std::wstring newId = id != nullptr ? id : L"";
          if (newId == known) {
            return S_OK;
          }
          known = newId;
        }
        mChanges.fetch_add(1u, std::memory_order_acq_rel);
        return S_OK;
      }

      HRESULT STDMETHODCALLTYPE OnDeviceStateChanged(
        LPCWSTR const id,
        const DWORD state
      ) override
      {
        if (state != DEVICE_STATE_ACTIVE) {
          OutputGone(id);
        }
        return S_OK;
      }

      HRESULT STDMETHODCALLTYPE OnDeviceRemoved(
        LPCWSTR const id
      ) override
      {
        OutputGone(id);
        return S_OK;
      }

      HRESULT STDMETHODCALLTYPE OnDeviceAdded(
        LPCWSTR
      ) override
      {
        return S_OK;
      }

      HRESULT STDMETHODCALLTYPE OnPropertyValueChanged(
        LPCWSTR,
        const PROPERTYKEY
      ) override
      {
        return S_OK;
      }

    private:
      [[nodiscard]] static std::wstring DefaultId(
        IMMDeviceEnumerator* const enumerator,
        const ERole role
      )
      {
        std::wstring result;
        IMMDevice* device = nullptr;
        if (SUCCEEDED(enumerator->GetDefaultAudioEndpoint(eRender, role, &device)) && device != nullptr) {
          LPWSTR id = nullptr;
          if (SUCCEEDED(device->GetId(&id)) && id != nullptr) {
            result = id;
            ::CoTaskMemFree(id);
          }
          device->Release();
        }
        return result;
      }

      // The default output was disabled or unplugged. Windows usually names a new default too,
      // but not when no output is left; counting here covers that case.
      void OutputGone(
        LPCWSTR const id
      )
      {
        if (id == nullptr) {
          return;
        }
        {
          const std::lock_guard<std::mutex> guard(mLock);
          if (mDefaultId != id) {
            return;
          }
        }
        mChanges.fetch_add(1u, std::memory_order_acq_rel);
      }

      IMMDeviceEnumerator* mEnumerator;
      std::atomic<std::uint32_t> mChanges{0u};
      std::mutex mLock;
      std::wstring mDefaultId;    // eConsole's default render endpoint
      std::wstring mMultimediaId; // eMultimedia's
    };
  } // namespace

  AudioOutputWatch* AudioOutputWatch::Start()
  {
    IMMDeviceEnumerator* enumerator = nullptr;
    HRESULT result =
      ::CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&enumerator));
    if (FAILED(result) || enumerator == nullptr) {
      gpg::Warnf("SND: can't watch the sound output for changes (0x%08X)", static_cast<unsigned>(result));
      return nullptr;
    }

    auto* const watch = new OutputWatch(enumerator);
    result = enumerator->RegisterEndpointNotificationCallback(watch);
    if (FAILED(result)) {
      gpg::Warnf("SND: can't watch the sound output for changes (0x%08X)", static_cast<unsigned>(result));
      delete watch;
      enumerator->Release();
      return nullptr;
    }
    return watch;
  }
} // namespace moho
#endif
