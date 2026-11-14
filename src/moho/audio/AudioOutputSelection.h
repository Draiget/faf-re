#pragma once

#include <mmdeviceapi.h>
#include <propsys.h>
#include <cstdint>
#include <string>

namespace moho
{
  struct AudioOutputDevice
  {
    std::wstring endpointId;
    std::wstring rendererId;
  };

  // XACT 2 uses the endpoint's DirectSound GUID, not its Core Audio endpoint ID.
  // Its defaultDevice flag also includes the communications default, which may
  // differ from the output selected for music and games in Windows.
  inline HRESULT ReadSelectedAudioOutput(IMMDeviceEnumerator& enumerator, AudioOutputDevice& output)
  {
    output = {};
    IMMDevice* device = nullptr;
    HRESULT result = enumerator.GetDefaultAudioEndpoint(eRender, eMultimedia, &device);
    if (FAILED(result)) return result;
    LPWSTR id = nullptr;
    result = device->GetId(&id);
    if (SUCCEEDED(result)) output.endpointId = id;
    CoTaskMemFree(id);
    IPropertyStore* properties = nullptr;
    if (SUCCEEDED(result)) result = device->OpenPropertyStore(STGM_READ, &properties);
    if (SUCCEEDED(result)) {
      // PKEY_AudioEndpoint_GUID (Windows SDK mmdeviceapi.h).
      constexpr PROPERTYKEY key{{0x1da5d803, 0xd492, 0x4edd, {0x8c,0x23,0xe0,0xc0,0xff,0xee,0x7f,0x0e}}, 4};
      PROPVARIANT value{};
      result = properties->GetValue(key, &value);
      if (SUCCEEDED(result)) {
        if (value.vt == VT_LPWSTR && value.pwszVal && *value.pwszVal) output.rendererId = value.pwszVal;
        else result = E_FAIL;
      }
      PropVariantClear(&value);
      properties->Release();
    }
    device->Release();
    return result;
  }

  constexpr bool IsAudioOutputLost(const std::int32_t result)
  {
    // Other DoWork failures include content/streaming errors; rebuilding the
    // renderer for those can cut all sounds short once a second indefinitely.
    const auto code = static_cast<std::uint32_t>(result);
    return code == 0x8AC70017u || code == 0x88890004u || code == 0x88960004u;
  }
}
