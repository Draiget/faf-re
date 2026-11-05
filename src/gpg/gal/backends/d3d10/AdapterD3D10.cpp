#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{
namespace
{

    constexpr DXGI_FORMAT kAdapterProbeFormats[8] = {
      static_cast<DXGI_FORMAT>(10),
      static_cast<DXGI_FORMAT>(24),
      static_cast<DXGI_FORMAT>(28),
      static_cast<DXGI_FORMAT>(29),
      static_cast<DXGI_FORMAT>(85),
      static_cast<DXGI_FORMAT>(86),
      static_cast<DXGI_FORMAT>(87),
      static_cast<DXGI_FORMAT>(88),
    };

    /**
     * Address: 0x008F71D0 (FUN_008F71D0)
     *
     * What it does:
     * Initializes one adapter-mode entry from `(format, output)`, resets its
     * embedded mode-vector lanes, and snapshots one output descriptor.
     */
    AdapterModeD3D10* InitializeAdapterModeEntry(
      AdapterModeD3D10* const entry,
      const std::uint32_t format,
      IDXGIOutput* const output
    )
    {
      entry->format_ = format;
      entry->output_ = output;
      entry->modes_.clear();
      entry->outputDesc_ = {};
      if (output != nullptr) {
        static_cast<void>(output->GetDesc(&entry->outputDesc_));
      }
      return entry;
    }
}


  /**
   * Address: 0x008F7AC0 (FUN_008F7AC0)
   *
   * IDXGIAdapter *
   *
   * What it does:
   * Initializes one adapter wrapper from one DXGI adapter pointer and captures
   * the adapter descriptor payload.
   */
  AdapterD3D10::AdapterD3D10(IDXGIAdapter* const dxgiAdapter)
    : dxgiAdapter_(dxgiAdapter)
    , description_()
    , modes_()
  {
    if (dxgiAdapter_ != nullptr) {
      static_cast<void>(dxgiAdapter_->GetDesc(&description_));
    }
  }

  /**
   * Address: 0x008FF450 (FUN_008FF450)
   *
   * What it does:
   * Copy-constructs one adapter wrapper by cloning descriptor payload and
   * deep-copying cached mode vectors from `other`.
   */
  AdapterD3D10::AdapterD3D10(const AdapterD3D10& other)
    : dxgiAdapter_(other.dxgiAdapter_)
    , description_(other.description_)
    , modes_(other.modes_)
  {}

  /**
   * Address: 0x008FF2F0 (FUN_008FF2F0)
   *
   * What it does:
   * Copy-assigns adapter pointer/descriptor lanes and deep-copies the cached
   * mode-vector lane from `other`.
   */
  AdapterD3D10& AdapterD3D10::operator=(const AdapterD3D10& other)
  {
    dxgiAdapter_ = other.dxgiAdapter_;
    description_ = other.description_;
    modes_ = other.modes_;
    return *this;
  }

  /**
   * Address: 0x008F7CF0 (FUN_008F7CF0, sub_8F7CF0)
   *
   * What it does:
   * Enumerates outputs and cached display-mode lists for the recovered DXGI
   * format probe set into the local mode cache.
   */
  int AdapterD3D10::ProbeOutputsAndModes()
  {
    IDXGIOutput* output = nullptr;
    const HRESULT result = dxgiAdapter_->EnumOutputs(0U, &output);
    if (result == DXGI_ERROR_NOT_FOUND) {
      return 0;
    }

    if (result >= 0) {
      // One entry per probe, built before the format loop and appended once
      // after it (0x008F7D8C-0x008F7DA2 sets it up, 0x008F7E85 pushes it).
      // `format_` is left at zero here — the binary never writes the probed
      // format into the entry; the entry describes the *output*, and every
      // format's modes accumulate into its single `modes_` lane.
      AdapterModeD3D10 modeEntry{};
      static_cast<void>(InitializeAdapterModeEntry(&modeEntry, 0U, output));

      for (const DXGI_FORMAT format : kAdapterProbeFormats) {
        UINT modeCount = 0U;
        if (output->GetDisplayModeList(format, 0U, &modeCount, nullptr) == DXGI_ERROR_NOT_FOUND) {
          break;
        }

        // The scratch buffer is allocated unconditionally on the count
        // result (0x008F7DFD-0x008F7E0C, including the `modeCount == 0`
        // case) and released before the next format probe; only the second
        // GetDisplayModeList's HRESULT gates the append loop (0x008F7E2A).
        auto* const scratch =
          static_cast<DXGI_MODE_DESC*>(::operator new(static_cast<std::size_t>(modeCount) * sizeof(DXGI_MODE_DESC)));
        if (output->GetDisplayModeList(format, 0U, &modeCount, scratch) >= 0) {
          for (UINT modeIndex = 0U; modeIndex < modeCount; ++modeIndex) {
            modeEntry.modes_.push_back(scratch[modeIndex]);
          }
        }
        ::operator delete[](scratch);
      }

      modes_.push_back(modeEntry);
    }

    return result;
  }

  /**
   * Address: 0x008F7BF0 (FUN_008F7BF0)
   *
   * What it does:
   * Owns the scalar-deleting destructor path for adapter wrappers and tears
   * down retained adapter-mode heap storage.
   */
  AdapterD3D10::~AdapterD3D10()
  {
    ReleaseAdapterOutputAndDeviceRefs(this);
    // Each entry's inner mode vector goes with the outer one; both are real
    // containers, so `modes_ = {}` is the whole teardown (0x008F76C0).
    modes_ = fa::vector<AdapterModeD3D10>{};
  }
}

