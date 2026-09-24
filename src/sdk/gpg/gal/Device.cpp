#include "Device.hpp"
#include "DeviceContext.hpp"
#include "Error.hpp"
#include "gpg/gal/backends/d3d10/DeviceD3D10.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "legacy/containers/AutoPtr.h"

#include <Windows.h>
#include <new>

namespace gpg::gal
{
    namespace
    {
        /**
         * The active device (0x00F8E284). An `auto_ptr`: `Create` and
         * `DestroyInstance` replace it with its delete-then-assign `reset`,
         * and its exit-time destructor (0x00C095F0) deletes whatever device is
         * still live.
         */
        msvc8::auto_ptr<Device> sDeviceD3D;

        [[noreturn]] void ThrowDeviceContextError(const int line, const char* const message)
        {
            throw Error(
                msvc8::string("c:\\work\\rts\\main\\code\\src\\libs\\gpggal\\Device.cpp"),
                line,
                msvc8::string(message)
            );
        }

        /**
         * Address: 0x00432310 (FUN_00432310)
         *
         * What it does:
         * Returns the number of `Head` elements currently stored in one vector lane.
         */
        [[nodiscard]] int CountHeadVectorEntries(const msvc8::vector<Head>& heads) noexcept
        {
            const Head* const start = heads.begin();
            if (start == nullptr)
            {
                return 0;
            }

            return static_cast<int>(heads.end() - start);
        }

    }

    /**
     * Address: 0x004369B0 (FUN_004369B0)
     *
     * What it does:
     * Copy-constructs one head-sample option lane including its owned label
     * string payload.
     */
    HeadSampleOption::HeadSampleOption(const HeadSampleOption& other)
        : sampleType(other.sampleType),
          sampleQuality(other.sampleQuality),
          label(other.label)
    {
    }

    /**
     * Address: 0x008E6D40 (FUN_008E6D40)
     *
     * What it does:
     * Initializes one device-context record and records requested backend type.
     */
    DeviceContext::DeviceContext(const std::int32_t deviceType)
        : mDeviceType(deviceType)
    {
    }

    /**
     * Address: 0x00430480 (FUN_00430480)
     *
     * DeviceContext const &
     *
     * What it does:
     * Copies one device-context payload, including all configured heads.
     */
    DeviceContext::DeviceContext(const DeviceContext& other)
        : mDeviceType(other.mDeviceType),
          mValidate(other.mValidate),
          mAdapter(other.mAdapter),
          mVSync(other.mVSync),
          mHWBasedInstancing(other.mHWBasedInstancing),
          mSupportsFloat16(other.mSupportsFloat16),
          mVertexShaderProfile(other.mVertexShaderProfile),
          mPixelShaderProfile(other.mPixelShaderProfile),
          mMaxPrimitiveCount(other.mMaxPrimitiveCount),
          mMaxVertexCount(other.mMaxVertexCount),
          mHeads(other.mHeads)
    {
    }

    /**
     * Address: 0x008D1D00 (FUN_008D1D00, func_CpyDeviceContext)
     *
     * What it does:
     * Copies one device-context payload and returns the destination context.
     */
    DeviceContext& DeviceContext::operator=(const DeviceContext& other)
    {
        mDeviceType = other.mDeviceType;
        mValidate = other.mValidate;
        mAdapter = other.mAdapter;
        mVSync = other.mVSync;
        mHWBasedInstancing = other.mHWBasedInstancing;
        mSupportsFloat16 = other.mSupportsFloat16;
        mVertexShaderProfile = other.mVertexShaderProfile;
        mPixelShaderProfile = other.mPixelShaderProfile;
        mMaxPrimitiveCount = other.mMaxPrimitiveCount;
        mMaxVertexCount = other.mMaxVertexCount;
        mHeads = other.mHeads;
        return *this;
    }

    /**
     * Address: 0x008E6730 (FUN_008E6730)
     *
     * What it does:
     * Returns the active device singleton pointer.
     */
    Device* Device::GetInstance()
    {
        return sDeviceD3D.get();
    }

    /**
     * Address: 0x008E6720 (FUN_008E6720, gpg::gal::Device::IsReady)
     *
     * What it does:
     * Returns true when the global active device singleton is available.
     */
    bool Device::IsReady()
    {
        return sDeviceD3D.get() != nullptr;
    }

    /**
     * Address: 0x008E6700 (FUN_008E6700, func_DeivceD3DDtr)
     *
     * What it does:
     * Deletes the active device (through its virtual destructor, slot 0) and
     * clears the singleton.
     */
    void Device::DestroyInstance()
    {
        sDeviceD3D.reset();
    }

    /**
     * Address: 0x008E6B60 (FUN_008E6B60, func_CreateDeviceD3D)
     *
     * What it does:
     * Deletes the active device, then builds the backend `context` asks for
     * (`new DeviceD3D9`, 0x84 bytes, or `new DeviceD3D10`, 0x128), installs
     * it as the active device before bringing it up, and returns it. Any other
     * device type throws "unknown API requested" (Device.cpp line 135).
     * `CScApp::CreateDevice` is the caller (0x008CFC09).
     */
    Device* Device::Create(DeviceContext* const context)
    {
        DestroyInstance();

        switch (context->mDeviceType)
        {
        case 1:
        {
            DeviceD3D9* const device = new DeviceD3D9();
            sDeviceD3D.reset(device);
            device->Setup(context);
            break;
        }
        case 2:
        {
            DeviceD3D10* const device = new DeviceD3D10();
            sDeviceD3D.reset(device);
            device->Setup(context);
            break;
        }
        default:
            ThrowDeviceContextError(135, "unknown API requested");
        }

        return sDeviceD3D.get();
    }

    /**
     * Address: 0x008E81B0 (FUN_008E81B0)
     *
     * What it does:
     * Installs the base vtable and builds the empty output context.
     */
    Device::Device() = default;

    /**
     * Address: 0x008E81A0 (FUN_008E81A0)
     *
     * What it does:
     * Reinstalls the base vtable and destroys the output context (a tail
     * jump to `~OutputContext`, 0x008E76D0).
     */
    Device::~Device() = default;

    /**
     * Address: 0x0079CB10 (FUN_0079CB10, gpg::gal::WindowIsForeground)
     *
     * What it does:
     * Returns true when the foreground HWND matches any configured head window
     * handle in the active device context.
     */
    bool WindowIsForeground()
    {
        const HWND foregroundWindow = ::GetForegroundWindow();
        Device* const instance = Device::GetInstance();
        if (instance == nullptr)
        {
            return false;
        }

        DeviceContext* const context = instance->GetDeviceContext();
        const int headCount = context->GetHeadCount();
        if (headCount <= 0)
        {
            return false;
        }

        for (int headIndex = 0; headIndex < headCount; ++headIndex)
        {
            const Head& head = context->GetHead(static_cast<std::uint32_t>(headIndex));
            if (foregroundWindow == head.mWindow || foregroundWindow == head.mHandle)
            {
                return true;
            }
        }

        return false;
    }

    /**
     * Address: 0x008E66E0 (FUN_008E66E0)
     *
     * What it does:
     * Returns the number of configured head descriptors in `mHeads`.
     */
    int DeviceContext::GetHeadCount() const
    {
        return CountHeadVectorEntries(mHeads);
    }

    /**
     * Address: 0x008E69C0 (FUN_008E69C0)
     *
     * What it does:
     * Validates one head index and returns the matching head descriptor.
     */
    const Head& DeviceContext::GetHead(const std::uint32_t index) const
    {
        const Head* const start = mHeads.begin();
        const Head* const finish = mHeads.end();
        const std::uint32_t count = (start == nullptr) ? 0U : static_cast<std::uint32_t>(finish - start);
        if ((start == nullptr) || (index >= count))
        {
            ThrowDeviceContextError(91, "invalid head index");
        }

        return start[index];
    }

    /**
     * Address: 0x008E6A90 (FUN_008E6A90)
     *
     * What it does:
     * Validates one mutable head index and returns the matching head descriptor.
     */
    Head& DeviceContext::GetHead(const std::uint32_t index)
    {
        Head* const start = mHeads.begin();
        const Head* const finish = mHeads.end();
        const std::uint32_t count = (start == nullptr) ? 0U : static_cast<std::uint32_t>(finish - start);
        if ((start == nullptr) || (index >= count))
        {
            ThrowDeviceContextError(97, "invalid head index");
        }

        return start[index];
    }

    /**
     * Address: 0x008E7530 (FUN_008E7530)
     *
     * IDA signature:
     * void __thiscall gpg::gal::DeviceContext::AddHead(DeviceContext *this, Head *head);
     *
     * What it does:
     * Appends one head descriptor to the retained head vector — a single
     * `mHeads.insert(end, 1, head)`. The release binary outlines this one
     * `insert(end(), 1, value)` into a conditional fast-path uninitialized fill
     * (`FUN_008E6F90`, taken when `size < capacity`) plus the `_Insert_n` grow
     * body (`FUN_008E71D0`); together they add exactly one element. Both cite
     * `msvc8::vector<T>::insert` in Vector.h, along with the copy-construct
     * range (`FUN_008D7C20`) and its four calling-convention trampolines.
     * `Head` copies route through the recovered `Head` copy-ctor
     * (`FUN_004368B0`), never a raw byte copy.
     */
    void DeviceContext::AddHead(const Head& head)
    {
        mHeads.insert(mHeads.end(), 1U, head);
    }

    /**
     * Address: 0x008E6940 (FUN_008E6940)
     *
     * OutputContext const *
     *
     * What it does:
     * Copies caller output-target context state into the device's active output context.
     */
    void Device::ClearTarget(const OutputContext* const context)
    {
        outputContext_ = *context;
    }

    /**
     * Address: 0x008E6810 (FUN_008E6810)
     *
     * OutputContext *
     *
     * What it does:
     * Copies the device's active output-target context into the caller-provided context object.
     */
    void Device::GetContext(OutputContext* const outContext)
    {
        *outContext = outputContext_;
    }
}
