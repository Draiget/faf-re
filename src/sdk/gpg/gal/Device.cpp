#include "Device.hpp"
#include "DeviceContext.hpp"
#include "Error.hpp"

namespace gpg::gal
{
    namespace
    {
        Device* sDeviceD3D = nullptr;

        [[noreturn]] void ThrowDeviceContextError(const int line, const char* const message)
        {
            throw Error(
                msvc8::string("c:\\work\\rts\\main\\code\\src\\libs\\gpggal\\Device.cpp"),
                line,
                msvc8::string(message)
            );
        }
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
     * Address: 0x008E6730 (FUN_008E6730)
     *
     * What it does:
     * Returns the active device singleton pointer.
     */
    Device* Device::GetInstance()
    {
        return sDeviceD3D;
    }

    /**
     * What it does:
     * Replaces the process-global backend device singleton pointer.
     */
    void Device::SetInstance(Device* const device)
    {
        sDeviceD3D = device;
    }

    /**
     * What it does:
     * Runs slot-0 destroy behavior for the active backend device and clears
     * the retained singleton pointer.
     */
    void Device::DestroyInstance()
    {
        if (sDeviceD3D == nullptr)
        {
            return;
        }

        Device* const device = sDeviceD3D;
        sDeviceD3D = nullptr;
        device->purecall0();
    }

    /**
     * Address: 0x008E66E0 (FUN_008E66E0)
     *
     * What it does:
     * Returns the number of configured head descriptors in `mHeads`.
     */
    int DeviceContext::GetHeadCount() const
    {
        const Head* const start = mHeads.begin();
        if (start == nullptr)
        {
            return 0;
        }

        return static_cast<int>(mHeads.end() - start);
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
     * Address family:
     * - 0x008E69C0 (const)
     * - mutable callsites in startup path (`FUN_008D0370`)
     *
     * What it does:
     * Returns one validated mutable head descriptor by index.
     */
    Head& DeviceContext::GetHead(const std::uint32_t index)
    {
        return const_cast<Head&>(static_cast<const DeviceContext*>(this)->GetHead(index));
    }

    /**
     * Address: 0x008E7530 (FUN_008E7530)
     *
     * What it does:
     * Appends one head descriptor to the retained head vector.
     */
    void DeviceContext::AddHead(const Head& head)
    {
        mHeads.push_back(head);
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
        outputContext_.cubeTarget = context->cubeTarget;
        outputContext_.face = context->face;
        outputContext_.surface = context->surface;
        outputContext_.texture = context->texture;
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
        outContext->cubeTarget = outputContext_.cubeTarget;
        outContext->face = outputContext_.face;
        outContext->surface = outputContext_.surface;
        outContext->texture = outputContext_.texture;
    }
}
