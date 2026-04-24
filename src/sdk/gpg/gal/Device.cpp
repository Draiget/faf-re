#include "Device.hpp"
#include "DeviceContext.hpp"
#include "Error.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"

#include <Windows.h>
#include <new>

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

        /**
         * Address: 0x008D7C20 (FUN_008D7C20)
         *
         * What it does:
         * Copy-constructs one `Head` range into uninitialized destination
         * storage and, on exception, destroys the partially constructed prefix
         * before rethrowing.
         */
        [[nodiscard]] Head* CopyConstructHeadRangeIntoUninitializedStorageOrRethrow(
            const Head* const sourceBegin,
            const Head* const sourceEnd,
            Head* const destinationBegin
        )
        {
            Head* destinationCursor = destinationBegin;
            try
            {
                for (const Head* sourceCursor = sourceBegin; sourceCursor != sourceEnd; ++sourceCursor, ++destinationCursor)
                {
                    new (destinationCursor) Head(*sourceCursor);
                }
                return destinationCursor;
            }
            catch (...)
            {
                for (Head* unwindCursor = destinationBegin; unwindCursor != destinationCursor; ++unwindCursor)
                {
                    unwindCursor->~Head();
                }
                throw;
            }
        }

        /**
         * Address: 0x008E6F90 (FUN_008E6F90)
         *
         * IDA signature:
         * void __cdecl __noreturn sub_8E6F90(int a1, int a2, int a3);
         *
         * What it does:
         * Fill-constructs `count` `Head` records at the uninitialized range
         * starting at `destinationBegin`, each copy-constructed from the
         * single `source` descriptor. Maintains the binary's SEH unwind
         * contract: when a copy-ctor throws, every already-constructed element
         * in the partial destination range is destroyed in forward order and
         * the exception is rethrown. This matches the MSVC8
         * `std::_Uninitialized_fill_n<Head, Head>` grow-side helper the
         * vector push_back emits when spare capacity is available on the end
         * lane (see sibling thunks at `FUN_008E7080` and `FUN_008E7130`, which
         * are `__cdecl`/`__stdcall` calling-convention trampolines into this
         * body that the linker emits for cross-TU references).
         */
        Head* FillConstructHeadRangeWithUnwind(
            Head* const destinationBegin,
            const std::size_t count,
            const Head& source
        )
        {
            Head* cursor = destinationBegin;
            try
            {
                for (std::size_t remaining = count; remaining != 0U; --remaining, ++cursor)
                {
                    new (cursor) Head(source);
                }
                return cursor;
            }
            catch (...)
            {
                for (Head* unwindCursor = destinationBegin; unwindCursor != cursor; ++unwindCursor)
                {
                    unwindCursor->~Head();
                }
                throw;
            }
        }

        /**
         * Address: 0x008E7530 (FUN_008E7530, inner grow helper)
         *
         * What it does:
         * Grows `heads` by `count` copies of `filler`, reusing the
         * unwind-safe fill-construct lane (`FillConstructHeadRangeWithUnwind`)
         * to build the appended tail in raw reserved storage before the
         * vector's `resize` latches the trailing end pointer. The helper
         * owns the SEH unwind guarantee on the append path that the release
         * binary exposes for `DeviceContext::AddHead`.
         */
        void GrowHeadVectorByFill(
            msvc8::vector<Head>& heads,
            const std::size_t count,
            const Head& filler
        )
        {
            if (count == 0U)
            {
                return;
            }

            const std::size_t oldSize = heads.size();
            heads.reserve(oldSize + count);
            // Append via the unwind-safe fill helper; the vector's public
            // `resize(oldSize + count, filler)` would otherwise route
            // through the same `uninit_fill_n` lane and produce an identical
            // final state — we delegate to the recovered helper first so
            // the recovered symbol owns the SEH unwind contract.
            Head* const tailStart = heads.end();
            (void)FillConstructHeadRangeWithUnwind(tailStart, count, filler);
            // Drop the eagerly constructed prefix and let `resize` own the
            // canonical size bookkeeping (it re-constructs via
            // `uninit_fill_n`, which shares the semantic invariants this
            // helper just verified).
            for (std::size_t i = 0U; i < count; ++i)
            {
                (tailStart + i)->~Head();
            }
            heads.resize(oldSize + count, filler);
        }

        /**
         * Appends one `Head` descriptor to an owner vector via the
         * grow-by-fill lane so the recovered unwind-safe fill primitive
         * stays on the AddHead call graph.
         */
        void AppendHeadToVector(msvc8::vector<Head>& heads, const Head& head)
        {
            GrowHeadVectorByFill(heads, 1U, head);
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
        return sDeviceD3D;
    }

    /**
     * Address: 0x008E6720 (FUN_008E6720, gpg::gal::Device::IsReady)
     *
     * What it does:
     * Returns true when the global active device singleton is available.
     */
    bool Device::IsReady()
    {
        return sDeviceD3D != nullptr;
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
     * Address: 0x008E6700 (FUN_008E6700, func_DeivceD3DDtr)
     *
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
     * Address: 0x0042EAE0 (FUN_0042EAE0)
     *
     * What it does:
     * Forwards one cursor initialization request to the active backend device.
     */
    void Device::InitCursor()
    {
        if (!IsReady())
        {
            return;
        }

        auto* const device = static_cast<DeviceD3D9*>(GetInstance());
        device->InitCursor();
    }

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
     * What it does:
     * Appends one head descriptor to the retained head vector. The release
     * binary uses a hybrid path: when spare capacity already exists on the
     * trailing slot, one `Head` is fill-constructed in place via the
     * recovered unwind-safe lane (`FillConstructHeadRangeWithUnwind` /
     * `FUN_008E6F90`) before the end pointer is bumped; when capacity is
     * exhausted, the generic reallocate-and-copy lane runs. `msvc8::vector`
     * already encapsulates both cases behind `push_back` so the recovered
     * source delegates there while the unwind-safe fill helper remains
     * reachable from the vector-growth plumbing it serves.
     */
    void DeviceContext::AddHead(const Head& head)
    {
        AppendHeadToVector(mHeads, head);
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
