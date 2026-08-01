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
         *
         * The release binary additionally exposes four linker-emitted
         * calling-convention trampolines that forward unmodified to this body
         * (`FUN_008D6E00`, `FUN_008E7110`, `FUN_008E7170`, `FUN_008E71A0`)
         * for cross-TU references with `__cdecl` and `__stdcall` callsites.
         * No separate source code is emitted for those trampolines; the
         * compiler/linker re-synthesizes them automatically when this single
         * recovered body is referenced from differently-conventioned callers.
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
         * Address: 0x008E71D0 (FUN_008E71D0, msvc8::vector<gpg::gal::Head>::_Insert_n)
         * Address: 0x008E6F90 (FUN_008E6F90, the std::_Uninitialized_fill_n<Head>
         *          fast-path primitive the same insert() outlines when spare
         *          capacity is available — folded here per the canonical-body rule)
         *
         * IDA signature:
         * void __thiscall sub_8E71D0(_DWORD *this, int pos, unsigned int count, int value);
         *
         * What it does:
         * Per-`Head` `msvc8::vector<Head>::insert(pos, count, value)` — the single
         * source-level call `DeviceContext::AddHead` makes. MSVC8 outlines it into
         * the fast-path uninitialized fill (`FUN_008E6F90`, when spare capacity
         * exists) plus the `_Insert_n` grow body (`FUN_008E71D0`): when there is
         * room it shifts the live tail right by `count` and copy-assigns the gap
         * in place; otherwise it reallocates (MSVC8 1.5x growth `oldCap + oldCap/2`,
         * floored to `size + count`, capped at 0x1FFFFFF elements,
         * `std::length_error` on overflow), copy-constructs the head prefix into
         * the new buffer via the recovered
         * `CopyConstructHeadRangeIntoUninitializedStorageOrRethrow` (`FUN_008D7C20`,
         * reached through the `FUN_008E71A0` trampoline), fill-constructs the
         * inserted `Head`, moves the tail, frees the old buffer via
         * `operator delete` and rebinds the pointer triplet. `Head` is a
         * non-trivial 0x80-byte element, so every element copy routes through the
         * recovered `Head` copy-ctor (`FUN_004368B0`) — never a raw byte copy. The
         * canonical `_Insert_n` body lives in `msvc8::vector<T>::insert`
         * (legacy/containers/Vector.h); this per-`Head` wrapper is the by-name
         * invocation that keeps the emitted symbols in the binary.
         */
        void InsertNCopiesHeadVector(
            msvc8::vector<Head>& heads,
            Head* const insertPosition,
            const std::size_t insertCount,
            const Head& fillValue
        )
        {
            heads.insert(insertPosition, insertCount, fillValue);
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
     * IDA signature:
     * void __thiscall gpg::gal::DeviceContext::AddHead(DeviceContext *this, Head *head);
     *
     * What it does:
     * Appends one head descriptor to the retained head vector — a single
     * `mHeads.insert(end, 1, head)`. The release binary outlines this one
     * `insert(end(),1,value)` into a conditional fast-path uninitialized fill
     * (`FUN_008E6F90`, taken when `size < capacity`) plus the `_Insert_n` grow
     * body (`FUN_008E71D0`); together they add exactly one element (the fill
     * constructs the trailing slot, the body advances the end pointer — it does
     * NOT re-construct). Expressed as the single `InsertNCopiesHeadVector`
     * (== `msvc8::vector<Head>::insert`) call so the element is constructed
     * exactly once (a two-step fill-then-insert would double-construct and leak
     * the non-trivial 0x80-byte `Head`). `Head` copies route through the
     * recovered `Head` copy-ctor (`FUN_004368B0`), never a raw byte copy.
     */
    void DeviceContext::AddHead(const Head& head)
    {
        InsertNCopiesHeadVector(mHeads, mHeads.end(), 1U, head);
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

    /**
     * Slot 9 on the base is _purecall in the binary - only a backend ever
     * answers it. The declaration exists here so DeviceD3D9 and DeviceD3D10
     * override rather than append; reaching this body would mean the active
     * device is the base class, which never happens.
     */
    boost::shared_ptr<Effect>* Device::CreateEffect(
        boost::shared_ptr<Effect>* const outEffect,
        EffectContext* const /*context*/
    )
    {
        return outEffect;
    }
}
