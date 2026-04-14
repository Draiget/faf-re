#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg::gal
{
    struct HeadAdapterMode
    {
        std::uint32_t width = 0;       // +0x00
        std::uint32_t height = 0;      // +0x04
        std::uint32_t refreshRate = 0; // +0x08
    };

    static_assert(sizeof(HeadAdapterMode) == 0x0C, "HeadAdapterMode size must be 0x0C");

    struct HeadSampleOption
    {
        HeadSampleOption() = default;

        /**
         * Address: 0x004369B0 (FUN_004369B0)
         *
         * What it does:
         * Copies one sample-option lane, including scalar sample settings and
         * owned label text.
         */
        HeadSampleOption(const HeadSampleOption& other);

        std::uint32_t sampleType = 0;  // +0x00
        std::uint32_t sampleQuality = 0; // +0x04
        msvc8::string label{};         // +0x08
    };

    static_assert(sizeof(HeadSampleOption) == 0x24, "HeadSampleOption size must be 0x24");

    /**
     * VFTABLE: 0x00D42128
     * COL:     0x00E5EB34
     */
    class Head
    {
    public:
        /**
         * Address: 0x008E6D80 (FUN_008E6D80, gpg::gal::Head::Head)
         *
         * What it does:
         * Initializes one GAL head descriptor and zeroes scalar/runtime
         * vector lanes.
         */
        Head();

        /**
         * Address: 0x004368B0 (FUN_004368B0)
         *
         * What it does:
         * Copies one head descriptor lane, including nested sample/mode/format
         * vector payloads and owned display text.
         */
        Head(const Head& other);

        /**
         * Address: 0x008E6EA0 (FUN_008E6EA0, gpg::gal::Head::~Head)
         * Address: 0x00436990 (FUN_00436990)
         *
         * What it does:
         * Tears down `Head` vector/string payload lanes; `0x00436990` is the
         * scalar-deleting thunk that dispatches here and conditionally frees
         * `this`.
         */
        virtual ~Head();

    public:
        void* mHandle = nullptr;                             // +0x04
        void* mWindow = nullptr;                             // +0x08
        bool mWindowed = false;                              // +0x0C
        std::uint8_t padding0x0D_[3]{};                      // +0x0D
        std::uint32_t mWidth = 0;                            // +0x10
        std::uint32_t mHeight = 0;                           // +0x14
        std::uint32_t framesPerSecond = 0;                   // +0x18
        std::uint32_t antialiasingHigh = 0;                  // +0x1C
        std::uint32_t antialiasingLow = 0;                   // +0x20
        msvc8::string name{};                                // +0x24
        msvc8::vector<HeadSampleOption> mStrs{};             // +0x40
        msvc8::vector<HeadAdapterMode> adapterModes{};       // +0x50
        msvc8::vector<std::int32_t> validFormats2{};         // +0x60
        msvc8::vector<std::int32_t> validFormats1{};         // +0x70
    };

    static_assert(offsetof(Head, mHandle) == 0x04, "Head::mHandle offset must be 0x04");
    static_assert(offsetof(Head, mWindow) == 0x08, "Head::mWindow offset must be 0x08");
    static_assert(offsetof(Head, mWindowed) == 0x0C, "Head::mWindowed offset must be 0x0C");
    static_assert(offsetof(Head, mWidth) == 0x10, "Head::mWidth offset must be 0x10");
    static_assert(offsetof(Head, mHeight) == 0x14, "Head::mHeight offset must be 0x14");
    static_assert(offsetof(Head, framesPerSecond) == 0x18, "Head::framesPerSecond offset must be 0x18");
    static_assert(offsetof(Head, antialiasingHigh) == 0x1C, "Head::antialiasingHigh offset must be 0x1C");
    static_assert(offsetof(Head, antialiasingLow) == 0x20, "Head::antialiasingLow offset must be 0x20");
    static_assert(offsetof(Head, name) == 0x24, "Head::name offset must be 0x24");
    static_assert(offsetof(Head, mStrs) == 0x40, "Head::mStrs offset must be 0x40");
    static_assert(offsetof(Head, adapterModes) == 0x50, "Head::adapterModes offset must be 0x50");
    static_assert(offsetof(Head, validFormats2) == 0x60, "Head::validFormats2 offset must be 0x60");
    static_assert(offsetof(Head, validFormats1) == 0x70, "Head::validFormats1 offset must be 0x70");
    static_assert(sizeof(Head) == 0x80, "Head size must be 0x80");
}
