#pragma once
#include <type_traits>
#include <utility>
#include <cstdint>
#include <typeinfo>
#include <new>

#include "boost/shared_ptr.h"

namespace boost
{
    class bad_ptr_container_operation;
    class bad_pointer;

    namespace detail
    {
		// Old-Boost style: use std::type_info and compare via operator==
        using sp_typeinfo = std::type_info;

        // Consistent comparison helper (keeps call sites simple)
        inline bool sp_typeinfo_equal(sp_typeinfo const& a,
            sp_typeinfo const& b) noexcept
        {
            return a == b;
        }

#ifndef BOOST_SP_TYPEID
        // Mirror BOOST_SP_TYPEID from Boost: wraps typeid(T)
#define BOOST_SP_TYPEID(T) typeid(T)
#endif
	}

    // Raw layout of boost::shared_ptr<T> used by VC8-era Boost on x86:
	// two pointers: px (T*), pi (control block*). We never mutate refcounts.
    template <class T>
    struct SharedPtrRaw {
        T* px;  // pointer to T
        detail::sp_counted_base* pi;  // boost::detail::sp_counted_base*

        /**
         * Address: 0x00442BC0 (FUN_00442BC0)
         * Address: 0x00442C30 (FUN_00442C30)
         * Address: 0x00442E80 (FUN_00442E80)
         * Address: 0x00442F10 (FUN_00442F10)
         * Address: 0x00442F90 (FUN_00442F90)
         * Address: 0x00443790 (FUN_00443790)
         * Address: 0x004437E0 (FUN_004437E0)
         *
         * What it does:
         * Initializes one raw shared-ptr `(px,pi)` pair to empty/null lanes.
         */
        SharedPtrRaw() noexcept : px(nullptr), pi(nullptr) {}

        /**
         * Construct raw shared_ptr from pointer only (no control block).
         * Useful for borrowing; no ownership semantics.
         */
        explicit SharedPtrRaw(T* p) noexcept : px(p), pi(nullptr) {}

        /**
         * Construct raw shared_ptr with a custom deleter, e.g.:
         *     SharedPtrRaw<char> r(buf, &free);
         * This allocates a VC8-like control block that will call the deleter.
         */
        template <class Deleter>
        SharedPtrRaw(T* p, Deleter d)
            : px(p)
            , pi(nullptr)
        {
            if (!p) {
                // Mirror common shared_ptr semantics: empty pointer => no control block.
                // (Old Boost could allocate it anyway; we choose lean behavior.)
                return;
            }

            // Local control block that mimics Boost's sp_counted_impl_pd<T,D> shape:
            struct ControlBlock final : boost::detail::sp_counted_base {
                T* p_;
                Deleter d_;
                ControlBlock(T* p_, Deleter d_) noexcept
                    : p_(p_), d_(std::move(d_)) {
                }

                // Called when use_count_ drops to zero
                void dispose() noexcept override {
                    // Call user-supplied deleter with the stored pointer
                    d_(p_);
                }

                // Called when weak_count_ drops to zero after dispose
                void destroy() noexcept override {
                    delete this;
                }

                // Expose deleter by type; compatible with Boost's ABI expectations
                void* get_deleter(detail::sp_typeinfo const& ti) noexcept override {
                    // Compare requested type with our stored deleter type
                    return detail::sp_typeinfo_equal(ti, BOOST_SP_TYPEID(Deleter)) ? &d_ : nullptr;
                }
            };

            // sp_counted_base ctor sets use_count_=1, weak_count_=1 (old-Boost behavior).
            // That matches a just-constructed shared_ptr owning one strong ref.
            pi = new ControlBlock(p, std::move(d));
        }

        /**
         * Helper factory that deduces T from pointer and deleter.
         * Usage: auto r = SharedPtrRaw<char>::with_deleter(buf, &free);
         */
        template <class Deleter>
        static SharedPtrRaw with_deleter(T* p, Deleter d) {
            return SharedPtrRaw(p, std::move(d));
        }

        [[nodiscard]] bool has_control_block() const noexcept {
            return pi != nullptr;
        }

        void add_ref_copy() const noexcept {
            if (pi != nullptr) {
                pi->add_ref_copy();
            }
        }

        [[nodiscard]] bool add_ref_lock() const noexcept {
            return pi != nullptr && pi->add_ref_lock();
        }

        void weak_add_ref() const noexcept {
            if (pi != nullptr) {
                pi->weak_add_ref();
            }
        }

        /**
         * Address: 0x004229B0 (FUN_004229B0, boost::detail::sp_counted_base::weak_release)
         *
         * What it does:
         * Releases one weak owner from the control block and clears the borrowed
         * raw-ptr lanes.
         */
        void weak_release() noexcept {
            if (pi != nullptr) {
                pi->weak_release();
            }
            px = nullptr;
            pi = nullptr;
        }

        /**
         * Address: 0x00422B80 (FUN_00422B80, Moho::WeakPtr_CD3DDynamicTextureSheet::Release)
         * Address: 0x004260B0 (FUN_004260B0, Moho::WeakPtr_CD3DBatchTexture::Release)
         * Address: 0x00442BD0 (FUN_00442BD0)
         * Address: 0x00442C40 (FUN_00442C40)
         * Address: 0x00442C90 (FUN_00442C90, boost::shared_ptr_TextureD3D9::reset)
         * Address: 0x00442F20 (FUN_00442F20)
         * Address: 0x00442FA0 (FUN_00442FA0)
         *
         * What it does:
         * Releases one shared owner from the control block, disposes the pointee
         * on last use, and clears the borrowed raw-ptr lanes.
         */
        void release() noexcept {
            if (pi != nullptr) {
                pi->release();
            }
            px = nullptr;
            pi = nullptr;
        }

        /**
         * Address: 0x00422A70 (FUN_00422A70, boost::detail::shared_count::operator=)
         * Address: 0x00424EF0 (FUN_00424EF0)
         * Address: 0x004260F0 (FUN_004260F0, boost::shared_ptr_CD3DBatchTexture copy lane)
         *
         * What it does:
         * Rebinds this borrowed shared-ptr view to another control block while
         * preserving the old reference-count semantics.
         */
        void assign_retain(const SharedPtrRaw& source) noexcept {
            // Keep VC8-era assignment ordering: copy px first, then swap control block.
            px = source.px;
            if (source.pi != pi) {
                if (source.pi != nullptr) {
                    source.pi->add_ref_copy();
                }
                if (pi != nullptr) {
                    pi->release();
                }
                pi = source.pi;
            }
        }

        [[nodiscard]] SharedPtrRaw clone_retained() const noexcept {
            SharedPtrRaw out{};
            out.px = px;
            out.pi = pi;
            if (out.pi != nullptr) {
                out.pi->add_ref_copy();
            }
            return out;
        }
    };

    template <class T>
    struct SharedPtrLayoutView
    {
        T* px;
        detail::sp_counted_base* pi;
    };

    struct SharedCountPair
    {
        void* px;
        detail::sp_counted_base* pi;
    };

    static_assert(sizeof(SharedCountPair) == 0x08, "SharedCountPair size must be 0x08");

    struct SharedCountPairWithTail
    {
        void* px;
        detail::sp_counted_base* pi;
        std::uint32_t tail0;
        std::uint32_t tail1;
    };

    static_assert(sizeof(SharedCountPairWithTail) == 0x10, "SharedCountPairWithTail size must be 0x10");

    /**
     * Address: 0x00445550 (FUN_00445550)
     * Address: 0x00445570 (FUN_00445570)
     * Address: 0x004455E0 (FUN_004455E0)
     * Address: 0x00445600 (FUN_00445600)
     * Address: 0x00445840 (FUN_00445840)
     * Address: 0x00446200 (FUN_00446200)
     *
     * What it does:
     * Constructs one `boost::shared_ptr<T>` from a raw pointee in caller-provided storage.
     */
    template <class T>
    [[nodiscard]] inline boost::shared_ptr<T>* ConstructSharedFromRaw(
        boost::shared_ptr<T>* const outShared,
        T* const rawPointer
    )
    {
        return ::new (static_cast<void*>(outShared)) boost::shared_ptr<T>(rawPointer);
    }

    /**
     * Address: 0x00445880 (FUN_00445880)
     *
     * What it does:
     * Rebinds one initialized `boost::shared_ptr<T>` to a raw pointee by
     * constructing one new control block and releasing one previous owner.
     */
    template <class T>
    [[nodiscard]] inline boost::shared_ptr<T>* ResetSharedFromRaw(
        boost::shared_ptr<T>* const outShared,
        T* const rawPointer
    )
    {
        outShared->reset(rawPointer);
        return outShared;
    }

    /**
     * Address: 0x00446010 (FUN_00446010)
     *
     * What it does:
     * Copies one `boost::shared_ptr<T>` into caller-provided output storage.
     */
    template <class T>
    [[nodiscard]] inline boost::shared_ptr<T>* CopySharedRetain(
        boost::shared_ptr<T>* const outShared,
        const boost::shared_ptr<T>& sourceShared
    )
    {
        *outShared = sourceShared;
        return outShared;
    }

    /**
     * Address: 0x00446030 (FUN_00446030)
     * Address: 0x004460C0 (FUN_004460C0)
     * Address: 0x00446170 (FUN_00446170)
     *
     * What it does:
     * Constructs one `boost::detail::shared_count` from a raw pointee in caller-provided storage.
     */
    template <class T>
    [[nodiscard]] inline detail::shared_count* ConstructSharedCountFromRaw(
        detail::shared_count* const outCount,
        T* const rawPointer
    )
    {
        return ::new (static_cast<void*>(outCount)) detail::shared_count(rawPointer);
    }

    /**
     * Address: 0x00445510 (FUN_00445510)
     *
     * What it does:
     * Copies one `(px,pi)` pair with retained shared ownership and preserves
     * two trailing 32-bit payload lanes.
     */
    [[nodiscard]] inline SharedCountPairWithTail* AssignSharedPairRetainWithTail(
        SharedCountPairWithTail* const outPair,
        const SharedCountPairWithTail* const sourcePair
    ) noexcept
    {
        outPair->px = sourcePair->px;
        outPair->pi = sourcePair->pi;
        if (outPair->pi != nullptr) {
            outPair->pi->add_ref_copy();
        }
        outPair->tail0 = sourcePair->tail0;
        outPair->tail1 = sourcePair->tail1;
        return outPair;
    }

    /**
     * Address: 0x00442A20 (FUN_00442A20, embedded shared-pair lane)
     *
     * What it does:
     * Clears one embedded shared `(px,pi)` member pair and releases one shared
     * control-block reference when present.
     */
    template <class Owner, SharedCountPair Owner::* Member>
    inline Owner* ReleaseEmbeddedSharedPair(Owner* const owner) noexcept
    {
        SharedCountPair& pair = owner->*Member;
        pair.px = nullptr;
        detail::sp_counted_base* const control = pair.pi;
        pair.pi = nullptr;
        if (control != nullptr) {
            control->release();
        }
        return owner;
    }

    /**
     * Address: 0x00442CF0 (FUN_00442CF0)
     * Address: 0x00443010 (FUN_00443010)
     * Address: 0x004437C0 (FUN_004437C0)
     *
     * What it does:
     * Returns legacy Win32-bool encoding for null-check (`-1` when null, `0` otherwise).
     */
    [[nodiscard]] inline int LegacyNullAsNegOne(const void* const px) noexcept
    {
        return (px != nullptr) - 1;
    }

    /**
     * Address: 0x00446000 (FUN_00446000)
     *
     * What it does:
     * Returns legacy Win32-bool encoding for null-check on one pointer slot
     * (`-1` when slot points to null, `0` otherwise).
     */
    [[nodiscard]] inline int LegacyNullSlotAsNegOne(const void* const* const pxSlot) noexcept
    {
        return (*pxSlot != nullptr) - 1;
    }

    /**
     * Address: 0x00446F20 (FUN_00446F20)
     *
     * What it does:
     * Returns legacy `boost::bad_weak_ptr::what()` message literal.
     */
    [[nodiscard]] inline const char* BadWeakPtrWhatLiteral() noexcept
    {
        return "tr1::bad_weak_ptr";
    }

    /**
     * Address: 0x004437D0 (FUN_004437D0)
     *
     * What it does:
     * Returns true when the pointer lane is null.
     */
    [[nodiscard]] inline bool LegacyIsNull(const void* const px) noexcept
    {
        return px == nullptr;
    }

    /**
     * Address: 0x004438B0 (FUN_004438B0)
     * Address: 0x00443900 (FUN_00443900)
     * Address: 0x00444E60 (FUN_00444E60)
     *
     * What it does:
     * Returns pointer-lane inequality.
     */
    [[nodiscard]] inline bool LegacyPtrNotEqual(const void* const lhs, const void* const rhs) noexcept
    {
        return lhs != rhs;
    }

    /**
     * Address: 0x00444170 (FUN_00444170)
     *
     * What it does:
     * Returns pointer-lane equality.
     */
    [[nodiscard]] inline bool LegacyPtrEqual(const void* const lhs, const void* const rhs) noexcept
    {
        return lhs == rhs;
    }

    /**
     * Address: 0x00444180 (FUN_00444180)
     * Address: 0x00444220 (FUN_00444220)
     * Address: 0x00444230 (FUN_00444230)
     * Address: 0x00444D90 (FUN_00444D90)
     * Address: 0x00444DA0 (FUN_00444DA0)
     * Address: 0x004454A0 (FUN_004454A0)
     *
     * What it does:
     * Copies one raw shared-pair payload `(px,pi)` without refcount mutation.
     */
    [[nodiscard]] inline SharedCountPair* CopySharedPair(
        SharedCountPair* const outPair,
        const SharedCountPair* const sourcePair
    ) noexcept
    {
        outPair->px = sourcePair->px;
        outPair->pi = sourcePair->pi;
        return outPair;
    }

    /**
     * Address: 0x00443910 (FUN_00443910)
     *
     * What it does:
     * Releases one shared control-block reference from one `(px,pi)` pair
     * without mutating the `px` lane.
     */
    inline void ReleaseSharedControlOnly(SharedCountPair* const pair) noexcept
    {
        if (pair != nullptr && pair->pi != nullptr) {
            pair->pi->release();
        }
    }

    template <class PointeeT>
    struct SpCountedImplStorage
    {
        void* vftable;
        std::int32_t useCount;
        std::int32_t weakCount;
        PointeeT* px;
    };

    static_assert(sizeof(SpCountedImplStorage<void>) == 0x10, "SpCountedImplStorage size must be 0x10");

    /**
     * Address: 0x00446860 (FUN_00446860)
     * Address: 0x004468A0 (FUN_004468A0)
     * Address: 0x004468E0 (FUN_004468E0)
     *
     * What it does:
     * Initializes one `sp_counted_impl_p<T>` storage lane with use/weak counts
     * set to one, one concrete vftable pointer, and one owned pointee pointer.
     */
    template <class PointeeT>
    [[nodiscard]] inline SpCountedImplStorage<PointeeT>* InitSpCountedImplStorage(
        SpCountedImplStorage<PointeeT>* const outStorage,
        void* const countedImplVftable,
        PointeeT* const ownedPointee
    ) noexcept
    {
        outStorage->useCount = 1;
        outStorage->weakCount = 1;
        outStorage->vftable = countedImplVftable;
        outStorage->px = ownedPointee;
        return outStorage;
    }

    /**
     * Address: 0x00446880 (FUN_00446880)
     * Address: 0x00446900 (FUN_00446900)
     * Address: 0x00446A60 (FUN_00446A60)
     * Address: 0x00446AA0 (FUN_00446AA0)
     *
     * What it does:
     * Deletes one owned pointee when present; returns zero on null input.
     */
    template <class T>
    [[nodiscard]] inline int DeleteOwnedObjectIfPresent(T* const object) noexcept
    {
        if (object != nullptr) {
            delete object;
            return 1;
        }
        return 0;
    }

    /**
     * Address: 0x00446890 (FUN_00446890)
     * Address: 0x004468D0 (FUN_004468D0)
     * Address: 0x00446910 (FUN_00446910)
     *
     * What it does:
     * Returns the legacy null get-deleter lane.
     */
    [[nodiscard]] inline int LegacyGetDeleterNullResult(const void*) noexcept
    {
        return 0;
    }

    /**
     * Address: 0x00446C40 (FUN_00446C40)
     *
     * What it does:
     * Releases one shared `(px,pi)` prefix lane from a heap object and deletes
     * that owning heap object.
     */
    template <class SharedOwnerT>
    [[nodiscard]] inline SharedOwnerT* ReleaseSharedPrefixAndDeleteOwner(SharedOwnerT* const owner) noexcept
    {
        if (owner != nullptr) {
            SharedCountPair* const pair = reinterpret_cast<SharedCountPair*>(owner);
            if (pair->pi != nullptr) {
                pair->pi->release();
            }
            ::operator delete(static_cast<void*>(owner));
        }
        return owner;
    }

    /**
     * Address: 0x004468C0 (FUN_004468C0)
     * Address: 0x00446A70 (FUN_00446A70)
     *
     * What it does:
     * Deletes one heap owner carrying a shared `(px,pi)` prefix when present.
     */
    template <class SharedOwnerT>
    [[nodiscard]] inline int DeleteSharedOwnerIfPresent(SharedOwnerT* const owner) noexcept
    {
        if (owner != nullptr) {
            ReleaseSharedPrefixAndDeleteOwner(owner);
            return 1;
        }
        return 0;
    }

    /**
     * Address: 0x00446F30 (FUN_00446F30)
     *
     * What it does:
     * Attempts to acquire one shared-owner reference only when the current
     * use-count is non-zero.
     */
    [[nodiscard]] bool SpCountedBaseAddRefLock(detail::sp_counted_base* control) noexcept;

    /**
     * Address: 0x00446F70 (FUN_00446F70)
     *
     * What it does:
     * Atomically increments one weak-count lane and returns the previous value.
     */
    [[nodiscard]] std::int32_t SpCountedBaseWeakAddRef(detail::sp_counted_base* control) noexcept;

    /**
     * Address: 0x00446F80 (FUN_00446F80)
     *
     * What it does:
     * Returns one shared-owner use-count lane.
     */
    [[nodiscard]] std::int32_t SpCountedBaseUseCount(const detail::sp_counted_base* control) noexcept;

    /**
     * Address: 0x00446FB0 (FUN_00446FB0)
     *
     * What it does:
     * Increments one weak-count lane and returns the same control pointer.
     */
    [[nodiscard]] detail::sp_counted_base* SpCountedBaseWeakAddRefReturn(detail::sp_counted_base* control) noexcept;

    /**
     * Address: 0x00446FC0 (FUN_00446FC0)
     *
     * What it does:
     * Releases one weak-owner reference from one control-pointer slot.
     */
    [[nodiscard]] detail::sp_counted_base* SpCountedBaseWeakReleaseFromSlot(
        detail::sp_counted_base** controlSlot
    ) noexcept;

    /**
     * Address: 0x00446FE0 (FUN_00446FE0)
     *
     * What it does:
     * Rebinds one weak control-pointer slot by weak-retaining the incoming
     * source control and weak-releasing the previously bound control.
     */
    [[nodiscard]] detail::sp_counted_base** SpCountedBaseWeakAssignSlot(
        detail::sp_counted_base** targetControlSlot,
        detail::sp_counted_base* const* sourceControlSlot
    ) noexcept;

    /**
     * Address: 0x00447020 (FUN_00447020)
     *
     * What it does:
     * Returns shared-owner use-count from one control-pointer slot, or zero
     * when no control block is present.
     */
    [[nodiscard]] std::int32_t SpCountedBaseUseCountFromSlotOrZero(
        detail::sp_counted_base* const* controlSlot
    ) noexcept;

    /**
     * Address: 0x00447030 (FUN_00447030)
     *
     * What it does:
     * Constructs/rebinds one weak control-pointer slot from one shared slot and
     * throws `boost::bad_weak_ptr` when the shared owner is absent or lock fails.
     */
    [[nodiscard]] detail::sp_counted_base** SpCountedBaseWeakConstructFromSharedOrThrow(
        detail::sp_counted_base** outWeakControlSlot,
        detail::sp_counted_base* const* sourceSharedControlSlot
    );

    /**
     * Address: 0x004470A0 (FUN_004470A0)
     *
     * What it does:
     * Constructs one `boost::bad_weak_ptr` exception object in caller-provided
     * storage.
     */
    [[nodiscard]] boost::bad_weak_ptr* ConstructBadWeakPtr(boost::bad_weak_ptr* outException);

    /**
     * Address: 0x004470D0 (FUN_004470D0)
     *
     * What it does:
     * Runs one `boost::bad_weak_ptr` deleting-destructor lane controlled by
     * the low bit of `deleteFlag`.
     */
    [[nodiscard]] boost::bad_weak_ptr* DestructBadWeakPtr(
        boost::bad_weak_ptr* exceptionObject,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x00491350 (FUN_00491350)
     *
     * What it does:
     * Returns the pointer-container exception message lane used by both
     * `boost::bad_ptr_container_operation` and `boost::bad_pointer`.
     */
    [[nodiscard]] const char* GetBadPtrContainerMessage(const boost::bad_ptr_container_operation* exceptionObject) noexcept;

    /**
     * Address: 0x00491360 (FUN_00491360)
     *
     * What it does:
     * Runs one deleting-destructor thunk for `boost::bad_ptr_container_operation`,
     * forwarding through `std::exception` teardown and optional operator delete.
     */
    [[nodiscard]] boost::bad_ptr_container_operation* DestructBadPtrContainerOperation(
        boost::bad_ptr_container_operation* exceptionObject,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x004913B0 (FUN_004913B0)
     *
     * What it does:
     * Runs one deleting-destructor thunk for `boost::bad_pointer`,
     * forwarding through `std::exception` teardown and optional operator delete.
     */
    [[nodiscard]] boost::bad_pointer* DestructBadPointer(
        boost::bad_pointer* exceptionObject,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x0049C140 (FUN_0049C140)
     *
     * What it does:
     * Copy-constructs one `boost::bad_pointer` exception into caller-provided
     * storage, preserving the legacy pointer-container exception chain.
     */
    [[nodiscard]] boost::bad_pointer* ConstructBadPointerFromCopy(
        boost::bad_pointer* outException,
        const boost::bad_pointer& sourceException
    );

    /**
     * Address: 0x0049C170 (FUN_0049C170)
     *
     * What it does:
     * Copy-constructs one `boost::bad_ptr_container_operation` exception into
     * caller-provided storage.
     */
    [[nodiscard]] boost::bad_ptr_container_operation* ConstructBadPtrContainerOperationFromCopy(
        boost::bad_ptr_container_operation* outException,
        const boost::bad_ptr_container_operation& sourceException
    );

    /**
     * Address: 0x00446920 (FUN_00446920)
     * Address: 0x00446940 (FUN_00446940)
     * Address: 0x00446960 (FUN_00446960)
     *
     * What it does:
     * Models legacy deleting-destructor thunk behavior for trivial
     * `sp_counted_impl_p<T>` destructors.
     */
    template <class ImplT>
    [[nodiscard]] inline ImplT* SpCountedImplDeletingDtor(
        ImplT* const self,
        const unsigned char deleteFlag
    ) noexcept
    {
        if ((deleteFlag & 1u) != 0u) {
            ::operator delete(static_cast<void*>(self));
        }
        return self;
    }

    /**
     * Address: 0x00446980 (FUN_00446980)
     * Address: 0x00446990 (FUN_00446990)
     * Address: 0x004469A0 (FUN_004469A0)
     *
     * What it does:
     * Models legacy non-deleting destructor body epilogue lane for trivial
     * `sp_counted_impl_p<T>` destructors.
     */
    template <class ImplT>
    [[nodiscard]] inline ImplT* SpCountedImplNonDeletingDtor(ImplT* const self) noexcept
    {
        return self;
    }

    /**
     * Address: 0x0043D940 (FUN_0043D940)
     * Address: 0x0043EED0 (FUN_0043EED0)
     * Address: 0x0043F2E0 (FUN_0043F2E0)
     * Address: 0x004438C0 (FUN_004438C0)
     *
     * What it does:
     * Copies one `(px,pi)` pair and rebinds control ownership by retaining the
     * incoming `pi` then weak-releasing the previous `pi`.
     */
    SharedCountPair* AssignWeakPairFromShared(SharedCountPair* outPair, const SharedCountPair* sourcePair) noexcept;

    /**
     * Address: 0x004414F0 (FUN_004414F0)
     * Address: 0x0043F7E0 (FUN_0043F7E0)
     * Address: 0x0043FCF0 (FUN_0043FCF0)
     *
     * What it does:
     * Same weak-owner `(px,pi)` rebind helper as `AssignWeakPairFromShared`,
     * but with caller argument order `(source, destination)`.
     */
    SharedCountPair* AssignWeakPairFromSharedReversed(const SharedCountPair* sourcePair, SharedCountPair* outPair) noexcept;

    /**
     * Address: 0x0043DCF0 (FUN_0043DCF0)
     * Address: 0x0043F500 (FUN_0043F500)
     * Address: 0x0043F8E0 (FUN_0043F8E0)
     * Address: 0x0043FD90 (FUN_0043FD90)
     * Address: 0x00446A80 (FUN_00446A80)
     * Address: 0x004456E0 (FUN_004456E0)
     * Address: 0x00445860 (FUN_00445860)
     * Address: 0x004459A0 (FUN_004459A0)
     * Address: 0x004459C0 (FUN_004459C0)
     * Address: 0x004459E0 (FUN_004459E0)
     * Address: 0x00446150 (FUN_00446150)
     * Address: 0x004462F0 (FUN_004462F0)
     *
     * What it does:
     * Copies one `(px,pi)` pair and retains one shared control-block reference.
     */
    SharedCountPair* AssignSharedPairRetain(SharedCountPair* outPair, const SharedCountPair* sourcePair) noexcept;

    /**
     * Address: 0x0043E3B0 (FUN_0043E3B0)
     *
     * What it does:
     * Alias lane for `AssignSharedPairRetain` with identical behavior.
     */
    SharedCountPair* AssignSharedPairRetainAlias(SharedCountPair* outPair, const SharedCountPair* sourcePair) noexcept;

    template <class T>
    [[nodiscard]] SharedPtrRaw<T> SharedPtrRawFromSharedBorrow(const boost::shared_ptr<T>& source) noexcept
    {
        static_assert(
            sizeof(boost::shared_ptr<T>) == sizeof(SharedPtrLayoutView<T>),
            "boost::shared_ptr<T> layout must match (px,pi) pair on this target"
        );

        const auto* const layout = reinterpret_cast<const SharedPtrLayoutView<T>*>(&source);
        SharedPtrRaw<T> out{};
        out.px = layout->px;
        out.pi = layout->pi;
        return out;
    }

    template <class T>
    [[nodiscard]] SharedPtrRaw<T> SharedPtrRawFromSharedRetained(const boost::shared_ptr<T>& source) noexcept
    {
        SharedPtrRaw<T> out = SharedPtrRawFromSharedBorrow(source);
        if (out.pi != nullptr) {
            out.pi->add_ref_copy();
        }
        return out;
    }

    template <class T>
    [[nodiscard]] boost::shared_ptr<T> SharedPtrFromRawRetained(const SharedPtrRaw<T>& source) noexcept
    {
        static_assert(
            sizeof(boost::shared_ptr<T>) == sizeof(SharedPtrLayoutView<T>),
            "boost::shared_ptr<T> layout must match (px,pi) pair on this target"
        );

        boost::shared_ptr<T> out{};
        auto* const layout = reinterpret_cast<SharedPtrLayoutView<T>*>(&out);
        layout->px = source.px;
        layout->pi = source.pi;
        if (layout->pi != nullptr) {
            layout->pi->add_ref_copy();
        }
        return out;
    }

    // Detection: is T iterable (has member begin()/end())?
    template <class U, class = void>
    struct is_iterable : std::false_type {};
    template <class U>
    struct is_iterable<U, std::void_t<
        decltype(std::declval<U&>().begin()),
        decltype(std::declval<U&>().end())
        >> : std::true_type {};

    // BorrowedSharedPtr<T> is a non-owning, read-only view over a raw Boost shared_ptr layout.
    // It does NOT change reference counts. Safe to pass by value (just copies the two pointers).
    template <class T>
    class BorrowedSharedPtr {
    public:
        using element_type = T;

        // ctors
        BorrowedSharedPtr() noexcept : px_(nullptr), pi_(nullptr) {}
        BorrowedSharedPtr(T* px, void* pi) noexcept : px_(px), pi_(pi) {}
        explicit BorrowedSharedPtr(const SharedPtrRaw<T>& raw) noexcept : px_(raw.px), pi_(raw.pi) {}

        // pointer interface
        T* get()       noexcept { return px_; }
        const T* get() const noexcept { return px_; }
        T& operator*() { return *px_; }
        const T& operator*()  const { return *px_; }
        T* operator->() { return px_; }
        const T* operator->() const { return px_; }
        explicit operator bool() const noexcept { return px_ != nullptr; }

        // raw accessors (debug/interop)
        /**
         * Address: 0x00442C20 (FUN_00442C20)
         * Address: 0x00442CE0 (FUN_00442CE0)
         * Address: 0x00442E90 (FUN_00442E90)
         * Address: 0x00442FF0 (FUN_00442FF0)
         * Address: 0x00443000 (FUN_00443000)
         * Address: 0x00442F70 (FUN_00442F70)
         * Address: 0x00442F80 (FUN_00442F80)
         * Address: 0x004437A0 (FUN_004437A0)
         * Address: 0x004437B0 (FUN_004437B0)
         * Address: 0x004437F0 (FUN_004437F0)
         * Address: 0x004438E0 (FUN_004438E0)
         * Address: 0x004438F0 (FUN_004438F0)
         * Address: 0x00443CD0 (FUN_00443CD0)
         * Address: 0x00444120 (FUN_00444120)
         * Address: 0x00444160 (FUN_00444160)
         *
         * What it does:
         * Returns the raw pointee lane (`px`) from one borrowed shared-ptr pair.
         */
        T* px_raw() const noexcept { return px_; }
        void* pi_raw() const noexcept { return pi_; }

        // reset view (does not touch refcounts)
        void reset() noexcept { px_ = nullptr; pi_ = nullptr; }

        // Iteration passthrough if T is iterable: enables range-for over the wrapper.
        template <class Q = T, std::enable_if_t<is_iterable<Q>::value, int> = 0>
        auto begin() { return px_->begin(); }
        template <class Q = T, std::enable_if_t<is_iterable<Q>::value, int> = 0>
        auto end() { return px_->end(); }
        template <class Q = T, std::enable_if_t<is_iterable<Q>::value, int> = 0>
        auto begin()  const { return px_->begin(); }
        template <class Q = T, std::enable_if_t<is_iterable<Q>::value, int> = 0>
        auto end()    const { return px_->end(); }

    private:
        T* px_;
        void* pi_;
    };
}
