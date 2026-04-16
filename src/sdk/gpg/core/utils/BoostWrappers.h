#pragma once
#include <type_traits>
#include <utility>
#include <cstdint>
#include <typeinfo>
#include <new>

#include "boost/shared_ptr.h"

namespace moho
{
    class RScmResource;
    class RScaResource;
    class CHeightField;
    class CMauiFrame;
    class CIntelGrid;
    class CAniPose;
    class CDebugCanvas;
    class CGpgNetInterface;
    class ISimResources;
    class PathPreviewFinder;
    class MeshMaterial;
    class Mesh;
    struct RMeshBlueprintLOD;
    class MeshBatch;
    class IRenTerrain;
    class CD3DTextureBatcher;
    class CD3DPrimBatcher;
    class ID3DVertexSheet;
    class ShoreCell;
    class MeshInstance;
    class CAniDefaultSkel;
    class LaunchInfoNew;
    class LaunchInfoLoad;
    struct SSessionSaveData;
    class UICommandGraph;
    struct SFileStarCloser;
    struct SParticleBuffer;
    class StatItem;
    template <class T>
    class Stats;
    using Stats_StatItem = Stats<StatItem>;
    struct STrigger;
}

namespace gpg::gal
{
    class TextureD3D9;
    class RenderTargetD3D9;
    class CubeRenderTargetD3D9;
    class DepthStencilTargetD3D9;
    class VertexFormatD3D9;
    class VertexBufferD3D9;
    class IndexBufferD3D9;
    class EffectD3D9;
    class PipelineStateD3D9;
    class EffectD3D10;
    class TextureD3D10;
    class RenderTargetD3D10;
    class CubeRenderTargetD3D10;
    class DepthStencilTargetD3D10;
    class VertexFormatD3D10;
    class VertexBufferD3D10;
    class IndexBufferD3D10;
    class PipelineStateD3D10;
    class EffectTechniqueD3D9;
    class EffectVariableD3D9;
    class EffectTechniqueD3D10;
    class EffectVariableD3D10;
}

namespace boost
{
    class bad_ptr_container_operation;
    class bad_pointer;

    namespace detail
    {
        class tss;

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
         * Address: 0x00539410 (FUN_00539410)
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
         * Address: 0x005383B0 (FUN_005383B0)
         * Address: 0x004D7A20 (FUN_004D7A20, Moho::WeakPtr_AudioEngine::Release)
         * Address: 0x00442BD0 (FUN_00442BD0)
         * Address: 0x00442C40 (FUN_00442C40)
         * Address: 0x00442C90 (FUN_00442C90, boost::shared_ptr_TextureD3D9::reset)
         * Address: 0x00442F20 (FUN_00442F20)
         * Address: 0x00442FA0 (FUN_00442FA0)
         * Address: 0x007D1CD0 (FUN_007D1CD0, boost::shared_ptr_CD3DBatchTexture::~shared_ptr_CD3DBatchTexture)
         * Address: 0x00873780 (FUN_00873780, boost::shared_ptr_UICommandGraph::~shared_ptr_UICommandGraph)
         * Address: 0x00824060 (FUN_00824060, Moho::WeakPtr_UICommandGraph::Release)
         * Address: 0x0053ACA0 (FUN_0053ACA0)
         *
         * What it does:
         * Releases one shared owner from the control block, disposes the pointee
         * on last use, and clears the borrowed raw-ptr lanes.
         */
        void release() noexcept {
            detail::sp_counted_base* const control = pi;
            px = nullptr;
            pi = nullptr;
            if (control != nullptr) {
                control->release();
            }
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

    struct SharedControlTriplet
    {
        std::uint32_t lane0;
        std::uint32_t lane1;
        detail::sp_counted_base* pi;
    };

    static_assert(sizeof(SharedControlTriplet) == 0x0C, "SharedControlTriplet size must be 0x0C");

    /**
     * Address: 0x00935E30 (FUN_00935E30)
     *
     * What it does:
     * Clears one current-thread value from one TSS slot, runs its cleanup
     * callback when present, and then destroys that slot descriptor.
     */
    void ResetCurrentThreadValueAndDestroyTss(detail::tss* tssSlot);

    /**
     * Address: 0x0055AA90 (FUN_0055AA90, boost::shared_ptr_RScmResource::~shared_ptr_RScmResource)
     *
     * What it does:
     * Clears one `boost::shared_ptr<RScmResource>` pair and releases one shared
     * owner reference from its control block.
     */
    [[nodiscard]] inline SharedPtrRaw<moho::RScmResource>* DestroySharedPtrRScmResource(
        SharedPtrRaw<moho::RScmResource>* const sharedResource
    ) noexcept
    {
        if (sharedResource != nullptr) {
            sharedResource->release();
        }
        return sharedResource;
    }

    /**
     * Address: 0x0055AA60 (FUN_0055AA60)
     *
     * What it does:
     * Rebinds one borrowed `boost::shared_ptr<RScmResource>` lane to another by
     * weak-retaining the incoming control block and weak-releasing the previous
     * one, while always copying the raw pointee lane.
     */
    [[nodiscard]] moho::RScmResource** AssignSharedPtrRScmResourceWeak(
        const SharedPtrRaw<moho::RScmResource>* sourceShared,
        SharedPtrRaw<moho::RScmResource>* outShared
    ) noexcept;

    /**
     * Address: 0x0055FBD0 (FUN_0055FBD0, Moho::WeakPtr_RScmResource::WeakPtr_RScmResource)
     *
     * What it does:
     * Initializes one weak `RScmResource` pointer pair from one source
     * `(px,pi)` lane by weak-retaining the incoming control block and
     * weak-releasing the replaced control lane.
     */
    [[nodiscard]] moho::RScmResource** ConstructWeakPtrRScmResourceFromShared(
        const SharedPtrRaw<moho::RScmResource>* sourceShared,
        SharedPtrRaw<moho::RScmResource>* outWeak
    ) noexcept;

    /**
     * Address: 0x00539450 (FUN_00539450, boost::enable_shared_from_this<Moho::RScmResource>::shared_from_this)
     * Mangled: ?shared_from_this@?$enable_shared_from_this@VRScmResource@Moho@@@boost@@QAE?AV?$shared_ptr@VRScmResource@Moho@@@2@XZ
     *
     * What it does:
     * Constructs one `shared_ptr<RScmResource>` from one
     * `enable_shared_from_this<RScmResource>` weak-this lane by building the
     * output shared-count from the source control lane and then copying `px`.
     */
    [[nodiscard]] SharedPtrRaw<moho::RScmResource>* ConstructSharedPtrRScmResourceFromWeakThis(
      const SharedPtrRaw<moho::RScmResource>* sourceWeakThis,
      SharedPtrRaw<moho::RScmResource>* outShared
    );

    /**
     * Address: 0x00796D40 (FUN_00796D40, boost::enable_shared_from_this<Moho::CMauiFrame>::shared_from_this)
     * Mangled: ?shared_from_this@?$enable_shared_from_this@VCMauiFrame@Moho@@@boost@@QAE?AV?$shared_ptr@VCMauiFrame@Moho@@@2@XZ
     *
     * What it does:
     * Constructs one `shared_ptr<CMauiFrame>` from one
     * `enable_shared_from_this<CMauiFrame>` weak-this lane by building the
     * output shared-count from the source control lane and then copying `px`.
     */
    [[nodiscard]] SharedPtrRaw<moho::CMauiFrame>* ConstructSharedPtrCMauiFrameFromWeakThis(
      const SharedPtrRaw<moho::CMauiFrame>* sourceWeakThis,
      SharedPtrRaw<moho::CMauiFrame>* outShared
    );

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
     * Address: 0x00539420 (FUN_00539420)
     * Address: 0x005395D0 (FUN_005395D0)
     * Address: 0x00539AC0 (FUN_00539AC0)
     * Address: 0x0053A080 (FUN_0053A080)
     *
     * What it does:
     * Clears one two-dword lane and returns the caller-owned output slot.
     */
    [[nodiscard]] SharedCountPair* ZeroDwordPairLane(SharedCountPair* outLane) noexcept;

    /**
     * Address: 0x00539470 (FUN_00539470)
     * Address: 0x0053B480 (FUN_0053B480)
     * Address: 0x00540250 (FUN_00540250)
     * Address: 0x00540820 (FUN_00540820)
     * Address: 0x00540D80 (FUN_00540D80)
     * Address: 0x00540DA0 (FUN_00540DA0)
     *
     * What it does:
     * Stores one dword lane value into caller-provided output storage.
     */
    [[nodiscard]] std::uint32_t* StoreDwordLane(std::uint32_t* outLane, std::uint32_t value) noexcept;

    /**
     * Address: 0x00540D90 (FUN_00540D90)
     *
     * What it does:
     * Copies one dword lane value from source storage into caller output.
     */
    [[nodiscard]] std::uint32_t* CopyDwordLane(std::uint32_t* outLane, const std::uint32_t* sourceLane) noexcept;

    /**
     * Address: 0x0053B470 (FUN_0053B470)
     *
     * What it does:
     * Clears one single dword lane and returns the caller-owned output slot.
     */
    [[nodiscard]] std::uint32_t* ZeroDwordLane(std::uint32_t* outLane) noexcept;

    /**
     * Address: 0x00539AD0 (FUN_00539AD0)
     *
     * What it does:
     * Swaps one dword lane between two caller-provided output slots.
     */
    [[nodiscard]] std::uint32_t* SwapDwordLane(std::uint32_t* leftLane, std::uint32_t* rightLane) noexcept;

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

    using SharedByteDeleterFn = void(__cdecl*)(void*);

    struct SpCountedImplPdCharPointerStorage
    {
        void* vftable;
        std::int32_t useCount;
        std::int32_t weakCount;
        char* px;
        SharedByteDeleterFn deleter;
    };
    static_assert(
        sizeof(SpCountedImplPdCharPointerStorage) == 0x14,
        "SpCountedImplPdCharPointerStorage size must be 0x14"
    );

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
     * Address: 0x0053A220 (FUN_0053A220, boost::detail::sp_counted_impl_p<Moho::RScmResource>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `RScmResource`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::RScmResource>* SpCountedImplPConstructRScmResource(
        SpCountedImplStorage<moho::RScmResource>* countedImpl,
        moho::RScmResource* ownedPointee
    ) noexcept;

    /**
     * Address: 0x00545340 (FUN_00545340, boost::detail::sp_counted_impl_p<Moho::LaunchInfoNew>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `LaunchInfoNew`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::LaunchInfoNew>* SpCountedImplPConstructLaunchInfoNew(
        SpCountedImplStorage<moho::LaunchInfoNew>* countedImpl,
        moho::LaunchInfoNew* ownedPointee
    ) noexcept;

    /**
     * Address: 0x005791B0 (FUN_005791B0, boost::detail::sp_counted_impl_p<Moho::CHeightField>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `CHeightField`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::CHeightField>* SpCountedImplPConstructCHeightField(
        SpCountedImplStorage<moho::CHeightField>* countedImpl,
        moho::CHeightField* ownedPointee
    ) noexcept;

    /**
     * Address: 0x005CC7C0 (FUN_005CC7C0, boost::detail::sp_counted_impl_p<Moho::Stats<Moho::StatItem>>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `Stats_StatItem`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::Stats_StatItem>* SpCountedImplPConstructStatsStatItem(
        SpCountedImplStorage<moho::Stats_StatItem>* countedImpl,
        moho::Stats_StatItem* ownedPointee
    ) noexcept;

    /**
     * Address: 0x005CD540 (FUN_005CD540)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `CIntelGrid`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::CIntelGrid>* SpCountedImplPConstructCIntelGrid(
        SpCountedImplStorage<moho::CIntelGrid>* countedImpl,
        moho::CIntelGrid* ownedPointee
    ) noexcept;

    /**
     * Address: 0x0063E760 (FUN_0063E760)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `CAniPose`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::CAniPose>* SpCountedImplPConstructCAniPose(
        SpCountedImplStorage<moho::CAniPose>* countedImpl,
        moho::CAniPose* ownedPointee
    ) noexcept;

    /**
     * Address: 0x007BDC20 (FUN_007BDC20, boost::detail::sp_counted_impl_p<Moho::CGpgNetInterface>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `CGpgNetInterface`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::CGpgNetInterface>* SpCountedImplPConstructCGpgNetInterface(
        SpCountedImplStorage<moho::CGpgNetInterface>* countedImpl,
        moho::CGpgNetInterface* ownedPointee
    ) noexcept;

    /**
     * Address: 0x007E6550 (FUN_007E6550, boost::detail::sp_counted_impl_p<Moho::MeshMaterial>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `MeshMaterial`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::MeshMaterial>* SpCountedImplPConstructMeshMaterial(
        SpCountedImplStorage<moho::MeshMaterial>* countedImpl,
        moho::MeshMaterial* ownedPointee
    ) noexcept;

    /**
     * Address: 0x007E6590 (FUN_007E6590, boost::detail::sp_counted_impl_p<Moho::Mesh>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `Mesh`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::Mesh>* SpCountedImplPConstructMesh(
        SpCountedImplStorage<moho::Mesh>* countedImpl,
        moho::Mesh* ownedPointee
    ) noexcept;

    /**
     * Address: 0x007E6920 (FUN_007E6920, boost::detail::sp_counted_impl_p<Moho::RMeshBlueprintLOD>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `RMeshBlueprintLOD`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::RMeshBlueprintLOD>* SpCountedImplPConstructRMeshBlueprintLOD(
        SpCountedImplStorage<moho::RMeshBlueprintLOD>* countedImpl,
        moho::RMeshBlueprintLOD* ownedPointee
    ) noexcept;

    /**
     * Address: 0x007E6970 (FUN_007E6970, boost::detail::sp_counted_impl_p<Moho::MeshBatch>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `MeshBatch`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::MeshBatch>* SpCountedImplPConstructMeshBatch(
        SpCountedImplStorage<moho::MeshBatch>* countedImpl,
        moho::MeshBatch* ownedPointee
    ) noexcept;

    /**
     * Address: 0x007E69B0 (FUN_007E69B0, boost::detail::sp_counted_impl_pd<Moho::Mesh*,Moho::RefCountedCache<Moho::MeshKey,Moho::Mesh>::Deleter>::sp_counted_impl_pd)
     *
     * What it does:
     * Initializes one recovered mesh-cache `sp_counted_impl_pd` control block
     * and stores one 8-byte deleter payload at `+0x10`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::Mesh>* SpCountedImplPdConstructMeshRefCountedCache(
        SpCountedImplStorage<moho::Mesh>* countedImpl,
        moho::Mesh* ownedPointee,
        std::uint32_t deleterWord0,
        std::uint32_t deleterWord1
    ) noexcept;

    /**
     * Address: 0x008E8990 (FUN_008E8990, boost::detail::sp_counted_impl_p<gpg::gal::TextureD3D9>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `TextureD3D9`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::TextureD3D9>* SpCountedImplPConstructTextureD3D9(
        SpCountedImplStorage<gpg::gal::TextureD3D9>* countedImpl,
        gpg::gal::TextureD3D9* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008E89C0 (FUN_008E89C0, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D9>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `RenderTargetD3D9`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::RenderTargetD3D9>* SpCountedImplPConstructRenderTargetD3D9(
        SpCountedImplStorage<gpg::gal::RenderTargetD3D9>* countedImpl,
        gpg::gal::RenderTargetD3D9* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008E89F0 (FUN_008E89F0, boost::detail::sp_counted_impl_p<gpg::gal::CubeRenderTargetD3D9>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `CubeRenderTargetD3D9`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D9>* SpCountedImplPConstructCubeRenderTargetD3D9(
        SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D9>* countedImpl,
        gpg::gal::CubeRenderTargetD3D9* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008E8A20 (FUN_008E8A20, boost::detail::sp_counted_impl_p<gpg::gal::DepthStencilTargetD3D9>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `DepthStencilTargetD3D9`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D9>* SpCountedImplPConstructDepthStencilTargetD3D9(
        SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D9>* countedImpl,
        gpg::gal::DepthStencilTargetD3D9* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008E8A50 (FUN_008E8A50, boost::detail::sp_counted_impl_p<gpg::gal::VertexFormatD3D9>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `VertexFormatD3D9`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::VertexFormatD3D9>* SpCountedImplPConstructVertexFormatD3D9(
        SpCountedImplStorage<gpg::gal::VertexFormatD3D9>* countedImpl,
        gpg::gal::VertexFormatD3D9* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008E8A80 (FUN_008E8A80, boost::detail::sp_counted_impl_p<gpg::gal::VertexBufferD3D9>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `VertexBufferD3D9`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::VertexBufferD3D9>* SpCountedImplPConstructVertexBufferD3D9(
        SpCountedImplStorage<gpg::gal::VertexBufferD3D9>* countedImpl,
        gpg::gal::VertexBufferD3D9* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008E8AB0 (FUN_008E8AB0, boost::detail::sp_counted_impl_p<gpg::gal::IndexBufferD3D9>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `IndexBufferD3D9`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::IndexBufferD3D9>* SpCountedImplPConstructIndexBufferD3D9(
        SpCountedImplStorage<gpg::gal::IndexBufferD3D9>* countedImpl,
        gpg::gal::IndexBufferD3D9* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008E8AE0 (FUN_008E8AE0, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D9>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `EffectD3D9`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::EffectD3D9>* SpCountedImplPConstructEffectD3D9(
        SpCountedImplStorage<gpg::gal::EffectD3D9>* countedImpl,
        gpg::gal::EffectD3D9* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008E8D80 (FUN_008E8D80, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D9>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `PipelineStateD3D9`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::PipelineStateD3D9>* SpCountedImplPConstructPipelineStateD3D9(
        SpCountedImplStorage<gpg::gal::PipelineStateD3D9>* countedImpl,
        gpg::gal::PipelineStateD3D9* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008F8FC0 (FUN_008F8FC0, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D10>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `EffectD3D10`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::EffectD3D10>* SpCountedImplPConstructEffectD3D10(
        SpCountedImplStorage<gpg::gal::EffectD3D10>* countedImpl,
        gpg::gal::EffectD3D10* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008F8FF0 (FUN_008F8FF0, boost::detail::sp_counted_impl_p<gpg::gal::TextureD3D10>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `TextureD3D10`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::TextureD3D10>* SpCountedImplPConstructTextureD3D10(
        SpCountedImplStorage<gpg::gal::TextureD3D10>* countedImpl,
        gpg::gal::TextureD3D10* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008F9020 (FUN_008F9020, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D10>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `RenderTargetD3D10`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::RenderTargetD3D10>* SpCountedImplPConstructRenderTargetD3D10(
        SpCountedImplStorage<gpg::gal::RenderTargetD3D10>* countedImpl,
        gpg::gal::RenderTargetD3D10* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008F9050 (FUN_008F9050, boost::detail::sp_counted_impl_p<gpg::gal::CubeRenderTargetD3D10>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `CubeRenderTargetD3D10`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D10>* SpCountedImplPConstructCubeRenderTargetD3D10(
        SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D10>* countedImpl,
        gpg::gal::CubeRenderTargetD3D10* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008F9080 (FUN_008F9080, boost::detail::sp_counted_impl_p<gpg::gal::DepthStencilTargetD3D10>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `DepthStencilTargetD3D10`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D10>* SpCountedImplPConstructDepthStencilTargetD3D10(
        SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D10>* countedImpl,
        gpg::gal::DepthStencilTargetD3D10* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008F90B0 (FUN_008F90B0, boost::detail::sp_counted_impl_p<gpg::gal::VertexFormatD3D10>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `VertexFormatD3D10`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::VertexFormatD3D10>* SpCountedImplPConstructVertexFormatD3D10(
        SpCountedImplStorage<gpg::gal::VertexFormatD3D10>* countedImpl,
        gpg::gal::VertexFormatD3D10* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008F90E0 (FUN_008F90E0, boost::detail::sp_counted_impl_p<gpg::gal::VertexBufferD3D10>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `VertexBufferD3D10`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::VertexBufferD3D10>* SpCountedImplPConstructVertexBufferD3D10(
        SpCountedImplStorage<gpg::gal::VertexBufferD3D10>* countedImpl,
        gpg::gal::VertexBufferD3D10* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008F9110 (FUN_008F9110, boost::detail::sp_counted_impl_p<gpg::gal::IndexBufferD3D10>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `IndexBufferD3D10`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::IndexBufferD3D10>* SpCountedImplPConstructIndexBufferD3D10(
        SpCountedImplStorage<gpg::gal::IndexBufferD3D10>* countedImpl,
        gpg::gal::IndexBufferD3D10* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008F9380 (FUN_008F9380, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D10>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `PipelineStateD3D10`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::PipelineStateD3D10>* SpCountedImplPConstructPipelineStateD3D10(
        SpCountedImplStorage<gpg::gal::PipelineStateD3D10>* countedImpl,
        gpg::gal::PipelineStateD3D10* ownedPointee
    ) noexcept;

    /**
     * Address: 0x00923700 (FUN_00923700, boost::detail::sp_counted_impl_p<std::basic_stringstream<char,std::char_traits<char>,std::allocator<char>>>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for one owned
     * `std::basic_stringstream<char,...>` lane.
     */
    [[nodiscard]] SpCountedImplStorage<void>* SpCountedImplPConstructStdStringstreamChar(
        SpCountedImplStorage<void>* countedImpl,
        void* ownedPointee
    ) noexcept;

    /**
     * Address: 0x00931EB0 (FUN_00931EB0, boost::detail::sp_counted_impl_p<gpg::HaStar::ClusterCache::Impl>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for one owned
     * `ClusterCache::Impl` lane.
     */
    [[nodiscard]] SpCountedImplStorage<void>* SpCountedImplPConstructClusterCacheImpl(
        SpCountedImplStorage<void>* countedImpl,
        void* ownedPointee
    ) noexcept;

    /**
     * Address: 0x00941660 (FUN_00941660, boost::detail::sp_counted_impl_p<gpg::gal::EffectTechniqueD3D9>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `EffectTechniqueD3D9`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::EffectTechniqueD3D9>* SpCountedImplPConstructEffectTechniqueD3D9(
        SpCountedImplStorage<gpg::gal::EffectTechniqueD3D9>* countedImpl,
        gpg::gal::EffectTechniqueD3D9* ownedPointee
    ) noexcept;

    /**
     * Address: 0x00941690 (FUN_00941690, boost::detail::sp_counted_impl_p<gpg::gal::EffectVariableD3D9>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `EffectVariableD3D9`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::EffectVariableD3D9>* SpCountedImplPConstructEffectVariableD3D9(
        SpCountedImplStorage<gpg::gal::EffectVariableD3D9>* countedImpl,
        gpg::gal::EffectVariableD3D9* ownedPointee
    ) noexcept;

    /**
     * Address: 0x0094B600 (FUN_0094B600, boost::detail::sp_counted_impl_p<gpg::gal::EffectTechniqueD3D10>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `EffectTechniqueD3D10`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::EffectTechniqueD3D10>* SpCountedImplPConstructEffectTechniqueD3D10(
        SpCountedImplStorage<gpg::gal::EffectTechniqueD3D10>* countedImpl,
        gpg::gal::EffectTechniqueD3D10* ownedPointee
    ) noexcept;

    /**
     * Address: 0x0094B630 (FUN_0094B630, boost::detail::sp_counted_impl_p<gpg::gal::EffectVariableD3D10>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `EffectVariableD3D10`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::EffectVariableD3D10>* SpCountedImplPConstructEffectVariableD3D10(
        SpCountedImplStorage<gpg::gal::EffectVariableD3D10>* countedImpl,
        gpg::gal::EffectVariableD3D10* ownedPointee
    ) noexcept;

    /**
     * Address: 0x0094E070 (FUN_0094E070, boost::detail::sp_counted_impl_pd<char*, void (__cdecl*)(void*)>::sp_counted_impl_pd)
     *
     * What it does:
     * Initializes one recovered byte-pointer `sp_counted_impl_pd` control block
     * with one owned `char*` lane and one raw-function deleter lane.
     */
    [[nodiscard]] SpCountedImplPdCharPointerStorage* SpCountedImplPdConstructCharPointerFunctionDeleter(
        SpCountedImplPdCharPointerStorage* countedImpl,
        char* ownedPointee,
        SharedByteDeleterFn deleter
    ) noexcept;

    /**
     * Address: 0x00714670 (FUN_00714670, boost::detail::sp_counted_impl_p<Moho::STrigger>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `STrigger`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::STrigger>* SpCountedImplPConstructSTrigger(
        SpCountedImplStorage<moho::STrigger>* countedImpl,
        moho::STrigger* ownedPointee
    ) noexcept;

    /**
     * Address: 0x00755FA0 (FUN_00755FA0, boost::detail::sp_counted_impl_p<Moho::ISimResources>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `ISimResources`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::ISimResources>* SpCountedImplPConstructISimResources(
        SpCountedImplStorage<moho::ISimResources>* countedImpl,
        moho::ISimResources* ownedPointee
    ) noexcept;

    /**
     * Address: 0x00755FE0 (FUN_00755FE0, boost::detail::sp_counted_impl_p<Moho::CDebugCanvas>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `CDebugCanvas`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::CDebugCanvas>* SpCountedImplPConstructCDebugCanvas(
        SpCountedImplStorage<moho::CDebugCanvas>* countedImpl,
        moho::CDebugCanvas* ownedPointee
    ) noexcept;

    /**
     * Address: 0x00756030 (FUN_00756030, boost::detail::sp_counted_impl_p<Moho::SParticleBuffer>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `SParticleBuffer`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::SParticleBuffer>* SpCountedImplPConstructSParticleBuffer(
        SpCountedImplStorage<moho::SParticleBuffer>* countedImpl,
        moho::SParticleBuffer* ownedPointee
    ) noexcept;

    /**
     * Address: 0x00765700 (FUN_00765700, boost::detail::sp_counted_impl_p<Moho::PathPreviewFinder>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `PathPreviewFinder`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::PathPreviewFinder>* SpCountedImplPConstructPathPreviewFinder(
        SpCountedImplStorage<moho::PathPreviewFinder>* countedImpl,
        moho::PathPreviewFinder* ownedPointee
    ) noexcept;

    /**
     * Address: 0x00797040 (FUN_00797040, boost::detail::sp_counted_impl_p<Moho::CMauiFrame>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `CMauiFrame`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::CMauiFrame>* SpCountedImplPConstructCMauiFrame(
        SpCountedImplStorage<moho::CMauiFrame>* countedImpl,
        moho::CMauiFrame* ownedPointee
    ) noexcept;

    /**
     * Address: 0x007FC1A0 (FUN_007FC1A0, boost::detail::sp_counted_impl_p<Moho::CD3DPrimBatcher>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `CD3DPrimBatcher`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::CD3DPrimBatcher>* SpCountedImplPConstructCD3DPrimBatcher(
        SpCountedImplStorage<moho::CD3DPrimBatcher>* countedImpl,
        moho::CD3DPrimBatcher* ownedPointee
    ) noexcept;

    /**
     * Address: 0x007FF6B0 (FUN_007FF6B0, boost::detail::sp_counted_impl_p<Moho::ID3DVertexSheet>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `ID3DVertexSheet`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::ID3DVertexSheet>* SpCountedImplPConstructID3DVertexSheet(
        SpCountedImplStorage<moho::ID3DVertexSheet>* countedImpl,
        moho::ID3DVertexSheet* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008142A0 (FUN_008142A0, boost::detail::sp_counted_impl_p<Moho::ShoreCell>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `ShoreCell`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::ShoreCell>* SpCountedImplPConstructShoreCell(
        SpCountedImplStorage<moho::ShoreCell>* countedImpl,
        moho::ShoreCell* ownedPointee
    ) noexcept;

    /**
     * Address: 0x00832A00 (FUN_00832A00, boost::detail::sp_counted_impl_p<Moho::MeshInstance>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for `MeshInstance`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::MeshInstance>* SpCountedImplPConstructMeshInstance(
        SpCountedImplStorage<moho::MeshInstance>* countedImpl,
        moho::MeshInstance* ownedPointee
    ) noexcept;

    /**
     * Address: 0x008847F0 (FUN_008847F0, boost::detail::sp_counted_impl_pd<_iobuf*,Moho::SFileStarCloser>::sp_counted_impl_pd)
     *
     * What it does:
     * Initializes one recovered file-closer `sp_counted_impl_pd` control block
     * with one owned `FILE*` lane.
     */
    [[nodiscard]] SpCountedImplStorage<void>* SpCountedImplPdConstructSFileStarCloser(
        SpCountedImplStorage<void>* countedImpl,
        void* ownedPointee
    ) noexcept;

    /**
     * Address: 0x00884EF0 (FUN_00884EF0, boost::detail::sp_counted_impl_p<Moho::LaunchInfoLoad>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `LaunchInfoLoad`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::LaunchInfoLoad>* SpCountedImplPConstructLaunchInfoLoad(
        SpCountedImplStorage<moho::LaunchInfoLoad>* countedImpl,
        moho::LaunchInfoLoad* ownedPointee
    ) noexcept;

    /**
     * Address: 0x0089B840 (FUN_0089B840, boost::detail::sp_counted_impl_p<Moho::SSessionSaveData>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `SSessionSaveData`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::SSessionSaveData>* SpCountedImplPConstructSSessionSaveData(
        SpCountedImplStorage<moho::SSessionSaveData>* countedImpl,
        moho::SSessionSaveData* ownedPointee
    ) noexcept;

    /**
     * Address: 0x0089BC70 (FUN_0089BC70, boost::detail::sp_counted_impl_p<Moho::UICommandGraph>::sp_counted_impl_p)
     *
     * What it does:
     * Initializes one recovered shared-count control block for
     * `UICommandGraph`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::UICommandGraph>* SpCountedImplPConstructUICommandGraph(
        SpCountedImplStorage<moho::UICommandGraph>* countedImpl,
        moho::UICommandGraph* ownedPointee
    ) noexcept;

    /**
     * Address: 0x005CC850 (FUN_005CC850)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `Stats_StatItem` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForStatsStatItem(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x005CD5E0 (FUN_005CD5E0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `CIntelGrid` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForCIntelGrid(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x0063E7D0 (FUN_0063E7D0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `CAniPose` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForCAniPose(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x007BDC80 (FUN_007BDC80)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `CGpgNetInterface` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForCGpgNetInterface(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x007E6620 (FUN_007E6620)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `MeshMaterial` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForMeshMaterial(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x007E6630 (FUN_007E6630)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `Mesh` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForMesh(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x007E6AA0 (FUN_007E6AA0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `RMeshBlueprintLOD` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForRMeshBlueprintLOD(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x007E6AB0 (FUN_007E6AB0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `MeshBatch` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForMeshBatch(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x007E6AC0 (FUN_007E6AC0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * mesh-cache `sp_counted_impl_pd` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForMeshRefCountedCache(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008E8B10 (FUN_008E8B10, boost::detail::sp_counted_base::sp_counted_base)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `TextureD3D9` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForTextureD3D9(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008E8B20 (FUN_008E8B20)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `RenderTargetD3D9` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForRenderTargetD3D9(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008E8B30 (FUN_008E8B30)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `CubeRenderTargetD3D9` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForCubeRenderTargetD3D9(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008E8B40 (FUN_008E8B40)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `DepthStencilTargetD3D9` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForDepthStencilTargetD3D9(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008E8B50 (FUN_008E8B50)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `VertexFormatD3D9` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForVertexFormatD3D9(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008E8B60 (FUN_008E8B60)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `VertexBufferD3D9` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForVertexBufferD3D9(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008E8B70 (FUN_008E8B70)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `IndexBufferD3D9` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForIndexBufferD3D9(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008E8B80 (FUN_008E8B80)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `EffectD3D9` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForEffectD3D9(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008E8DB0 (FUN_008E8DB0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `PipelineStateD3D9` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForPipelineStateD3D9(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008F9140 (FUN_008F9140)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `EffectD3D10` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForEffectD3D10(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008F9150 (FUN_008F9150)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `TextureD3D10` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForTextureD3D10(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008F9160 (FUN_008F9160)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `RenderTargetD3D10` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForRenderTargetD3D10(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008F9170 (FUN_008F9170)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `CubeRenderTargetD3D10` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForCubeRenderTargetD3D10(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008F9180 (FUN_008F9180)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `DepthStencilTargetD3D10` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForDepthStencilTargetD3D10(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008F9190 (FUN_008F9190)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `VertexFormatD3D10` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForVertexFormatD3D10(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008F91A0 (FUN_008F91A0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `VertexBufferD3D10` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForVertexBufferD3D10(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008F91B0 (FUN_008F91B0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `IndexBufferD3D10` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForIndexBufferD3D10(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x008F93B0 (FUN_008F93B0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `PipelineStateD3D10` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForPipelineStateD3D10(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x00923730 (FUN_00923730)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `std::basic_stringstream<char,...>` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForStdStringstreamChar(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x00931EE0 (FUN_00931EE0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `ClusterCache::Impl` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForClusterCacheImpl(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x009416C0 (FUN_009416C0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `EffectTechniqueD3D9` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForEffectTechniqueD3D9(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x009416D0 (FUN_009416D0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `EffectVariableD3D9` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForEffectVariableD3D9(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x0094B660 (FUN_0094B660)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `EffectTechniqueD3D10` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForEffectTechniqueD3D10(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x0094B670 (FUN_0094B670)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `EffectVariableD3D10` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForEffectVariableD3D10(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x0094E0E0 (FUN_0094E0E0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `char*` function-deleter control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForCharPointerFunctionDeleter(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x007FC230 (FUN_007FC230)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `CD3DTextureBatcher` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForCD3DTextureBatcher(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x007FC240 (FUN_007FC240)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `CD3DPrimBatcher` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForCD3DPrimBatcher(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x007FF710 (FUN_007FF710)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `ID3DVertexSheet` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForID3DVertexSheet(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x00814300 (FUN_00814300)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `ShoreCell` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForShoreCell(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x00832A60 (FUN_00832A60)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `MeshInstance` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForMeshInstance(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x00884890 (FUN_00884890, boost::detail::sp_counted_base::sp_counted_base)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * file-closer `sp_counted_impl_pd` init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForFileStarCloser(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x00884F50 (FUN_00884F50, boost::detail::sp_counted_base::sp_counted_base)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `LaunchInfoLoad` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForLaunchInfoLoad(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x0089B930 (FUN_0089B930, boost::detail::sp_counted_base::sp_counted_base)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `SSessionSaveData` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForSSessionSaveData(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x0089BCE0 (FUN_0089BCE0, boost::detail::sp_counted_base::sp_counted_base)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `UICommandGraph` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForUICommandGraph(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x007146E0 (FUN_007146E0, boost::detail::sp_counted_base::sp_counted_base)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane for the trigger
     * shared-count constructor path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForSTrigger(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x007560E0 (FUN_007560E0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `ISimResources` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForISimResources(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x007560F0 (FUN_007560F0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `CDebugCanvas` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForCDebugCanvas(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x00756100 (FUN_00756100)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `SParticleBuffer` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForSParticleBuffer(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x00765790 (FUN_00765790)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `PathPreviewFinder` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForPathPreviewFinder(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x007970B0 (FUN_007970B0)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `CMauiFrame` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForCMauiFrame(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x0053A290 (FUN_0053A290)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `RScmResource` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForRScmResource(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x0053B420 (FUN_0053B420)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `RScaResource` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForRScaResource(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x00545460 (FUN_00545460)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `LaunchInfoNew` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForLaunchInfoNew(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x0054EE20 (FUN_0054EE20)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `CAniDefaultSkel` function-deleter control path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForAniDefaultSkelDeleter(
        detail::sp_counted_base* control
    ) noexcept;

    /**
     * Address: 0x00579210 (FUN_00579210)
     *
     * What it does:
     * Restores one abstract `sp_counted_base` vtable lane used by the
     * `CHeightField` control-block init path.
     */
    [[nodiscard]] detail::sp_counted_base* InitializeSpCountedBaseLaneForCHeightField(
        detail::sp_counted_base* control
    ) noexcept;

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
     * Address: 0x0053A240 (FUN_0053A240, boost::detail::sp_counted_impl_p<Moho::RScmResource>::dispose)
     *
     * What it does:
     * Deletes one owned `RScmResource` pointee bound to this shared-count
     * control lane when present.
     */
    void SpCountedImplPDisposeRScmResource(
        SpCountedImplStorage<moho::RScmResource>* countedImpl
    ) noexcept;

    /**
     * Address: 0x0053B3D0 (FUN_0053B3D0, boost::detail::sp_counted_impl_p<Moho::RScaResource>::dispose)
     *
     * What it does:
     * Deletes one owned `RScaResource` pointee bound to this shared-count
     * control lane when present.
     */
    void SpCountedImplPDisposeRScaResource(
        SpCountedImplStorage<moho::RScaResource>* countedImpl
    ) noexcept;

    /**
     * Address: 0x00545360 (FUN_00545360, boost::detail::sp_counted_impl_p<Moho::LaunchInfoNew>::dispose)
     *
     * What it does:
     * Deletes one owned `LaunchInfoNew` pointee bound to this shared-count
     * control lane when present.
     */
    void SpCountedImplPDisposeLaunchInfoNew(
        SpCountedImplStorage<moho::LaunchInfoNew>* countedImpl
    ) noexcept;

    /**
     * Address: 0x005CC7E0 (FUN_005CC7E0, boost::detail::sp_counted_impl_p<Moho::Stats<Moho::StatItem>>::dispose)
     *
     * What it does:
     * Deletes one owned `Stats_StatItem` pointee bound to this shared-count
     * control lane when present.
     */
    void SpCountedImplPDisposeStatsStatItem(
        SpCountedImplStorage<moho::Stats_StatItem>* countedImpl
    ) noexcept;

    /**
     * Address: 0x005CD560 (FUN_005CD560, boost::detail::sp_counted_impl_p<Moho::CIntelGrid>::dispose)
     *
     * What it does:
     * Deletes one owned `CIntelGrid` pointee bound to this shared-count
     * control lane when present.
     */
    void SpCountedImplPDisposeCIntelGrid(
        SpCountedImplStorage<moho::CIntelGrid>* countedImpl
    ) noexcept;

    /**
     * Address: 0x0063E780 (FUN_0063E780, boost::detail::sp_counted_impl_p<Moho::CAniPose>::dispose)
     *
     * What it does:
     * Deletes one owned `CAniPose` pointee bound to this shared-count control
     * lane when present.
     */
    void SpCountedImplPDisposeCAniPose(
        SpCountedImplStorage<moho::CAniPose>* countedImpl
    ) noexcept;

    /**
     * Address: 0x00714690 (FUN_00714690, boost::detail::sp_counted_impl_p<Moho::STrigger>::dispose)
     *
     * What it does:
     * Deletes one owned `STrigger` pointee bound to this shared-count control
     * lane when present.
     */
    void SpCountedImplPDisposeSTrigger(
        SpCountedImplStorage<moho::STrigger>* countedImpl
    ) noexcept;

    /**
     * Address: 0x00756000 (FUN_00756000, boost::detail::sp_counted_impl_p<Moho::CDebugCanvas>::dispose)
     *
     * What it does:
     * Deletes one owned `CDebugCanvas` pointee bound to this shared-count
     * control lane when present.
     */
    void SpCountedImplPDisposeCDebugCanvas(
        SpCountedImplStorage<moho::CDebugCanvas>* countedImpl
    ) noexcept;

    /**
     * Address: 0x00756050 (FUN_00756050, boost::detail::sp_counted_impl_p<Moho::SParticleBuffer>::dispose)
     *
     * What it does:
     * Deletes one owned `SParticleBuffer` pointee bound to this shared-count
     * control lane when present.
     */
    void SpCountedImplPDisposeSParticleBuffer(
        SpCountedImplStorage<moho::SParticleBuffer>* countedImpl
    ) noexcept;

    /**
     * Address: 0x007BDC40 (FUN_007BDC40, boost::detail::sp_counted_impl_p<Moho::CGpgNetInterface>::dispose)
     *
     * What it does:
     * Releases one owned `CGpgNetInterface` pointee through its
     * scalar-deleting virtual destructor lane when present.
     */
    void SpCountedImplPDisposeCGpgNetInterface(
        SpCountedImplStorage<moho::CGpgNetInterface>* countedImpl
    ) noexcept;

    /**
     * Address: 0x007E6570 (FUN_007E6570, boost::detail::sp_counted_impl_p<Moho::MeshMaterial>::dispose)
     *
     * What it does:
     * Releases one owned `MeshMaterial` pointee through its scalar-deleting
     * virtual destructor lane when present.
     */
    void SpCountedImplPDisposeMeshMaterial(
        SpCountedImplStorage<moho::MeshMaterial>* countedImpl
    ) noexcept;

    /**
     * Address: 0x007E65B0 (FUN_007E65B0, boost::detail::sp_counted_impl_p<Moho::Mesh>::dispose)
     *
     * What it does:
     * Releases one owned `Mesh` pointee through its secondary deleting
     * virtual destructor lane (`vtable[1]`) when present.
     */
    void SpCountedImplPDisposeMesh(
        SpCountedImplStorage<moho::Mesh>* countedImpl
    ) noexcept;

    /**
     * Address: 0x007E6990 (FUN_007E6990, boost::detail::sp_counted_impl_p<Moho::MeshBatch>::dispose)
     *
     * What it does:
     * Releases one owned `MeshBatch` pointee through its scalar-deleting
     * virtual destructor lane when present.
     */
    void SpCountedImplPDisposeMeshBatch(
        SpCountedImplStorage<moho::MeshBatch>* countedImpl
    ) noexcept;

    /**
     * Address: 0x007FBE60 (FUN_007FBE60, boost::detail::sp_counted_impl_p<Moho::IRenTerrain>::dispose)
     *
     * What it does:
     * Releases one owned `IRenTerrain` pointee through its scalar-deleting
     * virtual destructor lane when present.
     */
    void SpCountedImplPDisposeIRenTerrain(
        SpCountedImplStorage<moho::IRenTerrain>* countedImpl
    ) noexcept;

    /**
     * Address: 0x007FF6D0 (FUN_007FF6D0, boost::detail::sp_counted_impl_p<Moho::ID3DVertexSheet>::dispose)
     *
     * What it does:
     * Releases one owned `ID3DVertexSheet` pointee through its scalar-deleting
     * virtual destructor lane when present.
     */
    void SpCountedImplPDisposeID3DVertexSheet(
        SpCountedImplStorage<moho::ID3DVertexSheet>* countedImpl
    ) noexcept;

    /**
     * Address: 0x008142C0 (FUN_008142C0, boost::detail::sp_counted_impl_p<Moho::ShoreCell>::dispose)
     *
     * What it does:
     * Releases one owned `ShoreCell` pointee through its scalar-deleting
     * virtual destructor lane when present.
     */
    void SpCountedImplPDisposeShoreCell(
        SpCountedImplStorage<moho::ShoreCell>* countedImpl
    ) noexcept;

    /**
     * Address: 0x00832A20 (FUN_00832A20, boost::detail::sp_counted_impl_p<Moho::MeshInstance>::dispose)
     *
     * What it does:
     * Releases one owned `MeshInstance` pointee through its scalar-deleting
     * virtual destructor lane when present.
     */
    void SpCountedImplPDisposeMeshInstance(
        SpCountedImplStorage<moho::MeshInstance>* countedImpl
    ) noexcept;

    /**
     * Address: 0x00884F10 (FUN_00884F10, boost::detail::sp_counted_impl_p<Moho::LaunchInfoLoad>::dispose)
     *
     * What it does:
     * Releases one owned `LaunchInfoLoad` pointee through its scalar-deleting
     * virtual destructor lane when present.
     */
    void SpCountedImplPDisposeLaunchInfoLoad(
        SpCountedImplStorage<moho::LaunchInfoLoad>* countedImpl
    ) noexcept;

    /**
     * Address: 0x00765720 (FUN_00765720, boost::detail::sp_counted_impl_p<Moho::PathPreviewFinder>::dispose)
     *
     * What it does:
     * Disposes one `PathPreviewFinder` pointee by unlinking its intrusive
     * queue node lanes and releasing the owned runtime object memory.
     */
    void SpCountedImplPDisposePathPreviewFinder(
        SpCountedImplStorage<moho::PathPreviewFinder>* countedImpl
    ) noexcept;

    /**
     * Address: 0x00884810 (FUN_00884810, boost::detail::sp_counted_impl_pd<_iobuf*,Moho::SFileStarCloser>::dispose)
     *
     * What it does:
     * Closes one owned `FILE*` lane through `fclose` when that file pointer is
     * present in the file-star-closer control block.
     */
    void SpCountedImplPdDisposeSFileStarCloser(
        SpCountedImplStorage<void>* countedImpl
    ) noexcept;

    /**
     * Address: 0x0054EDC0 (FUN_0054EDC0, boost::detail::sp_counted_impl_pd<Moho::CAniDefaultSkel *, void (__cdecl *)(void *)>::dispose)
     *
     * What it does:
     * Invokes the stored raw-function deleter lane for one `CAniDefaultSkel*`
     * pointee when both lanes are present in the control block.
     */
    void SpCountedImplPdDisposeCAniDefaultSkelFunctionDeleter(
        SpCountedImplStorage<void>* countedImpl
    ) noexcept;

    /**
     * Address: 0x008E9840 (FUN_008E9840, boost::detail::sp_counted_impl_p<gpg::gal::TextureD3D9>::dispose)
     *
     * What it does:
     * Releases one owned `TextureD3D9` pointee through its scalar-deleting
     * virtual destructor lane when present.
     */
    void SpCountedImplPDisposeTextureD3D9(
        SpCountedImplStorage<gpg::gal::TextureD3D9>* countedImpl
    ) noexcept;

    /**
     * Address: 0x008E9850 (FUN_008E9850, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D9>::dispose)
     *
     * What it does:
     * Releases one owned `RenderTargetD3D9` pointee through its
     * scalar-deleting virtual destructor lane when present.
     */
    void SpCountedImplPDisposeRenderTargetD3D9(
        SpCountedImplStorage<gpg::gal::RenderTargetD3D9>* countedImpl
    ) noexcept;

    /**
     * Address: 0x008E9860 (FUN_008E9860, boost::detail::sp_counted_impl_p<gpg::gal::CubeRenderTargetD3D9>::dispose)
     *
     * What it does:
     * Releases one owned `CubeRenderTargetD3D9` pointee through its
     * scalar-deleting virtual destructor lane when present.
     */
    void SpCountedImplPDisposeCubeRenderTargetD3D9(
        SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D9>* countedImpl
    ) noexcept;

    /**
     * Address: 0x008E9870 (FUN_008E9870, boost::detail::sp_counted_impl_p<gpg::gal::DepthStencilTargetD3D9>::dispose)
     *
     * What it does:
     * Releases one owned `DepthStencilTargetD3D9` pointee through its
     * scalar-deleting virtual destructor lane when present.
     */
    void SpCountedImplPDisposeDepthStencilTargetD3D9(
        SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D9>* countedImpl
    ) noexcept;

    /**
     * Address: 0x008E9880 (FUN_008E9880, boost::detail::sp_counted_impl_p<gpg::gal::VertexFormatD3D9>::dispose)
     *
     * What it does:
     * Releases one owned `VertexFormatD3D9` pointee through its
     * scalar-deleting virtual destructor lane when present.
     */
    void SpCountedImplPDisposeVertexFormatD3D9(
        SpCountedImplStorage<gpg::gal::VertexFormatD3D9>* countedImpl
    ) noexcept;

    /**
     * Address: 0x008E9890 (FUN_008E9890, boost::detail::sp_counted_impl_p<gpg::gal::VertexBufferD3D9>::dispose)
     *
     * What it does:
     * Releases one owned `VertexBufferD3D9` pointee through its
     * scalar-deleting virtual destructor lane when present.
     */
    void SpCountedImplPDisposeVertexBufferD3D9(
        SpCountedImplStorage<gpg::gal::VertexBufferD3D9>* countedImpl
    ) noexcept;

    /**
     * Address: 0x008E98A0 (FUN_008E98A0, boost::detail::sp_counted_impl_p<gpg::gal::IndexBufferD3D9>::dispose)
     *
     * What it does:
     * Releases one owned `IndexBufferD3D9` pointee through its
     * scalar-deleting virtual destructor lane when present.
     */
    void SpCountedImplPDisposeIndexBufferD3D9(
        SpCountedImplStorage<gpg::gal::IndexBufferD3D9>* countedImpl
    ) noexcept;

    /**
     * Address: 0x008E98B0 (FUN_008E98B0, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D9>::dispose)
     *
     * What it does:
     * Releases one owned `EffectD3D9` pointee through its scalar-deleting
     * virtual destructor lane when present.
     */
    void SpCountedImplPDisposeEffectD3D9(
        SpCountedImplStorage<gpg::gal::EffectD3D9>* countedImpl
    ) noexcept;

    /**
     * Address: 0x008E9A70 (FUN_008E9A70, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D9>::dispose)
     *
     * What it does:
     * Releases one owned `PipelineStateD3D9` pointee through its
     * scalar-deleting virtual destructor lane when present.
     */
    void SpCountedImplPDisposePipelineStateD3D9(
        SpCountedImplStorage<gpg::gal::PipelineStateD3D9>* countedImpl
    ) noexcept;

    /**
     * Address: 0x008F9F40 (FUN_008F9F40, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D10>::dispose variant)
     *
     * What it does:
     * Releases one owned `EffectD3D10` pointee through its scalar-deleting
     * virtual destructor lane when present (alternate emitted lane).
     */
    void SpCountedImplPDisposeEffectD3D10VariantA(
        SpCountedImplStorage<gpg::gal::EffectD3D10>* countedImpl
    ) noexcept;

    /**
     * Address: 0x008F9F60 (FUN_008F9F60, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D10>::dispose)
     *
     * What it does:
     * Releases one owned `RenderTargetD3D10` pointee through its
     * scalar-deleting virtual destructor lane when present.
     */
    void SpCountedImplPDisposeRenderTargetD3D10(
        SpCountedImplStorage<gpg::gal::RenderTargetD3D10>* countedImpl
    ) noexcept;

    /**
     * Address: 0x008F9FB0 (FUN_008F9FB0, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D10>::dispose)
     *
     * What it does:
     * Deletes one owned `EffectD3D10` pointee bound to this shared-count
     * control lane when present.
     */
    void SpCountedImplPDisposeEffectD3D10(
        SpCountedImplStorage<gpg::gal::EffectD3D10>* countedImpl
    ) noexcept;

    /**
     * Address: 0x008FA190 (FUN_008FA190, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D10>::dispose)
     *
     * What it does:
     * Deletes one owned `PipelineStateD3D10` pointee bound to this
     * shared-count control lane when present.
     */
    void SpCountedImplPDisposePipelineStateD3D10(
        SpCountedImplStorage<gpg::gal::PipelineStateD3D10>* countedImpl
    ) noexcept;

    /**
     * Address: 0x00923920 (FUN_00923920, boost::detail::sp_counted_impl_p<std::basic_stringstream<char, std::char_traits<char>, std::allocator<char>>>::dispose)
     *
     * What it does:
     * Deletes one owned `std::basic_stringstream<char,...>` pointee bound to
     * this shared-count control lane when present.
     */
    void SpCountedImplPDisposeStdStringstreamChar(
        SpCountedImplStorage<void>* countedImpl
    ) noexcept;

    /**
     * Address: 0x009418D0 (FUN_009418D0, boost::detail::sp_counted_impl_p<gpg::gal::EffectTechniqueD3D9>::dispose)
     *
     * What it does:
     * Deletes one owned `EffectTechniqueD3D9` pointee bound to this
     * shared-count control lane when present.
     */
    void SpCountedImplPDisposeEffectTechniqueD3D9(
        SpCountedImplStorage<gpg::gal::EffectTechniqueD3D9>* countedImpl
    ) noexcept;

    /**
     * Address: 0x009418E0 (FUN_009418E0, boost::detail::sp_counted_impl_p<gpg::gal::EffectVariableD3D9>::dispose)
     *
     * What it does:
     * Deletes one owned `EffectVariableD3D9` pointee bound to this
     * shared-count control lane when present.
     */
    void SpCountedImplPDisposeEffectVariableD3D9(
        SpCountedImplStorage<gpg::gal::EffectVariableD3D9>* countedImpl
    ) noexcept;

    /**
     * Address: 0x0094B7E0 (FUN_0094B7E0, boost::detail::sp_counted_impl_p<gpg::gal::EffectTechniqueD3D10>::dispose)
     *
     * What it does:
     * Deletes one owned `EffectTechniqueD3D10` pointee bound to this
     * shared-count control lane when present.
     */
    void SpCountedImplPDisposeEffectTechniqueD3D10(
        SpCountedImplStorage<gpg::gal::EffectTechniqueD3D10>* countedImpl
    ) noexcept;

    /**
     * Address: 0x0094B7F0 (FUN_0094B7F0, boost::detail::sp_counted_impl_p<gpg::gal::EffectVariableD3D10>::dispose)
     *
     * What it does:
     * Deletes one owned `EffectVariableD3D10` pointee bound to this
     * shared-count control lane when present.
     */
    void SpCountedImplPDisposeEffectVariableD3D10(
        SpCountedImplStorage<gpg::gal::EffectVariableD3D10>* countedImpl
    ) noexcept;

    /**
     * Address: 0x0094E0A0 (FUN_0094E0A0, boost::detail::sp_counted_impl_pd<char*, void (__cdecl*)(void*)>::dispose)
     *
     * What it does:
     * Invokes the stored byte-pointer deleter lane for one
     * `sp_counted_impl_pd<char*,void(*)(void*)>` control block.
     */
    void SpCountedImplPdDisposeCharPointerFunctionDeleter(
        SpCountedImplPdCharPointerStorage* countedImpl
    ) noexcept;

    /**
     * Address: 0x005CC830 (FUN_005CC830, boost::detail::sp_counted_impl_p<Moho::Stats<Moho::StatItem>>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<Stats<StatItem>>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::Stats_StatItem>* SpCountedImplPDeletingDtorStatsStatItem(
        SpCountedImplStorage<moho::Stats_StatItem>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x005CD5C0 (FUN_005CD5C0, boost::detail::sp_counted_impl_p<Moho::CIntelGrid>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<CIntelGrid>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::CIntelGrid>* SpCountedImplPDeletingDtorCIntelGrid(
        SpCountedImplStorage<moho::CIntelGrid>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x0063E7B0 (FUN_0063E7B0, boost::detail::sp_counted_impl_p<Moho::CAniPose>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<CAniPose>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::CAniPose>* SpCountedImplPDeletingDtorCAniPose(
        SpCountedImplStorage<moho::CAniPose>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x007146C0 (FUN_007146C0, boost::detail::sp_counted_impl_p<Moho::STrigger>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<STrigger>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::STrigger>* SpCountedImplPDeletingDtorSTrigger(
        SpCountedImplStorage<moho::STrigger>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x00756080 (FUN_00756080, boost::detail::sp_counted_impl_p<Moho::ISimResources>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<ISimResources>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::ISimResources>* SpCountedImplPDeletingDtorISimResources(
        SpCountedImplStorage<moho::ISimResources>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x007560A0 (FUN_007560A0, boost::detail::sp_counted_impl_p<Moho::CDebugCanvas>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<CDebugCanvas>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::CDebugCanvas>* SpCountedImplPDeletingDtorCDebugCanvas(
        SpCountedImplStorage<moho::CDebugCanvas>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x007560C0 (FUN_007560C0, boost::detail::sp_counted_impl_p<Moho::SParticleBuffer>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<SParticleBuffer>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::SParticleBuffer>* SpCountedImplPDeletingDtorSParticleBuffer(
        SpCountedImplStorage<moho::SParticleBuffer>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x00765770 (FUN_00765770, boost::detail::sp_counted_impl_p<Moho::PathPreviewFinder>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<PathPreviewFinder>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::PathPreviewFinder>* SpCountedImplPDeletingDtorPathPreviewFinder(
        SpCountedImplStorage<moho::PathPreviewFinder>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008F9FE0 (FUN_008F9FE0, boost::detail::sp_counted_impl_p<gpg::gal::TextureD3D10>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<TextureD3D10>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::TextureD3D10>* SpCountedImplPDeletingDtorTextureD3D10(
        SpCountedImplStorage<gpg::gal::TextureD3D10>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008FA000 (FUN_008FA000, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D10>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<RenderTargetD3D10>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::RenderTargetD3D10>* SpCountedImplPDeletingDtorRenderTargetD3D10(
        SpCountedImplStorage<gpg::gal::RenderTargetD3D10>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008FA020 (FUN_008FA020, boost::detail::sp_counted_impl_p<gpg::gal::CubeRenderTargetD3D10>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<CubeRenderTargetD3D10>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D10>* SpCountedImplPDeletingDtorCubeRenderTargetD3D10(
        SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D10>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008FA040 (FUN_008FA040, boost::detail::sp_counted_impl_p<gpg::gal::DepthStencilTargetD3D10>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<DepthStencilTargetD3D10>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D10>* SpCountedImplPDeletingDtorDepthStencilTargetD3D10(
        SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D10>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008FA060 (FUN_008FA060, boost::detail::sp_counted_impl_p<gpg::gal::VertexFormatD3D10>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<VertexFormatD3D10>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::VertexFormatD3D10>* SpCountedImplPDeletingDtorVertexFormatD3D10(
        SpCountedImplStorage<gpg::gal::VertexFormatD3D10>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008FA080 (FUN_008FA080, boost::detail::sp_counted_impl_p<gpg::gal::VertexBufferD3D10>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<VertexBufferD3D10>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::VertexBufferD3D10>* SpCountedImplPDeletingDtorVertexBufferD3D10(
        SpCountedImplStorage<gpg::gal::VertexBufferD3D10>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008FA0A0 (FUN_008FA0A0, boost::detail::sp_counted_impl_p<gpg::gal::IndexBufferD3D10>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<IndexBufferD3D10>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::IndexBufferD3D10>* SpCountedImplPDeletingDtorIndexBufferD3D10(
        SpCountedImplStorage<gpg::gal::IndexBufferD3D10>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008FA1A0 (FUN_008FA1A0, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D10>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<PipelineStateD3D10>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::PipelineStateD3D10>* SpCountedImplPDeletingDtorPipelineStateD3D10(
        SpCountedImplStorage<gpg::gal::PipelineStateD3D10>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x00923940 (FUN_00923940, boost::detail::sp_counted_impl_p<std::basic_stringstream<char, std::char_traits<char>, std::allocator<char>>>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<std::basic_stringstream<char,...>>`.
     */
    [[nodiscard]] SpCountedImplStorage<void>* SpCountedImplPDeletingDtorStdStringstreamChar(
        SpCountedImplStorage<void>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x009325F0 (FUN_009325F0, boost::detail::sp_counted_impl_p<gpg::HaStar::ClusterCache::Impl>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<ClusterCache::Impl>`.
     */
    [[nodiscard]] SpCountedImplStorage<void>* SpCountedImplPDeletingDtorClusterCacheImpl(
        SpCountedImplStorage<void>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x009418F0 (FUN_009418F0, boost::detail::sp_counted_impl_p<gpg::gal::EffectTechniqueD3D9>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<EffectTechniqueD3D9>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::EffectTechniqueD3D9>* SpCountedImplPDeletingDtorEffectTechniqueD3D9(
        SpCountedImplStorage<gpg::gal::EffectTechniqueD3D9>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x00941910 (FUN_00941910, boost::detail::sp_counted_impl_p<gpg::gal::EffectVariableD3D9>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<EffectVariableD3D9>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::EffectVariableD3D9>* SpCountedImplPDeletingDtorEffectVariableD3D9(
        SpCountedImplStorage<gpg::gal::EffectVariableD3D9>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x0094B800 (FUN_0094B800, boost::detail::sp_counted_impl_p<gpg::gal::EffectTechniqueD3D10>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<EffectTechniqueD3D10>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::EffectTechniqueD3D10>* SpCountedImplPDeletingDtorEffectTechniqueD3D10(
        SpCountedImplStorage<gpg::gal::EffectTechniqueD3D10>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x0094B820 (FUN_0094B820, boost::detail::sp_counted_impl_p<gpg::gal::EffectVariableD3D10>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_p<EffectVariableD3D10>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::EffectVariableD3D10>* SpCountedImplPDeletingDtorEffectVariableD3D10(
        SpCountedImplStorage<gpg::gal::EffectVariableD3D10>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x0094E260 (FUN_0094E260, boost::detail::sp_counted_impl_pd<char*, void (__cdecl*)(void*)>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for
     * `sp_counted_impl_pd<char*, void(__cdecl*)(void*)>`.
     */
    [[nodiscard]] SpCountedImplPdCharPointerStorage* SpCountedImplPdDeletingDtorCharPointerFunctionDeleter(
        SpCountedImplPdCharPointerStorage* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x00797090 (FUN_00797090, boost::detail::sp_counted_impl_p<Moho::CMauiFrame>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<CMauiFrame>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::CMauiFrame>* SpCountedImplPDeletingDtorCMauiFrame(
        SpCountedImplStorage<moho::CMauiFrame>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x007BDC60 (FUN_007BDC60, boost::detail::sp_counted_impl_p<Moho::CGpgNetInterface>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<CGpgNetInterface>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::CGpgNetInterface>* SpCountedImplPDeletingDtorCGpgNetInterface(
        SpCountedImplStorage<moho::CGpgNetInterface>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x007E65E0 (FUN_007E65E0, boost::detail::sp_counted_impl_p<Moho::MeshMaterial>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<MeshMaterial>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::MeshMaterial>* SpCountedImplPDeletingDtorMeshMaterial(
        SpCountedImplStorage<moho::MeshMaterial>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x007E6600 (FUN_007E6600, boost::detail::sp_counted_impl_p<Moho::Mesh>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<Mesh>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::Mesh>* SpCountedImplPDeletingDtorMesh(
        SpCountedImplStorage<moho::Mesh>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x007E6A40 (FUN_007E6A40, boost::detail::sp_counted_impl_p<Moho::RMeshBlueprintLOD>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<RMeshBlueprintLOD>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::RMeshBlueprintLOD>* SpCountedImplPDeletingDtorRMeshBlueprintLOD(
        SpCountedImplStorage<moho::RMeshBlueprintLOD>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x007E6A60 (FUN_007E6A60, boost::detail::sp_counted_impl_p<Moho::MeshBatch>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<MeshBatch>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::MeshBatch>* SpCountedImplPDeletingDtorMeshBatch(
        SpCountedImplStorage<moho::MeshBatch>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x007E6A80 (FUN_007E6A80, boost::detail::sp_counted_impl_pd<Moho::Mesh*,Moho::RefCountedCache<Moho::MeshKey,Moho::Mesh>::Deleter>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for one
     * `sp_counted_impl_pd<Mesh*,MeshCacheDeleter>` lane.
     */
    [[nodiscard]] SpCountedImplStorage<moho::Mesh>* SpCountedImplPdDeletingDtorMeshRefCountedCache(
        SpCountedImplStorage<moho::Mesh>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x007FBE80 (FUN_007FBE80, boost::detail::sp_counted_impl_p<Moho::IRenTerrain>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<IRenTerrain>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::IRenTerrain>* SpCountedImplPDeletingDtorIRenTerrain(
        SpCountedImplStorage<moho::IRenTerrain>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x007FC1F0 (FUN_007FC1F0, boost::detail::sp_counted_impl_p<Moho::CD3DTextureBatcher>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<CD3DTextureBatcher>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::CD3DTextureBatcher>* SpCountedImplPDeletingDtorCD3DTextureBatcher(
        SpCountedImplStorage<moho::CD3DTextureBatcher>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x007FC210 (FUN_007FC210, boost::detail::sp_counted_impl_p<Moho::CD3DPrimBatcher>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<CD3DPrimBatcher>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::CD3DPrimBatcher>* SpCountedImplPDeletingDtorCD3DPrimBatcher(
        SpCountedImplStorage<moho::CD3DPrimBatcher>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x007FF6F0 (FUN_007FF6F0, boost::detail::sp_counted_impl_p<Moho::ID3DVertexSheet>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<ID3DVertexSheet>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::ID3DVertexSheet>* SpCountedImplPDeletingDtorID3DVertexSheet(
        SpCountedImplStorage<moho::ID3DVertexSheet>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008142E0 (FUN_008142E0, boost::detail::sp_counted_impl_p<Moho::ShoreCell>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<ShoreCell>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::ShoreCell>* SpCountedImplPDeletingDtorShoreCell(
        SpCountedImplStorage<moho::ShoreCell>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x00832A40 (FUN_00832A40, boost::detail::sp_counted_impl_p<Moho::MeshInstance>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<MeshInstance>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::MeshInstance>* SpCountedImplPDeletingDtorMeshInstance(
        SpCountedImplStorage<moho::MeshInstance>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x00884870 (FUN_00884870, boost::detail::sp_counted_impl_pd<_iobuf*,Moho::SFileStarCloser>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for one
     * `sp_counted_impl_pd<FILE*,SFileStarCloser>` lane.
     */
    [[nodiscard]] SpCountedImplStorage<void>* SpCountedImplPdDeletingDtorFileStarCloser(
        SpCountedImplStorage<void>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x00884F30 (FUN_00884F30, boost::detail::sp_counted_impl_p<Moho::LaunchInfoLoad>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<LaunchInfoLoad>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::LaunchInfoLoad>* SpCountedImplPDeletingDtorLaunchInfoLoad(
        SpCountedImplStorage<moho::LaunchInfoLoad>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x0089B910 (FUN_0089B910, boost::detail::sp_counted_impl_p<Moho::SSessionSaveData>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<SSessionSaveData>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::SSessionSaveData>* SpCountedImplPDeletingDtorSSessionSaveData(
        SpCountedImplStorage<moho::SSessionSaveData>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x0089BCC0 (FUN_0089BCC0, boost::detail::sp_counted_impl_p<Moho::UICommandGraph>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<UICommandGraph>`.
     */
    [[nodiscard]] SpCountedImplStorage<moho::UICommandGraph>* SpCountedImplPDeletingDtorUICommandGraph(
        SpCountedImplStorage<moho::UICommandGraph>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008E98C0 (FUN_008E98C0, boost::detail::sp_counted_impl_p<gpg::gal::TextureD3D9>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<TextureD3D9>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::TextureD3D9>* SpCountedImplPDeletingDtorTextureD3D9(
        SpCountedImplStorage<gpg::gal::TextureD3D9>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008E98E0 (FUN_008E98E0, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D9>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<RenderTargetD3D9>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::RenderTargetD3D9>* SpCountedImplPDeletingDtorRenderTargetD3D9(
        SpCountedImplStorage<gpg::gal::RenderTargetD3D9>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008E9900 (FUN_008E9900, boost::detail::sp_counted_impl_p<gpg::gal::CubeRenderTargetD3D9>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<CubeRenderTargetD3D9>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D9>* SpCountedImplPDeletingDtorCubeRenderTargetD3D9(
        SpCountedImplStorage<gpg::gal::CubeRenderTargetD3D9>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008E9920 (FUN_008E9920, boost::detail::sp_counted_impl_p<gpg::gal::DepthStencilTargetD3D9>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<DepthStencilTargetD3D9>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D9>* SpCountedImplPDeletingDtorDepthStencilTargetD3D9(
        SpCountedImplStorage<gpg::gal::DepthStencilTargetD3D9>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008E9940 (FUN_008E9940, boost::detail::sp_counted_impl_p<gpg::gal::VertexFormatD3D9>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<VertexFormatD3D9>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::VertexFormatD3D9>* SpCountedImplPDeletingDtorVertexFormatD3D9(
        SpCountedImplStorage<gpg::gal::VertexFormatD3D9>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008E9960 (FUN_008E9960, boost::detail::sp_counted_impl_p<gpg::gal::VertexBufferD3D9>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<VertexBufferD3D9>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::VertexBufferD3D9>* SpCountedImplPDeletingDtorVertexBufferD3D9(
        SpCountedImplStorage<gpg::gal::VertexBufferD3D9>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008E9980 (FUN_008E9980, boost::detail::sp_counted_impl_p<gpg::gal::IndexBufferD3D9>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<IndexBufferD3D9>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::IndexBufferD3D9>* SpCountedImplPDeletingDtorIndexBufferD3D9(
        SpCountedImplStorage<gpg::gal::IndexBufferD3D9>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008E99A0 (FUN_008E99A0, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D9>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<EffectD3D9>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::EffectD3D9>* SpCountedImplPDeletingDtorEffectD3D9(
        SpCountedImplStorage<gpg::gal::EffectD3D9>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008E9A80 (FUN_008E9A80, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D9>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<PipelineStateD3D9>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::PipelineStateD3D9>* SpCountedImplPDeletingDtorPipelineStateD3D9(
        SpCountedImplStorage<gpg::gal::PipelineStateD3D9>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x008F9FC0 (FUN_008F9FC0, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D10>::dtr)
     *
     * What it does:
     * Runs one scalar-deleting destructor thunk for `sp_counted_impl_p<EffectD3D10>`.
     */
    [[nodiscard]] SpCountedImplStorage<gpg::gal::EffectD3D10>* SpCountedImplPDeletingDtorEffectD3D10(
        SpCountedImplStorage<gpg::gal::EffectD3D10>* countedImpl,
        unsigned char deleteFlag
    ) noexcept;

    /**
     * Address: 0x007E6A10 (FUN_007E6A10, boost::detail::sp_counted_impl_pd<Moho::Mesh*,Moho::RefCountedCache<Moho::MeshKey,Moho::Mesh>::Deleter>::get_deleter)
     *
     * What it does:
     * Returns the mesh-cache deleter lane at `+0x10` when the requested
     * `type_info` matches the cache deleter type.
     */
    [[nodiscard]] void* SpCountedImplPdGetDeleterMeshRefCountedCache(
        SpCountedImplStorage<moho::Mesh>* countedImpl,
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x00884820 (FUN_00884820, boost::detail::sp_counted_impl_pd<_iobuf*,Moho::SFileStarCloser>::get_deleter)
     *
     * What it does:
     * Returns the file-closer deleter lane at `+0x10` when the requested
     * `type_info` matches `Moho::SFileStarCloser`.
     */
    [[nodiscard]] void* SpCountedImplPdGetDeleterSFileStarCloser(
        SpCountedImplStorage<void>* countedImpl,
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x004DE780 (FUN_004DE780, boost::detail::sp_counted_impl_p<Moho::AudioEngine>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullAudioEngine(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x0053A260 (FUN_0053A260, boost::detail::sp_counted_impl_p<Moho::RScmResource>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullRScmResource(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x0053B3F0 (FUN_0053B3F0, boost::detail::sp_counted_impl_p<Moho::RScaResource>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullRScaResource(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x00545370 (FUN_00545370, boost::detail::sp_counted_impl_p<Moho::LaunchInfoNew>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullLaunchInfoNew(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x005791E0 (FUN_005791E0, boost::detail::sp_counted_impl_p<Moho::CHeightField>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullCHeightField(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x005CD5B0 (FUN_005CD5B0, boost::detail::sp_counted_impl_p<Moho::CIntelGrid>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullCIntelGrid(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x0063E7A0 (FUN_0063E7A0, boost::detail::sp_counted_impl_p<Moho::CAniPose>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullCAniPose(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x00755FD0 (FUN_00755FD0, boost::detail::sp_counted_impl_p<Moho::ISimResources>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullISimResources(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x00756020 (FUN_00756020, boost::detail::sp_counted_impl_p<Moho::CDebugCanvas>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullCDebugCanvas(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x00756070 (FUN_00756070, boost::detail::sp_counted_impl_p<Moho::SParticleBuffer>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullSParticleBuffer(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x00765760 (FUN_00765760, boost::detail::sp_counted_impl_p<Moho::PathPreviewFinder>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullPathPreviewFinder(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x007BDC50 (FUN_007BDC50, boost::detail::sp_counted_impl_p<Moho::CGpgNetInterface>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullCGpgNetInterface(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x007E6580 (FUN_007E6580, boost::detail::sp_counted_impl_p<Moho::MeshMaterial>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullMeshMaterial(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x007E65D0 (FUN_007E65D0, boost::detail::sp_counted_impl_p<Moho::Mesh>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullMesh(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x007E69A0 (FUN_007E69A0, boost::detail::sp_counted_impl_p<Moho::MeshBatch>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullMeshBatch(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x007FBE70 (FUN_007FBE70, boost::detail::sp_counted_impl_p<Moho::IRenTerrain>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullIRenTerrain(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x007FC190 (FUN_007FC190, boost::detail::sp_counted_impl_p<Moho::CD3DTextureBatcher>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullCD3DTextureBatcher(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x007FC1E0 (FUN_007FC1E0, boost::detail::sp_counted_impl_p<Moho::CD3DPrimBatcher>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullCD3DPrimBatcher(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x007FF6E0 (FUN_007FF6E0, boost::detail::sp_counted_impl_p<Moho::ID3DVertexSheet>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullID3DVertexSheet(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x008142D0 (FUN_008142D0, boost::detail::sp_counted_impl_p<Moho::ShoreCell>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullShoreCell(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x00832A30 (FUN_00832A30, boost::detail::sp_counted_impl_p<Moho::MeshInstance>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullMeshInstance(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x00884F20 (FUN_00884F20, boost::detail::sp_counted_impl_p<Moho::LaunchInfoLoad>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullLaunchInfoLoad(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x0089B8A0 (FUN_0089B8A0, boost::detail::sp_counted_impl_p<Moho::SSessionSaveData>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullSSessionSaveData(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x0089BCB0 (FUN_0089BCB0, boost::detail::sp_counted_impl_p<Moho::UICommandGraph>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullUICommandGraph(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x008E89B0 (FUN_008E89B0, boost::detail::sp_counted_impl_p<gpg::gal::TextureD3D9>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullTextureD3D9(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x008E89E0 (FUN_008E89E0, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D9>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullRenderTargetD3D9(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x008E8A40 (FUN_008E8A40, boost::detail::sp_counted_impl_p<gpg::gal::DepthStencilTargetD3D9>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullDepthStencilTargetD3D9(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x008E8A70 (FUN_008E8A70, boost::detail::sp_counted_impl_p<gpg::gal::VertexFormatD3D9>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullVertexFormatD3D9(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x008E8AA0 (FUN_008E8AA0, boost::detail::sp_counted_impl_p<gpg::gal::VertexBufferD3D9>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullVertexBufferD3D9(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x008E8AD0 (FUN_008E8AD0, boost::detail::sp_counted_impl_p<gpg::gal::IndexBufferD3D9>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullIndexBufferD3D9(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x008E8B00 (FUN_008E8B00, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D9>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullEffectD3D9(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x008E8DA0 (FUN_008E8DA0, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D9>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullPipelineStateD3D9(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x008F8FE0 (FUN_008F8FE0, boost::detail::sp_counted_impl_p<gpg::gal::EffectD3D10>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullEffectD3D10(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x008F9040 (FUN_008F9040, boost::detail::sp_counted_impl_p<gpg::gal::RenderTargetD3D10>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullRenderTargetD3D10(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x008F93A0 (FUN_008F93A0, boost::detail::sp_counted_impl_p<gpg::gal::PipelineStateD3D10>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullPipelineStateD3D10(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x00923720 (FUN_00923720, boost::detail::sp_counted_impl_p<std::basic_stringstream<char, std::char_traits<char>, std::allocator<char>>>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullStdStringstreamChar(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x00931ED0 (FUN_00931ED0, boost::detail::sp_counted_impl_p<gpg::HaStar::ClusterCache::Impl>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullClusterCacheImpl(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x00941680 (FUN_00941680, boost::detail::sp_counted_impl_p<gpg::gal::EffectTechniqueD3D9>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullEffectTechniqueD3D9(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x009416B0 (FUN_009416B0, boost::detail::sp_counted_impl_p<gpg::gal::EffectVariableD3D9>::get_deleter)
     *
     * What it does:
     * Returns the null deleter-query lane for this `sp_counted_impl_p<T>` specialization.
     */
    [[nodiscard]] void* SpCountedImplPGetDeleterNullEffectVariableD3D9(
        detail::sp_typeinfo const& requestedType
    ) noexcept;

    /**
     * Address: 0x0094E0B0 (FUN_0094E0B0, boost::detail::sp_counted_impl_pd<char*, void (__cdecl*)(void*)>::get_deleter)
     *
     * What it does:
     * Returns the stored deleter lane when queried with
     * `typeid(void (__cdecl*)(void*))`; otherwise returns null.
     */
    [[nodiscard]] void* SpCountedImplPdGetDeleterCharPointerFunctionDeleter(
        SpCountedImplPdCharPointerStorage* countedImpl,
        detail::sp_typeinfo const& requestedType
    ) noexcept;

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
     * Address: 0x007DD160 (FUN_007DD160)
     *
     * What it does:
     * Copies one `(px,pi)` pair and rebinds ownership by shared-retaining the
     * incoming control lane and weak-releasing the previous control lane.
     */
    SharedCountPair* AssignSharedPairRetainWithWeakRelease(
        SharedCountPair* outPair,
        const SharedCountPair* sourcePair
    ) noexcept;

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
     * Address: 0x00539AA0 (FUN_00539AA0)
     * Address: 0x00539F70 (FUN_00539F70)
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

    /**
     * Address: 0x004DEA20 (FUN_004DEA20)
     * Address: 0x007846C0 (FUN_007846C0)
     * Address: 0x00784800 (FUN_00784800)
     *
     * What it does:
     * Uninitialized-copies one shared-pair range `[sourceBegin, sourceEnd)` into
     * destination lanes starting at `destinationBegin`, retaining the copied
     * control blocks and returning one-past the final destination slot.
     */
    [[nodiscard]] SharedCountPair* UninitializedCopySharedPairRangeRetain(
        SharedCountPair* destinationBegin,
        const SharedCountPair* sourceBegin,
        const SharedCountPair* const sourceEnd
    ) noexcept;

    /**
     * Address: 0x0075FF10 (FUN_0075FF10)
     * Address: 0x00760310 (FUN_00760310)
     * Address: 0x007568D0 (FUN_007568D0)
     *
     * What it does:
     * Uninitialized-copies one 12-byte `(lane0,lane1,pi)` range
     * `[sourceBegin, sourceEnd)` into destination lanes and retains each copied
     * shared control lane.
     */
    [[nodiscard]] SharedControlTriplet* UninitializedCopySharedControlTripletRangeRetain(
        SharedControlTriplet* destinationBegin,
        const SharedControlTriplet* sourceBegin,
        const SharedControlTriplet* const sourceEnd
    ) noexcept;

    /**
     * Address: 0x00755C50 (FUN_00755C50)
     *
     * What it does:
     * Copy-assigns one 12-byte `(lane0,lane1,pi)` range into initialized
     * destination slots, retaining incoming controls and releasing previously
     * bound controls when owners differ.
     */
    [[nodiscard]] SharedControlTriplet* CopyAssignSharedControlTripletRangeRetain(
        SharedControlTriplet* destination,
        const SharedControlTriplet* sourceBegin,
        const SharedControlTriplet* sourceEnd
    ) noexcept;

    /**
     * Address: 0x0075FCA0 (FUN_0075FCA0)
     * Address: 0x0075FF30 (FUN_0075FF30)
     *
     * What it does:
     * Fill-assigns one shared-control triplet value over
     * `[destinationBegin, destinationEnd)`, retaining incoming controls and
     * releasing previously bound controls when owners differ.
     */
    [[nodiscard]] SharedControlTriplet* FillAssignSharedControlTripletRangeRetain(
        SharedControlTriplet* destinationBegin,
        SharedControlTriplet* destinationEnd,
        const SharedControlTriplet& value
    ) noexcept;

    /**
     * Address: 0x0075FFC0 (FUN_0075FFC0)
     * Address: 0x00760330 (FUN_00760330)
     *
     * What it does:
     * Copy-assigns one 12-byte `(lane0,lane1,pi)` range backward from
     * `[sourceBegin, sourceEnd)` into destination lanes ending at
     * `destinationEnd`, retaining incoming controls and releasing previously
     * bound controls when owners differ.
     */
    [[nodiscard]] SharedControlTriplet* CopyAssignSharedControlTripletRangeBackwardRetain(
        SharedControlTriplet* destinationEnd,
        const SharedControlTriplet* sourceBegin,
        const SharedControlTriplet* sourceEnd
    ) noexcept;

    /**
     * Address: 0x00740270 (FUN_00740270)
     *
     * What it does:
     * Releases one shared control block and disposes/destroys the control
     * block on the final strong and weak transitions.
     */
    void ReleaseSharedCount(detail::sp_counted_base* control) noexcept;

    /**
     * Address: 0x00857630 (FUN_00857630)
     *
     * What it does:
     * Releases one half-open range of shared-pair slots by releasing each
     * control block referenced from the pair lanes.
     */
    [[nodiscard]] SharedCountPair* ReleaseSharedCountRange(
        SharedCountPair* begin,
        SharedCountPair* end
    ) noexcept;

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
