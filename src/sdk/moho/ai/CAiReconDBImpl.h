// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/Entity.h"
#include "wm3/Box3.h"
#include "wm3/Vector3.h"
#include <moho/unit/core/Unit.h>

namespace moho
{
	class ReconBlip;
	class CIntelGrid;
} // forward decl

namespace moho {
  /**
   * VFTABLE: 0x00E1D8D4
   * COL:  0x00E74388
   */
  class CAiReconDBImpl
  {
  public:
    /**
     * Address: 0x005C2300
     * Slot: 0
     * Demangled: sub_5C2300
     */
    virtual void sub_5C2300() = 0;

    /**
     * Address: 0x005C0C40
     * Slot: 1
     * Demangled: public: virtual void __thiscall moho::CAiReconDBImpl::ReconTick(int)
     */
    virtual void ReconTick(int) = 0;

    /**
     * Address: 0x005C14E0
     * Slot: 2
     * Demangled: public: virtual void __thiscall moho::CAiReconDBImpl::ReconRefresh(void)
     */
    virtual void ReconRefresh() = 0;

    /**
     * Address: 0x005C18A0
     * Slot: 3
     * Demangled: public: virtual int __thiscall moho::CAiReconDBImpl::ReconCanDetect(class gpg::Rect2<int> const near &,float,int)const
     */
    virtual int ReconCanDetect(moho::Rect2<int> const &, float, int) const = 0;

    /**
     * Address: 0x005C1850
     * Slot: 4
     * Demangled: public: virtual int __thiscall moho::CAiReconDBImpl::ReconCanDetect(class Wm3::Vector3<float> const near &,int)const
     */
    virtual int ReconCanDetect(Wm3::Vec3f const &, int) const = 0;

    /**
     * Address: 0x005C1720
     * Slot: 5
     * Demangled: public: virtual void __thiscall moho::CAiReconDBImpl::ReconGetBlips(class Wm3::Box3<float> const near &,class gpg::fastvector<class moho::Entity near *> near *)const
     */
    virtual void ReconGetBlips(Wm3::Box3<float> const &, gpg::core::FastVector<Entity *> *) const = 0;

    /**
     * Address: 0x005C1640
     * Slot: 6
     * Demangled: public: virtual void __thiscall moho::CAiReconDBImpl::ReconGetBlips(class Wm3::Vector3<float> const near &,float,class gpg::fastvector<class moho::Entity near *> near *)const
     */
    virtual void ReconGetBlips(Wm3::Vec3f const &, float, gpg::core::FastVector<Entity *> *) const = 0;

    /**
     * Address: 0x005C1590
     * Slot: 7
     * Demangled: public: virtual class std::vector<class moho::ReconBlip near *,class std::allocator<class moho::ReconBlip near *>> const near & __thiscall moho::CAiReconDBImpl::ReconGetBlips(void)const
     */
    virtual msvc8::vector<ReconBlip*> const & ReconGetBlips() const = 0;

    /**
     * Address: 0x005C1A10
     * Slot: 8
     * Demangled: public: virtual class boost::shared_ptr<class moho::CIntelGrid> __thiscall moho::CAiReconDBImpl::ReconGetVisionGrid(void)const
     */
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetVisionGrid() const = 0;

    /**
     * Address: 0x005C1A40
     * Slot: 9
     * Demangled: public: virtual class boost::shared_ptr<class moho::CIntelGrid> __thiscall moho::CAiReconDBImpl::ReconGetWaterGrid(void)const
     */
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetWaterGrid() const = 0;

    /**
     * Address: 0x005C1A70
     * Slot: 10
     * Demangled: public: virtual class boost::shared_ptr<class moho::CIntelGrid> __thiscall moho::CAiReconDBImpl::ReconGetRadarGrid(void)const
     */
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetRadarGrid() const = 0;

    /**
     * Address: 0x005C1AA0
     * Slot: 11
     * Demangled: public: virtual class boost::shared_ptr<class moho::CIntelGrid> __thiscall moho::CAiReconDBImpl::ReconGetSonarGrid(void)const
     */
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetSonarGrid() const = 0;

    /**
     * Address: 0x005C1AD0
     * Slot: 12
     * Demangled: public: virtual class boost::shared_ptr<class moho::CIntelGrid> __thiscall moho::CAiReconDBImpl::ReconGetOmniGrid(void)const
     */
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetOmniGrid() const = 0;

    /**
     * Address: 0x005C1B00
     * Slot: 13
     * Demangled: public: virtual class boost::shared_ptr<class moho::CIntelGrid> __thiscall moho::CAiReconDBImpl::ReconGetRCIGrid(void)const
     */
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetRCIGrid() const = 0;

    /**
     * Address: 0x005C1B30
     * Slot: 14
     * Demangled: public: virtual class boost::shared_ptr<class moho::CIntelGrid> __thiscall moho::CAiReconDBImpl::ReconGetSCIGrid(void)const
     */
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetSCIGrid() const = 0;

    /**
     * Address: 0x005C1B60
     * Slot: 15
     * Demangled: public: virtual class boost::shared_ptr<class moho::CIntelGrid> __thiscall moho::CAiReconDBImpl::ReconGetVCIGrid(void)const
     */
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetVCIGrid() const = 0;

    /**
     * Address: 0x005C08F0
     * Slot: 16
     * Demangled: public: virtual void __thiscall moho::CAiReconDBImpl::ReconSetFogOfWar(bool)
     */
    virtual void ReconSetFogOfWar(bool) = 0;

    /**
     * Address: 0x005C0910
     * Slot: 17
     * Demangled: public: virtual bool __thiscall moho::CAiReconDBImpl::ReconGetFogOfWar(void)const
     */
    virtual bool ReconGetFogOfWar() const = 0;

    /**
     * Address: 0x005C29C0
     * Slot: 18
     * Demangled: nullsub_1553
     */
    virtual void nullsub_1553() = 0;

    /**
     * Address: 0x005C15A0
     * Slot: 19
     * Demangled: public: virtual class moho::ReconBlip near * __thiscall moho::CAiReconDBImpl::ReconGetBlip(class moho::Unit near *)const
     */
    virtual ReconBlip * ReconGetBlip(Unit *) const = 0;

    /**
     * Address: 0x005C20C0
     * Slot: 20
     * Demangled: public: virtual class moho::EntitySetTemplate<class moho::Entity> __thiscall moho::CAiReconDBImpl::ReconGetJamingBlips(class moho::Unit near *)
     */
    virtual EntitySetTemplate<Entity> ReconGetJamingBlips(Unit *) = 0;

    /**
     * Address: 0x005C05A0
     * Slot: 21
     * Demangled: public: virtual void __thiscall moho::CAiReconDBImpl::ReconFlushBlipsInRect(class gpg::Rect2<int> const near &)
     */
    virtual void ReconFlushBlipsInRect(moho::Rect2<int> const &) = 0;
  };
} 
