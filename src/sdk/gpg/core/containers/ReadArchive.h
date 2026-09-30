// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a reconstruction target; keep address docs in sync with recovered bodies.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <iosfwd>

#include "ArchiveSerialization.h"
#include "boost/shared_ptr.h"
#include "legacy/containers/Vector.h"
#include "moho/path/PathTables.h"  // PathQueue::Impl is nested, so the enclosing class must be complete

namespace msvc8
{
  struct string;
}

namespace LuaPlus
{
  class LuaState;
}

struct lua_State;
struct Table;
struct TString;
struct LClosure;
struct Udata;
struct Proto;
struct UpVal;

namespace moho
{
  template <class TEvent>
  class Listener;
  template <class TEvent>
  class ManyToOneListener;
  template <class TEvent>
  class Broadcaster;

  enum EFormationdStatus : std::int32_t;
  enum EAiNavigatorEvent : std::int32_t;
  enum EAiAttackerEvent : std::int32_t;
  enum EAiTransportEvent : std::int32_t;
  enum ECommandEvent : std::int32_t;
  enum EUnitCommandQueueStatus : std::int32_t;
  enum ECollisionBeamEvent : std::int32_t;
  enum EProjectileImpactEvent : std::int32_t;
  enum EAiResult : std::int32_t;
  class HSound;
  class CSndParams;
  struct REntityBlueprint;
  struct RMeshBlueprint;
  struct RUnitBlueprint;
  class RRuleGameRules;
  class ReconBlip;
  class IUnit;
  class CAniPose;
  class CAniActor;
  class IAniManipulator;
  class PathTables;
  class IPathTraveler;
  class Shield;
  class CArmyStats;
  class CArmyStatItem;
  class CAcquireTargetTask;
  class CAiAttackerImpl;
  class CTask;
  class CTaskThread;
  class CSquad;
  struct STaskEventLinkage;
  class StatItem;
  class CEconomy;
  class CEconomyEvent;
  class CCommandDb;
  class CUnitCommand;
  class CDecalBuffer;
  class CDecalHandle;
  class CParticleTexture;
  class CEntityDb;
  class Entity;
  class COGrid;
  class CInfluenceMap;
  class STIMap;
  class PathQueue;
  class CEconStorage;
  class CTextureScroller;
  class CAiBrain;
  class CAiPathFinder;
  class CAiPathNavigator;
  class CAiPathSpline;
  class CAiPersonality;
  class CUnitCommandQueue;
  class CUnitMotion;
  class CFireWeaponTask;
  class CRandomStream;
  struct RProjectileBlueprint;
  class IEffect;
  class IEffectManager;
  class IAiAttacker;
  class IAiBuilder;
  class IAiCommandDispatch;
  class IAiFormationDB;
  class IAiNavigator;
  class IAiReconDB;
  class IAiSiloBuild;
  class IAiTransport;
  class IFormationInstance;
  class ISoundManager;
  class Motor;
  class CColPrimitiveBase;
  class IAiSteering;
  class CCommandTask;
  class CIntel;
  class CIntelPosHandle;
  class CTaskStage;
  struct CPathPoint;
  struct CEconRequest;
  struct PositionHistory;
  struct REmitterBlueprint;
  struct RTrailBlueprint;
  struct RUnitBlueprintWeapon;
  struct SPhysConstants;
  struct SPhysBody;
  struct SNavPath;
  class Sim;
  class SimArmy;
  class CPlatoon;
  class Unit;
  class UnitWeapon;
  class EntitySetBase;
}

namespace gpg
{
  class RIndexed;
  class RRef;
  class RType;

  /**
   * VFTABLE: 0x00D48D14
   * COL:  0x00E53B84
   */
  class ReadArchive
  {
  public:
    /**
     * Address: 0x00952B60 (FUN_00952B60, ??0ReadArchive@gpg@@QAE@XZ)
     *
     * What it does:
     * Initializes tracked-type and tracked-pointer tables to empty state and
     * resets the null tracked-pointer sentinel to the reserved ownership lane.
     */
    ReadArchive();

    /**
     * Address: 0x00953700 (FUN_00953700)
     * Demangled: gpg::ReadArchive::dtr
     *
     * What it does:
     * Destroys read-archive bookkeeping state.
     */
    virtual ~ReadArchive();

    /**
     * Address: 0x00A82547
     * Slot: 1
     * Demangled: _purecall
     */
    virtual void ReadBytes(char*, size_t) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 2
     * Demangled: _purecall
     */
    virtual void ReadString(msvc8::string*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 3
     * Demangled: _purecall
     */
    virtual void ReadFloat(float*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 4
     * Demangled: _purecall
     */
    virtual void ReadUInt64(unsigned __int64*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 5
     * Demangled: _purecall
     */
    virtual void ReadInt64(__int64*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 6
     * Demangled: _purecall
     */
    virtual void ReadULong(unsigned long*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 7
     * Demangled: _purecall
     */
    virtual void ReadLong(long*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 8
     * Demangled: _purecall
     */
    virtual void ReadUInt(unsigned int*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 9
     * Demangled: _purecall
     */
    virtual void ReadInt(int*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 10
     * Demangled: _purecall
     */
    virtual void ReadUShort(unsigned short*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 11
     * Demangled: _purecall
     */
    virtual void ReadShort(short*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 12
     * Demangled: _purecall
     */
    virtual void ReadUByte(unsigned __int8*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 13
     * Demangled: _purecall
     */
    virtual void ReadByte(__int8*) = 0;

    /**
     * Address: 0x00A82547
     * Slot: 14
     * Demangled: _purecall
     */
    virtual void ReadBool(bool*) = 0;

    /**
     * Address: 0x00952BD0 (FUN_00952BD0)
     * Slot: 15
     * Demangled: public: virtual void __thiscall gpg::ReadArchive::EndSection(bool)
     *
     * What it does:
     * Releases tracked pointer/type-handle section state.
     */
    virtual void EndSection(bool);

    /**
     * Address: 0x00A82547
     * Slot: 16
     * Demangled: _purecall
     */
    virtual int NextMarker() = 0;

    /**
     * Address: 0x00953DA0 (FUN_00953DA0)
     * Demangled: public: void __thiscall gpg::ReadArchive::Read(class gpg::RType const *,void *,class gpg::RRef const
     * &)
     *
     * What it does:
     * Reads one typed object payload using reflection serializer callbacks.
     */
    void Read(const gpg::RType* type, void* object, const gpg::RRef& ownerRef);

    /**
     * Reads one tracked pointer as a `T*`; defined, with the addresses of
     * its instantiations, after `RType` in gpg/core/reflection/Reflection.h.
     */
    template <class T>
    ReadArchive* ReadPointer(T** outValue, const gpg::RRef* ownerRef);

    /**
     * `ReadPointer` for a pointer whose object the reader takes ownership of.
     */
    template <class T>
    ReadArchive* ReadPointerOwned(T** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x0065A810 (FUN_0065A810, gpg::ReadArchive::ReadPointer_CParticleTexture)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> SHARED` ownership
     * transition, and upcasts the pointee to `moho::CParticleTexture`.
     */
    ReadArchive* ReadPointer_CParticleTexture(moho::CParticleTexture** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00763C80 (FUN_00763C80, gpg::ReadArchive::ReadPointer_Listener_NavPath)
     *
     * What it does:
     * Reads one tracked pointer lane and upcasts it to
     * `moho::Listener<const moho::SNavPath&>`, throwing
     * `SerializationError` on pointee-type mismatch.
     */
    ReadArchive* ReadPointer_Listener_NavPath(
      moho::Listener<const moho::SNavPath&>** outValue, const gpg::RRef* ownerRef
    );

    /**
     * Address: 0x006EB9E0 (FUN_006EB9E0, gpg::ReadArchive::ReadPointerWeak_IFormationInstance)
     *
     * What it does:
     * Reads one tracked pointer lane, enforces `UNOWNED -> SHARED` ownership
     * transition, and upcasts the pointee to `moho::IFormationInstance`.
     */
    ReadArchive* ReadPointerWeak_IFormationInstance(moho::IFormationInstance** outValue, const gpg::RRef* ownerRef);

    /**
     * Address: 0x00953B30 (FUN_00953B30)
     * Demangled: public: class gpg::ReadArchive & __thiscall gpg::ReadArchive::TrackPointer(class gpg::RRef const &)
     *
     * What it does:
     * Appends one pre-tracked pointer entry for an already-constructed object.
     */
    ReadArchive& TrackPointer(const gpg::RRef& objectRef);

    /**
     * Address: 0x00952F10 (FUN_00952F10)
     * Demangled: gpg::ReadArchive::ReadTypeHandle
     *
     * What it does:
     * Reads or resolves reflected type/version handle from archive token stream.
     */
    TypeHandle ReadTypeHandle();

  protected:
    msvc8::vector<TypeHandle> mTypeHandles;
    msvc8::vector<TrackedPointerInfo> mTrackedPtrs;
    TrackedPointerInfo mNullTrackedPointer;

    friend TrackedPointerInfo& ReadRawPointer(ReadArchive* archive, const RRef& ownerRef);
    friend void
    ReadPointerShared_LaunchInfoBase(boost::SharedPtrRaw<moho::LaunchInfoBase>& outPointer, ReadArchive* archive, const RRef& ownerRef);
    friend void ReadPointerShared_SSessionSaveData(
      boost::SharedPtrRaw<moho::SSessionSaveData>& outPointer, ReadArchive* archive, const RRef& ownerRef
    );
    friend void
    ReadPointerShared_CAniPose(boost::SharedPtrRaw<moho::CAniPose>& outPointer, ReadArchive* archive, const RRef& ownerRef);
    friend void
    ReadPointerShared_CAniSkel(boost::SharedPtrRaw<moho::CAniSkel>& outPointer, ReadArchive* archive, const RRef& ownerRef);
    friend void ReadPointerShared_Stats_StatItem(
      boost::SharedPtrRaw<moho::Stats<moho::StatItem>>& outPointer, ReadArchive* archive, const RRef& ownerRef
    );
    friend void ReadPointerShared_ISimResources(
      boost::SharedPtrRaw<moho::ISimResources>& outPointer, ReadArchive* archive, const RRef& ownerRef
    );
    friend void
    ReadPointerShared_CIntelGrid(boost::SharedPtrRaw<moho::CIntelGrid>& outPointer, ReadArchive* archive, const RRef& ownerRef);
    friend void ReadPointerShared_RScaResource(
      boost::SharedPtrRaw<moho::RScaResource>& outPointer, ReadArchive* archive, const RRef& ownerRef
    );
    friend void ReadPointerShared_RScmResource(
      boost::SharedPtrRaw<moho::RScmResource>& outPointer, ReadArchive* archive, const RRef& ownerRef
    );
    friend void
    ReadPointerShared_STrigger(boost::SharedPtrRaw<moho::STrigger>& outPointer, ReadArchive* archive, const RRef& ownerRef);
  };
  static_assert(sizeof(ReadArchive) == 0x38, "ReadArchive size must be 0x38");

  /**
   * Address: 0x007638D0 (FUN_007638D0)
   *
   * What it does:
   * Repeatedly reads `Listener<const SNavPath&>` pointers from `archive` and
   * relinks each non-null listener node into the intrusive ring immediately
   * before `listHead`.
   */
  moho::Listener<const moho::SNavPath&>* ReadAndLinkNavPathListeners(
    ReadArchive* archive,
    moho::Broadcaster<const moho::SNavPath&>* listHead,
    int version,
    const gpg::RRef* ownerRef
  );

  /**
   * Address: 0x009048B0 (FUN_009048B0)
   * Mangled: ?CreateBinaryReadArchive@gpg@@YAPAVReadArchive@1@ABV?$shared_ptr@U_iobuf@@@boost@@@Z
   *
   * What it does:
   * Creates one file-backed concrete `ReadArchive` for save/load serializers.
   */
  ReadArchive* CreateBinaryReadArchive(const boost::shared_ptr<std::FILE>& file);

  /**
   * Address: 0x00939800 (FUN_00939800, ?CreateTextReadArchive@gpg@@YAPAVReadArchive@1@ABV?$shared_ptr@Vistream@std@@@boost@@@Z)
   *
   * What it does:
   * Creates one stream-backed concrete `ReadArchive` (TextReadArchive) for
   * the Lua-facing `serialize.fromstring` text-deserialization path.
   */
  ReadArchive* CreateTextReadArchive(const boost::shared_ptr<std::istream>& stream);
} // namespace gpg
