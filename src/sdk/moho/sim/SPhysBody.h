#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/sim/SPhysConstants.h"
#include "wm3/Quaternion.h"
#include "wm3/Vector3.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * Address evidence:
   * - 0x00697450 (FUN_00697450, SPhysBodyTypeInfo::Init, size = 0x54)
   * - 0x006981B0 (FUN_006981B0, construct defaults)
   * - 0x00698A60 (FUN_00698A60, deserialize body)
   * - 0x00698BC0 (FUN_00698BC0, serialize body)
   */
  struct SPhysBody
  {
    static gpg::RType* sType;

    SPhysConstants* mConstants;       // +0x00
    float mMass;                      // +0x04
    Wm3::Vec3f mInvInertiaTensor;     // +0x08
    Wm3::Vec3f mCollisionOffset;      // +0x14
    Wm3::Vec3f mPos;                  // +0x20
    Wm3::Quaternionf mOrientation;    // +0x2C
    Wm3::Vec3f mVelocity;             // +0x3C
    Wm3::Vec3f mWorldImpulse;         // +0x48

    /**
     * Address: 0x00697E70 (FUN_00697E70, Moho::SPhysBody::GetImpulse)
     *
     * What it does:
     * Projects world impulse into body-axis space with inverse-inertia scaling,
     * then reconstructs the resulting world impulse vector.
     */
    Wm3::Vec3f* GetImpulse(Wm3::Vec3f* out) const;
  };

  static_assert(offsetof(SPhysBody, mConstants) == 0x00, "SPhysBody::mConstants offset must be 0x00");
  static_assert(offsetof(SPhysBody, mMass) == 0x04, "SPhysBody::mMass offset must be 0x04");
  static_assert(offsetof(SPhysBody, mInvInertiaTensor) == 0x08, "SPhysBody::mInvInertiaTensor offset must be 0x08");
  static_assert(offsetof(SPhysBody, mCollisionOffset) == 0x14, "SPhysBody::mCollisionOffset offset must be 0x14");
  static_assert(offsetof(SPhysBody, mPos) == 0x20, "SPhysBody::mPos offset must be 0x20");
  static_assert(offsetof(SPhysBody, mOrientation) == 0x2C, "SPhysBody::mOrientation offset must be 0x2C");
  static_assert(offsetof(SPhysBody, mVelocity) == 0x3C, "SPhysBody::mVelocity offset must be 0x3C");
  static_assert(offsetof(SPhysBody, mWorldImpulse) == 0x48, "SPhysBody::mWorldImpulse offset must be 0x48");
  static_assert(sizeof(SPhysBody) == 0x54, "SPhysBody size must be 0x54");

  class SPhysBodyTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006973F0 (FUN_006973F0, Moho::SPhysBodyTypeInfo::SPhysBodyTypeInfo)
     */
    SPhysBodyTypeInfo();

    /**
     * Address: 0x00697480 (FUN_00697480, Moho::SPhysBodyTypeInfo::dtr)
     */
    ~SPhysBodyTypeInfo() override;

    /**
     * Address: 0x00697470 (FUN_00697470, Moho::SPhysBodyTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00697450 (FUN_00697450, Moho::SPhysBodyTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(SPhysBodyTypeInfo) == 0x64, "SPhysBodyTypeInfo size must be 0x64");

  class SPhysBodySerializer
  {
  public:
    /**
     * Address: 0x006982A0 (FUN_006982A0, Moho::SPhysBodySerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006982B0 (FUN_006982B0, Moho::SPhysBodySerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006982C0 (FUN_006982C0, serializer registration lane)
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(SPhysBodySerializer, mHelperNext) == 0x04, "SPhysBodySerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(SPhysBodySerializer, mHelperPrev) == 0x08, "SPhysBodySerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(SPhysBodySerializer, mDeserialize) == 0x0C,
    "SPhysBodySerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(offsetof(SPhysBodySerializer, mSerialize) == 0x10, "SPhysBodySerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(SPhysBodySerializer) == 0x14, "SPhysBodySerializer size must be 0x14");

  class SPhysBodySaveConstruct
  {
  public:
    /**
     * Address: 0x00698040 (FUN_00698040, save-construct registration lane)
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(SPhysBodySaveConstruct, mHelperNext) == 0x04,
    "SPhysBodySaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SPhysBodySaveConstruct, mHelperPrev) == 0x08,
    "SPhysBodySaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SPhysBodySaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "SPhysBodySaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(SPhysBodySaveConstruct) == 0x10, "SPhysBodySaveConstruct size must be 0x10");

  class SPhysBodyConstruct
  {
  public:
    /**
     * Address: 0x006981B0 (FUN_006981B0, construct registration lane)
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(SPhysBodyConstruct, mHelperNext) == 0x04,
    "SPhysBodyConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SPhysBodyConstruct, mHelperPrev) == 0x08,
    "SPhysBodyConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SPhysBodyConstruct, mConstructCallback) == 0x0C,
    "SPhysBodyConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SPhysBodyConstruct, mDeleteCallback) == 0x10,
    "SPhysBodyConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(SPhysBodyConstruct) == 0x14, "SPhysBodyConstruct size must be 0x14");

  /**
   * Address: 0x00BFD2D0 (FUN_00BFD2D0, cleanup_SPhysBodyTypeInfo)
   */
  void cleanup_SPhysBodyTypeInfo();

  /**
   * Address: 0x00BFD330 (FUN_00BFD330, cleanup_SPhysBodySaveConstruct)
   */
  gpg::SerHelperBase* cleanup_SPhysBodySaveConstruct();

  /**
   * Address: 0x00BFD360 (FUN_00BFD360, cleanup_SPhysBodyConstruct)
   */
  gpg::SerHelperBase* cleanup_SPhysBodyConstruct();

  /**
   * Address: 0x00BFD390 (FUN_00BFD390, cleanup_SPhysBodySerializer)
   */
  void cleanup_SPhysBodySerializer();

  /**
   * Address: 0x00BD5E80 (FUN_00BD5E80, register_SPhysBodyTypeInfo)
   */
  void register_SPhysBodyTypeInfo();

  /**
   * Address: 0x00BD5EA0 (FUN_00BD5EA0, register_SPhysBodySaveConstruct)
   */
  int register_SPhysBodySaveConstruct();

  /**
   * Address: 0x00BD5ED0 (FUN_00BD5ED0, register_SPhysBodyConstruct)
   */
  int register_SPhysBodyConstruct();

  /**
   * Address: 0x00BD5F10 (FUN_00BD5F10, register_SPhysBodySerializer)
   */
  void register_SPhysBodySerializer();
} // namespace moho
