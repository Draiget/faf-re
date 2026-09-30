#pragma once

#include <cstddef>

#include "boost/mutex.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/math/VMatrix4.h"
#include "moho/math/Vector2f.h"
#include "moho/math/Vector3f.h"
#include "moho/math/Vector4f.h"
#include "Wm3AxisAlignedBox3.h"
#include "Wm3Quaternion.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

namespace moho
{
  class CRandomStream;

  using Vector2i = Wm3::Vector2i;
  using Vector3i = Wm3::Vector3i;
  using Quaternionf = Wm3::Quaternionf;

  // Process-wide mutex used by math/random helper lanes.
  extern boost::mutex math_GlobalRandomMutex;
  // Process-wide random stream used by math helper lanes.
  extern CRandomStream math_GlobalRandomStream;

  /**
   * Address: 0x007A6460 (FUN_007A6460, sub_7A6460)
   *
   * What it does:
   * Returns one process-global random sample in `[0, scale)` under
   * `math_GlobalRandomMutex`.
   */
  [[nodiscard]] double MathGlobalRandomUnitScaled(float scale);

  /**
   * Address: 0x00514BC0 (FUN_00514BC0, func_RandomFloatSafe)
   *
   * What it does:
   * Returns one process-global random sample in `[0, 1)` under
   * `math_GlobalRandomMutex`.
   */
  [[nodiscard]] double MathGlobalRandomUnitSafe();

  /**
   * Address: 0x007A64B0 (FUN_007A64B0, func_DRand)
   *
   * What it does:
   * Returns one process-global random sample in `[minValue, maxValue)` under
   * `math_GlobalRandomMutex`.
   */
  [[nodiscard]] double MathGlobalRandomRange(float minValue, float maxValue);

  struct VEulers3
  {
    /**
     * What it does:
     * Reads `r`, `p`, `y`. Inlined into `gpg::SerSaveLoadHelper<VEulers3>::Deserialize` 0x004EC100.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * What it does:
     * Writes `r`, `p`, `y`. Inlined into `gpg::SerSaveLoadHelper<VEulers3>::Serialize` 0x004EC140.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    float r; // +0x00
    float p; // +0x04
    float y; // +0x08
  };

  /**
   * Address: 0x004EB590 (FUN_004EB590, func_EulerToQuaternion)
   *
   * What it does:
   * Converts Euler roll/pitch/yaw lanes into one quaternion orientation.
   */
  [[nodiscard]] Wm3::Quaternionf EulerToQuaternion(const VEulers3& orientation);

  struct VAxes3
  {
    /**
     * Address: 0x004EE100 (FUN_004EE100)
     *
     * What it does:
     * Saves this object's members.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

    /**
     * Address: 0x004EE050 (FUN_004EE050)
     *
     * What it does:
     * Loads this object's members.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    VAxes3() = default;

    /**
     * Address: 0x004EC590 (FUN_004EC590, Moho::VAxes3::VAxes3)
     *
     * What it does:
     * Builds one orthonormal basis matrix from quaternion lanes.
     */
    explicit VAxes3(const Wm3::Quaternionf& orientation);

    /**
     * Address: 0x004EC6D0 (FUN_004EC6D0, ??0VAxes3@Moho@@QAE@ABVVEulers3@1@@Z)
     *
     * What it does:
     * Converts roll/pitch/yaw Euler lanes to quaternion and then expands that
     * quaternion into one orthonormal basis matrix.
     */
    explicit VAxes3(const VEulers3& orientation);

    /**
     * Address: 0x004EC720 (FUN_004EC720, ?OrthoNormalize@VAxes3@Moho@@QAEXXZ)
     * Mangled: ?OrthoNormalize@VAxes3@Moho@@QAEXXZ
     *
     * What it does:
     * Rebuilds one orthonormal basis by deriving `vX` from `vY x vZ`, then
     * deriving `vZ` from `vX x vY`, and finally deriving `vY` from `vZ x vX`.
     */
    void OrthoNormalize();

    /**
     * Address: 0x004EC850 (FUN_004EC850, ?IsNormal@VAxes3@Moho@@QBE_NXZ)
     * Mangled: ?IsNormal@VAxes3@Moho@@QBE_NXZ
     *
     * What it does:
     * Verifies all basis lanes are unit-length and confirms `vX` matches the
     * reconstructed `vZ x vY` lane within epsilon.
     */
    [[nodiscard]] bool IsNormal() const;

    Wm3::Vector3f vX; // +0x00
    Wm3::Vector3f vY; // +0x0C
    Wm3::Vector3f vZ; // +0x18
  };

  /**
   * Address: 0x004ECB60 (FUN_004ECB60, ??$Identity@VVAxes3@Moho@@@Moho@@YAABVVAxes3@0@XZ)
   *
   * What it does:
   * Returns a reference to the lazy-initialized identity `VAxes3` basis
   * `(1,0,0)/(0,1,0)/(0,0,1)`. The first call latches an init-once guard so
   * subsequent calls skip the matrix write.
   */
  template <typename T>
  [[nodiscard]] const T& Identity();

  template <>
  [[nodiscard]] const VAxes3& Identity<VAxes3>();

  /**
   * Address: 0x004ED000 (FUN_004ED000, ?ToString@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABVVAxes3@1@@Z)
   * Mangled: ?ToString@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@ABVVAxes3@1@@Z
   *
   * What it does:
   * Formats one `VAxes3` basis as `X=(...) Y=(...) Z=(...)` by reusing the
   * vector-lane string formatter.
   */
  [[nodiscard]] msvc8::string ToString(const VAxes3& value);



  class AxisAlignedBox3fTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004E9FB0 (FUN_004E9FB0, Moho::AxisAlignedBox3fTypeInfo::AxisAlignedBox3fTypeInfo)
     */
    AxisAlignedBox3fTypeInfo();

    /**
     * Address: 0x004EA040 (FUN_004EA040, Moho::AxisAlignedBox3fTypeInfo::dtr)
     */
    ~AxisAlignedBox3fTypeInfo() override;

    /**
     * Address: 0x004EA030 (FUN_004EA030, Moho::AxisAlignedBox3fTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004EA010 (FUN_004EA010, Moho::AxisAlignedBox3fTypeInfo::Init)
     */
    void Init() override;
  };

  class Vector2iTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004EA200 (FUN_004EA200, Moho::Vector2iTypeInfo::Vector2iTypeInfo)
     */
    Vector2iTypeInfo();

    /**
     * Address: 0x004EA2B0 (FUN_004EA2B0, Moho::Vector2iTypeInfo::dtr)
     */
    ~Vector2iTypeInfo() override;

    /**
     * Address: 0x004EA2A0 (FUN_004EA2A0, Moho::Vector2iTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004EA260 (FUN_004EA260, Moho::Vector2iTypeInfo::Init)
     */
    void Init() override;
  };

  class Vector3iTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004EA4C0 (FUN_004EA4C0, Moho::Vector3iTypeInfo::Vector3iTypeInfo)
     */
    Vector3iTypeInfo();

    /**
     * Address: 0x004EA580 (FUN_004EA580, Moho::Vector3iTypeInfo::dtr)
     */
    ~Vector3iTypeInfo() override;

    /**
     * Address: 0x004EA570 (FUN_004EA570, Moho::Vector3iTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004EA520 (FUN_004EA520, Moho::Vector3iTypeInfo::Init)
     */
    void Init() override;
  };

  class Vector2fTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004EA7C0 (FUN_004EA7C0, Moho::Vector2fTypeInfo::Vector2fTypeInfo)
     */
    Vector2fTypeInfo();

    /**
     * Address: 0x004EA870 (FUN_004EA870, Moho::Vector2fTypeInfo::dtr)
     */
    ~Vector2fTypeInfo() override;

    /**
     * Address: 0x004EA860 (FUN_004EA860, Moho::Vector2fTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004EA820 (FUN_004EA820, Moho::Vector2fTypeInfo::Init)
     */
    void Init() override;
  };

  class Vector3fTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004EAA90 (FUN_004EAA90, Moho::Vector3fTypeInfo::Vector3fTypeInfo)
     */
    Vector3fTypeInfo();

    /**
     * Address: 0x004EAB50 (FUN_004EAB50, Moho::Vector3fTypeInfo::dtr)
     */
    ~Vector3fTypeInfo() override;

    /**
     * Address: 0x004EAB40 (FUN_004EAB40, Moho::Vector3fTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004EAAF0 (FUN_004EAAF0, Moho::Vector3fTypeInfo::Init)
     */
    void Init() override;
  };

  class Vector4fTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004EADC0 (FUN_004EADC0, Moho::Vector4fTypeInfo::Vector4fTypeInfo)
     */
    Vector4fTypeInfo();

    /**
     * Address: 0x004EAE90 (FUN_004EAE90, Moho::Vector4fTypeInfo::dtr)
     */
    ~Vector4fTypeInfo() override;

    /**
     * Address: 0x004EAE80 (FUN_004EAE80, Moho::Vector4fTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004EAE20 (FUN_004EAE20, Moho::Vector4fTypeInfo::Init)
     */
    void Init() override;
  };

  class QuaternionfTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004EB120 (FUN_004EB120, Moho::QuaternionfTypeInfo::QuaternionfTypeInfo)
     */
    QuaternionfTypeInfo();

    /**
     * Address: 0x004EB1F0 (FUN_004EB1F0, Moho::QuaternionfTypeInfo::dtr)
     */
    ~QuaternionfTypeInfo() override;

    /**
     * Address: 0x004EB1E0 (FUN_004EB1E0, Moho::QuaternionfTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004EB180 (FUN_004EB180, Moho::QuaternionfTypeInfo::Init)
     */
    void Init() override;
  };

  class VEulers3TypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004EBF50 (FUN_004EBF50, Moho::VEulers3TypeInfo::VEulers3TypeInfo)
     */
    VEulers3TypeInfo();

    /**
     * Address: 0x004EC020 (FUN_004EC020, Moho::VEulers3TypeInfo::dtr)
     */
    ~VEulers3TypeInfo() override;

    /**
     * Address: 0x004EC010 (FUN_004EC010, Moho::VEulers3TypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004EBFB0 (FUN_004EBFB0, Moho::VEulers3TypeInfo::Init)
     */
    void Init() override;
  };

  class VAxes3TypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004EC360 (FUN_004EC360, Moho::VAxes3TypeInfo::VAxes3TypeInfo)
     */
    VAxes3TypeInfo();

    /**
     * Address: 0x004EC410 (FUN_004EC410, Moho::VAxes3TypeInfo::dtr)
     */
    ~VAxes3TypeInfo() override;

    /**
     * Address: 0x004EC400 (FUN_004EC400, Moho::VAxes3TypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004EC3C0 (FUN_004EC3C0, Moho::VAxes3TypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * Address: 0x004ECBD0 (FUN_004ECBD0, Moho::VEC_LookAt)
   *
   * What it does:
   * Builds one orthonormal basis from a reference up vector and a forward
   * vector, using the binary's alternate right-axis lane when the cross
   * product collapses.
   */
  void VEC_LookAt(const Wm3::Vector3f& up, const Wm3::Vector3f& forward, VAxes3* axes);

  /**
   * Address: 0x0050B650 (FUN_0050B650, ?COORDS_LookAt@Moho@@YAXABV?$Vector3@M@Wm3@@PAVVAxes3@1@@Z)
   *
   * What it does:
   * Builds look-at axes using world-up `(0,1,0)` and the supplied forward
   * direction.
   */
  void COORDS_LookAt(const Wm3::Vector3f& forward, VAxes3* axes);

  /**
   * Address: 0x0050B680 (FUN_0050B680, ?COORDS_LookAtXZ@Moho@@YAXABV?$Vector3@M@Wm3@@PAVVAxes3@1@@Z)
   *
   * What it does:
   * Builds an XZ-plane-aligned basis from one direction vector without
   * normalizing the projected axes.
   */
  VAxes3* COORDS_LookAtXZ(VAxes3* outAxes, const Wm3::Vector3f& direction);

  class VMatrix4TypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004F00E0 (FUN_004F00E0, Moho::VMatrix4TypeInfo::VMatrix4TypeInfo)
     */
    VMatrix4TypeInfo();

    /**
     * Address: 0x004F0170 (FUN_004F0170, Moho::VMatrix4TypeInfo::dtr)
     */
    ~VMatrix4TypeInfo() override;

    /**
     * Address: 0x004F0160 (FUN_004F0160, Moho::VMatrix4TypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004F0140 (FUN_004F0140, Moho::VMatrix4TypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * Address: 0x00BC6C40 (FUN_00BC6C40, register_AxisAlignedBox3fTypeInfo)
   */
  void register_AxisAlignedBox3fTypeInfo();

  /**
   * Address: 0x00BC6CA0 (FUN_00BC6CA0, register_Vector2iTypeInfo)
   */
  void register_Vector2iTypeInfo();

  /**
   * Address: 0x00BC6D00 (FUN_00BC6D00, register_Vector3iTypeInfo)
   */
  void register_Vector3iTypeInfo();

  /**
   * Address: 0x00BC6D60 (FUN_00BC6D60, register_Vector2fTypeInfo)
   */
  void register_Vector2fTypeInfo();

  /**
   * Address: 0x00BC6DC0 (FUN_00BC6DC0, register_Vector3fTypeInfo)
   */
  void register_Vector3fTypeInfo();

  /**
   * Address: 0x00BC6E20 (FUN_00BC6E20, register_Vector4fTypeInfo)
   */
  void register_Vector4fTypeInfo();

  /**
   * Address: 0x00BC6E80 (FUN_00BC6E80, register_QuaternionfTypeInfo)
   */
  void register_QuaternionfTypeInfo();

  /**
   * Address: 0x00BC6EE0 (FUN_00BC6EE0, register_VEulers3TypeInfo)
   */
  void register_VEulers3TypeInfo();

  /**
   * Address: 0x00BC6F40 (FUN_00BC6F40, register_VAxes3TypeInfo)
   */
  void register_VAxes3TypeInfo();

  /**
   * Address: 0x00BC7000 (FUN_00BC7000, register_VMatrix4NaN)
   */
  void register_VMatrix4NaN();

  /**
   * Address: 0x00BC7090 (FUN_00BC7090, register_VMatrix4TypeInfo)
   */
  void register_VMatrix4TypeInfo();

  static_assert(sizeof(AxisAlignedBox3fTypeInfo) == 0x64, "AxisAlignedBox3fTypeInfo size must be 0x64");
  static_assert(sizeof(Vector2iTypeInfo) == 0x64, "Vector2iTypeInfo size must be 0x64");
  static_assert(sizeof(Vector3iTypeInfo) == 0x64, "Vector3iTypeInfo size must be 0x64");
  static_assert(sizeof(Vector2fTypeInfo) == 0x64, "Vector2fTypeInfo size must be 0x64");
  static_assert(sizeof(Vector3fTypeInfo) == 0x64, "Vector3fTypeInfo size must be 0x64");
  static_assert(sizeof(Vector4fTypeInfo) == 0x64, "Vector4fTypeInfo size must be 0x64");
  static_assert(sizeof(QuaternionfTypeInfo) == 0x64, "QuaternionfTypeInfo size must be 0x64");
  static_assert(sizeof(VEulers3TypeInfo) == 0x64, "VEulers3TypeInfo size must be 0x64");
  static_assert(sizeof(VAxes3TypeInfo) == 0x64, "VAxes3TypeInfo size must be 0x64");
  static_assert(sizeof(VMatrix4TypeInfo) == 0x64, "VMatrix4TypeInfo size must be 0x64");

  static_assert(sizeof(VEulers3) == 0x0C, "VEulers3 size must be 0x0C");
  static_assert(offsetof(VEulers3, r) == 0x00, "VEulers3::r offset must be 0x00");
  static_assert(offsetof(VEulers3, p) == 0x04, "VEulers3::p offset must be 0x04");
  static_assert(offsetof(VEulers3, y) == 0x08, "VEulers3::y offset must be 0x08");

  static_assert(sizeof(VAxes3) == 0x24, "VAxes3 size must be 0x24");
  static_assert(offsetof(VAxes3, vX) == 0x00, "VAxes3::vX offset must be 0x00");
  static_assert(offsetof(VAxes3, vY) == 0x0C, "VAxes3::vY offset must be 0x0C");
  static_assert(offsetof(VAxes3, vZ) == 0x18, "VAxes3::vZ offset must be 0x18");
} // namespace moho

/**
 * Address: 0x00A8ECD3 (FUN_00A8ECD3, func_SetSSE2)
 *
 * What it does:
 * Enables/disables the SSE2 runtime lane by masking with the startup
 * compatibility flag, then publishes and returns the resulting mode value.
 * `CScApp::Init` calls this first thing with the result of
 * `CFG_GetArgOption("/sse2")`, so the default launch - no `/sse2` on the
 * command line - deliberately turns the SSE2 lane off.
 */
extern "C" int __cdecl RuntimeSetSse2Mode(int enableSse2);
