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

  // Address-backed process-wide mutex used by math/random helper lanes.
  extern boost::mutex& math_GlobalRandomMutex;
  // Address-backed process-wide random stream used by math helper lanes.
  extern CRandomStream& math_GlobalRandomStream;

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

  /**
   * Address: 0x004EDB60 (FUN_004EDB60, Moho::AxisAlignedBox3f::MemberDeserialize)
   *
   * What it does:
   * Loads `Min`/`Max` vector lanes in binary archive order.
   */
  void AxisAlignedBox3fMemberDeserialize(Wm3::AxisAlignedBox3f* box, gpg::ReadArchive* archive);

  /**
   * Address: 0x004EDBB0 (FUN_004EDBB0, Moho::AxisAlignedBox3f::MemberSerialize)
   *
   * What it does:
   * Stores `Min`/`Max` vector lanes in binary archive order.
   */
  void AxisAlignedBox3fMemberSerialize(const Wm3::AxisAlignedBox3f* box, gpg::WriteArchive* archive);

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

  class AxisAlignedBox3fSerializer
  {
  public:
    /**
     * Address: 0x004EA140 (FUN_004EA140, Moho::AxisAlignedBox3fSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, Wm3::AxisAlignedBox3f* box);

    /**
     * Address: 0x004EA150 (FUN_004EA150, Moho::AxisAlignedBox3fSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, Wm3::AxisAlignedBox3f* box);

    /**
     * Address: 0x00BF1230 (FUN_00BF1230, cleanup_AxisAlignedBox3fSerializer)
     */
    virtual ~AxisAlignedBox3fSerializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
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

  class Vector2iSerializer
  {
  public:
    /**
     * Address: 0x004EA370 (FUN_004EA370, Moho::Vector2iSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, Vector2i* vector);

    /**
     * Address: 0x004EA3A0 (FUN_004EA3A0, Moho::Vector2iSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, Vector2i* vector);

    /**
     * Address: 0x00BF12C0 (FUN_00BF12C0, cleanup_Vector2iSerializer)
     */
    virtual ~Vector2iSerializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
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

  class Vector3iSerializer
  {
  public:
    /**
     * Address: 0x004EA650 (FUN_004EA650, Moho::Vector3iSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, Vector3i* vector);

    /**
     * Address: 0x004EA690 (FUN_004EA690, Moho::Vector3iSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, Vector3i* vector);

    /**
     * Address: 0x00BF1350 (FUN_00BF1350, cleanup_Vector3iSerializer)
     */
    virtual ~Vector3iSerializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
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

  class Vector2fSerializer
  {
  public:
    /**
     * Address: 0x004EA930 (FUN_004EA930, Moho::Vector2fSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, Vector2f* vector);

    /**
     * Address: 0x004EA960 (FUN_004EA960, Moho::Vector2fSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, Vector2f* vector);

    /**
     * Address: 0x00BF13E0 (FUN_00BF13E0, cleanup_Vector2fSerializer)
     */
    virtual ~Vector2fSerializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
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

  class Vector3fSerializer
  {
  public:
    /**
     * Address: 0x004EAC20 (FUN_004EAC20, Moho::Vector3fSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, Vector3f* vector);

    /**
     * Address: 0x004EAC60 (FUN_004EAC60, Moho::Vector3fSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, Vector3f* vector);

    /**
     * Address: 0x00BF1470 (FUN_00BF1470, cleanup_Vector3fSerializer)
     */
    virtual ~Vector3fSerializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
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

  class Vector4fSerializer
  {
  public:
    /**
     * Address: 0x004EAF70 (FUN_004EAF70, Moho::Vector4fSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, Vector4f* vector);

    /**
     * Address: 0x004EAFB0 (FUN_004EAFB0, Moho::Vector4fSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, Vector4f* vector);

    /**
     * Address: 0x00BF1500 (FUN_00BF1500, cleanup_Vector4fSerializer)
     */
    virtual ~Vector4fSerializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
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

  class QuaternionfSerializer
  {
  public:
    /**
     * Address: 0x004EB2D0 (FUN_004EB2D0, Moho::QuaternionfSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, Quaternionf* quaternion);

    /**
     * Address: 0x004EB310 (FUN_004EB310, Moho::QuaternionfSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, Quaternionf* quaternion);

    /**
     * Address: 0x00BF1590 (FUN_00BF1590, cleanup_QuaternionfSerializer)
     */
    virtual ~QuaternionfSerializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
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

  class VEulers3Serializer
  {
  public:
    /**
     * Address: 0x004EC100 (FUN_004EC100, Moho::VEulers3Serializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, VEulers3* eulers);

    /**
     * Address: 0x004EC140 (FUN_004EC140, Moho::VEulers3Serializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, VEulers3* eulers);

    /**
     * Address: 0x00BF1620 (FUN_00BF1620, cleanup_VEulers3Serializer)
     */
    virtual ~VEulers3Serializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
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

  class VAxes3Serializer
  {
  public:
    /**
     * Address: 0x004EE050 (FUN_004EE050, Moho::VAxes3Serializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, VAxes3* axes);

    /**
     * Address: 0x004EE100 (FUN_004EE100, Moho::VAxes3Serializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, VAxes3* axes);

    /**
     * Address: 0x00BF16B0 (FUN_00BF16B0, cleanup_VAxes3Serializer)
     */
    virtual ~VAxes3Serializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
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

  /**
   * Address: 0x004EC4E0 (FUN_004EC4E0, Moho::VAxes3Serializer::DeserializeThunk)
   */
  void DeserializeVAxes3SerializerThunk(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

  /**
   * Address: 0x004EC4F0 (FUN_004EC4F0, Moho::VAxes3Serializer::SerializeThunk)
   */
  void SerializeVAxes3SerializerThunk(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

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

  class VMatrix4Serializer
  {
  public:
    /**
     * Address: 0x004F0220 (FUN_004F0220, Moho::VMatrix4Serializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, VMatrix4* matrix);

    /**
     * Address: 0x004F0230 (FUN_004F0230, Moho::VMatrix4Serializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, VMatrix4* matrix);

    /**
     * Address: 0x004F0300 (FUN_004F0300, Moho::VMatrix4Serializer::RegisterSerializeFunctions)
     */
    virtual void RegisterSerializeFunctions();

    /**
     * Address: 0x00BF1740 (FUN_00BF1740, cleanup_VMatrix4Serializer)
     */
    virtual ~VMatrix4Serializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
  };

  /**
   * Address: 0x00BC6C40 (FUN_00BC6C40, register_AxisAlignedBox3fTypeInfo)
   */
  int register_AxisAlignedBox3fTypeInfo();

  /**
   * Address: 0x00BC32E0 (FUN_00BC32E0, register_math_GlobalRandomMutex)
   *
   * What it does:
   * Constructs the process-global random-math mutex and registers process-exit
   * teardown.
   */
  void register_math_GlobalRandomMutex();

  /**
   * Address: 0x00BC32A0 (FUN_00BC32A0, register_math_GlobalRandomStream)
   *
   * What it does:
   * Seeds the process-global random stream from time/tick entropy and
   * registers process-exit teardown.
   */
  void register_math_GlobalRandomStream();

  /**
   * Address: 0x00BC6C60 (FUN_00BC6C60, register_AxisAlignedBox3fSerializer)
   */
  void register_AxisAlignedBox3fSerializer();

  /**
   * Address: 0x00BC6CA0 (FUN_00BC6CA0, register_Vector2iTypeInfo)
   */
  int register_Vector2iTypeInfo();

  /**
   * Address: 0x00BC6CC0 (FUN_00BC6CC0, register_Vector2iSerializer)
   */
  void register_Vector2iSerializer();

  /**
   * Address: 0x00BC6D00 (FUN_00BC6D00, register_Vector3iTypeInfo)
   */
  int register_Vector3iTypeInfo();

  /**
   * Address: 0x00BC6D20 (FUN_00BC6D20, register_Vector3iSerializer)
   */
  void register_Vector3iSerializer();

  /**
   * Address: 0x00BC6D60 (FUN_00BC6D60, register_Vector2fTypeInfo)
   */
  int register_Vector2fTypeInfo();

  /**
   * Address: 0x00BC6D80 (FUN_00BC6D80, register_Vector2fSerializer)
   */
  void register_Vector2fSerializer();

  /**
   * Address: 0x00BC6DC0 (FUN_00BC6DC0, register_Vector3fTypeInfo)
   */
  int register_Vector3fTypeInfo();

  /**
   * Address: 0x00BC6DE0 (FUN_00BC6DE0, register_Vector3fSerializer)
   */
  void register_Vector3fSerializer();

  /**
   * Address: 0x00BC6E20 (FUN_00BC6E20, register_Vector4fTypeInfo)
   */
  int register_Vector4fTypeInfo();

  /**
   * Address: 0x00BC6E40 (FUN_00BC6E40, register_Vector4fSerializer)
   */
  void register_Vector4fSerializer();

  /**
   * Address: 0x00BC6E80 (FUN_00BC6E80, register_QuaternionfTypeInfo)
   */
  int register_QuaternionfTypeInfo();

  /**
   * Address: 0x00BC6EA0 (FUN_00BC6EA0, register_QuaternionfSerializer)
   */
  void register_QuaternionfSerializer();

  /**
   * Address: 0x00BC6EE0 (FUN_00BC6EE0, register_VEulers3TypeInfo)
   */
  int register_VEulers3TypeInfo();

  /**
   * Address: 0x00BC6F00 (FUN_00BC6F00, register_VEulers3Serializer)
   */
  void register_VEulers3Serializer();

  /**
   * Address: 0x00BC6F40 (FUN_00BC6F40, register_VAxes3TypeInfo)
   */
  int register_VAxes3TypeInfo();

  /**
   * Address: 0x00BC6F60 (FUN_00BC6F60, register_VAxes3Serializer)
   */
  int register_VAxes3Serializer();

  /**
   * Address: 0x00BC7000 (FUN_00BC7000, register_VMatrix4NaN)
   */
  void register_VMatrix4NaN();

  /**
   * Address: 0x00BC7090 (FUN_00BC7090, register_VMatrix4TypeInfo)
   */
  void register_VMatrix4TypeInfo();

  /**
   * Address: 0x00BC70B0 (FUN_00BC70B0, register_VMatrix4Serializer)
   */
  void register_VMatrix4Serializer();

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

  static_assert(offsetof(AxisAlignedBox3fSerializer, mHelperNext) == 0x04, "AxisAlignedBox3fSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(AxisAlignedBox3fSerializer, mHelperPrev) == 0x08, "AxisAlignedBox3fSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(AxisAlignedBox3fSerializer, mDeserialize) == 0x0C, "AxisAlignedBox3fSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(AxisAlignedBox3fSerializer, mSerialize) == 0x10, "AxisAlignedBox3fSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(AxisAlignedBox3fSerializer) == 0x14, "AxisAlignedBox3fSerializer size must be 0x14");

  static_assert(offsetof(Vector2iSerializer, mHelperNext) == 0x04, "Vector2iSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(Vector2iSerializer, mHelperPrev) == 0x08, "Vector2iSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(Vector2iSerializer, mDeserialize) == 0x0C, "Vector2iSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(Vector2iSerializer, mSerialize) == 0x10, "Vector2iSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(Vector2iSerializer) == 0x14, "Vector2iSerializer size must be 0x14");

  static_assert(offsetof(Vector3iSerializer, mHelperNext) == 0x04, "Vector3iSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(Vector3iSerializer, mHelperPrev) == 0x08, "Vector3iSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(Vector3iSerializer, mDeserialize) == 0x0C, "Vector3iSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(Vector3iSerializer, mSerialize) == 0x10, "Vector3iSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(Vector3iSerializer) == 0x14, "Vector3iSerializer size must be 0x14");

  static_assert(offsetof(Vector2fSerializer, mHelperNext) == 0x04, "Vector2fSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(Vector2fSerializer, mHelperPrev) == 0x08, "Vector2fSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(Vector2fSerializer, mDeserialize) == 0x0C, "Vector2fSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(Vector2fSerializer, mSerialize) == 0x10, "Vector2fSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(Vector2fSerializer) == 0x14, "Vector2fSerializer size must be 0x14");

  static_assert(offsetof(Vector3fSerializer, mHelperNext) == 0x04, "Vector3fSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(Vector3fSerializer, mHelperPrev) == 0x08, "Vector3fSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(Vector3fSerializer, mDeserialize) == 0x0C, "Vector3fSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(Vector3fSerializer, mSerialize) == 0x10, "Vector3fSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(Vector3fSerializer) == 0x14, "Vector3fSerializer size must be 0x14");

  static_assert(offsetof(Vector4fSerializer, mHelperNext) == 0x04, "Vector4fSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(Vector4fSerializer, mHelperPrev) == 0x08, "Vector4fSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(Vector4fSerializer, mDeserialize) == 0x0C, "Vector4fSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(Vector4fSerializer, mSerialize) == 0x10, "Vector4fSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(Vector4fSerializer) == 0x14, "Vector4fSerializer size must be 0x14");

  static_assert(offsetof(QuaternionfSerializer, mHelperNext) == 0x04, "QuaternionfSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(QuaternionfSerializer, mHelperPrev) == 0x08, "QuaternionfSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(QuaternionfSerializer, mDeserialize) == 0x0C, "QuaternionfSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(QuaternionfSerializer, mSerialize) == 0x10, "QuaternionfSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(QuaternionfSerializer) == 0x14, "QuaternionfSerializer size must be 0x14");

  static_assert(offsetof(VEulers3Serializer, mHelperNext) == 0x04, "VEulers3Serializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(VEulers3Serializer, mHelperPrev) == 0x08, "VEulers3Serializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(VEulers3Serializer, mDeserialize) == 0x0C, "VEulers3Serializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(VEulers3Serializer, mSerialize) == 0x10, "VEulers3Serializer::mSerialize offset must be 0x10");
  static_assert(sizeof(VEulers3Serializer) == 0x14, "VEulers3Serializer size must be 0x14");

  static_assert(offsetof(VAxes3Serializer, mHelperNext) == 0x04, "VAxes3Serializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(VAxes3Serializer, mHelperPrev) == 0x08, "VAxes3Serializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(VAxes3Serializer, mDeserialize) == 0x0C, "VAxes3Serializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(VAxes3Serializer, mSerialize) == 0x10, "VAxes3Serializer::mSerialize offset must be 0x10");
  static_assert(sizeof(VAxes3Serializer) == 0x14, "VAxes3Serializer size must be 0x14");

  static_assert(offsetof(VMatrix4Serializer, mHelperNext) == 0x04, "VMatrix4Serializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(VMatrix4Serializer, mHelperPrev) == 0x08, "VMatrix4Serializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(VMatrix4Serializer, mDeserialize) == 0x0C, "VMatrix4Serializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(VMatrix4Serializer, mSerialize) == 0x10, "VMatrix4Serializer::mSerialize offset must be 0x10");
  static_assert(sizeof(VMatrix4Serializer) == 0x14, "VMatrix4Serializer size must be 0x14");

  static_assert(sizeof(VEulers3) == 0x0C, "VEulers3 size must be 0x0C");
  static_assert(offsetof(VEulers3, r) == 0x00, "VEulers3::r offset must be 0x00");
  static_assert(offsetof(VEulers3, p) == 0x04, "VEulers3::p offset must be 0x04");
  static_assert(offsetof(VEulers3, y) == 0x08, "VEulers3::y offset must be 0x08");

  static_assert(sizeof(VAxes3) == 0x24, "VAxes3 size must be 0x24");
  static_assert(offsetof(VAxes3, vX) == 0x00, "VAxes3::vX offset must be 0x00");
  static_assert(offsetof(VAxes3, vY) == 0x0C, "VAxes3::vY offset must be 0x0C");
  static_assert(offsetof(VAxes3, vZ) == 0x18, "VAxes3::vZ offset must be 0x18");
} // namespace moho
