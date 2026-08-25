#include "moho/unit/tasks/CUnitMobileBuildTaskSerializer.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/tasks/CUnitMobileBuildTask.h"

namespace moho
{
  gpg::RType* CUnitMobileBuildTask::sType = nullptr;
} // namespace moho

namespace
{
  /**
   * Address: 0x00BCF890 (FUN_00BCF890, dynamic initializer for the global
   * `CUnitMobileBuildTaskSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`).
   */
  moho::CUnitMobileBuildTaskSerializer gCUnitMobileBuildTaskSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x005F6A10 (FUN_005F6A10, Moho::CUnitMobileBuildTaskSerializer::Deserialize)
   *
   * IDA signature:
   * int __cdecl Deserialize(ReadArchive* archive, void* objectPtr, ...);
   *
   * What it does:
   * Reflection load-callback facade. The binary loads `eax`=archive (arg_0),
   * `ecx`=objectPtr (arg_4) and tail-jumps to the member load body, so the
   * modern form forwards `objectPtr->MemberDeserialize(archive)`.
   */
  void CUnitMobileBuildTaskSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int /*version*/,
    gpg::RRef* /*ownerRef*/
  )
  {
    auto* const task = reinterpret_cast<CUnitMobileBuildTask*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (archive == nullptr || task == nullptr) {
      return;
    }
    task->MemberDeserialize(archive);
  }

  /**
   * Address: 0x005F6A20 (FUN_005F6A20, Moho::CUnitMobileBuildTaskSerializer::Serialize)
   *
   * IDA signature:
   * int __cdecl Serialize(WriteArchive* archive, void* objectPtr, ...);
   *
   * What it does:
   * Reflection save-callback facade. The binary loads `eax`=objectPtr (arg_4),
   * `esi`=archive (arg_0) and calls the member save body, so the modern form
   * forwards `objectPtr->MemberSerialize(archive)`.
   */
  void CUnitMobileBuildTaskSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int /*version*/,
    gpg::RRef* /*ownerRef*/
  )
  {
    auto* const task = reinterpret_cast<CUnitMobileBuildTask*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(task != nullptr);
    if (archive == nullptr || task == nullptr) {
      return;
    }
    task->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BCF890 (FUN_00BCF890, register_CUnitMobileBuildTaskSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CUnitMobileBuildTaskSerializer::CUnitMobileBuildTaskSerializer()
    : mDeserialize(reinterpret_cast<gpg::RType::load_func_t>(&CUnitMobileBuildTaskSerializer::Deserialize))
    , mSerialize(reinterpret_cast<gpg::RType::save_func_t>(&CUnitMobileBuildTaskSerializer::Serialize))
  {}

  /**
   * Address: 0x00BF9330 (FUN_00BF9330, Moho::CUnitMobileBuildTaskSerializer::~CUnitMobileBuildTaskSerializer)
   */
  CUnitMobileBuildTaskSerializer::~CUnitMobileBuildTaskSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x005FBBA0 (FUN_005FBBA0, gpg::SerSaveLoadHelper<Moho::CUnitMobileBuildTask>::Init)
   */
  void CUnitMobileBuildTaskSerializer::Init()
  {
    if (CUnitMobileBuildTask::sType == nullptr) {
      CUnitMobileBuildTask::sType = gpg::LookupRType(typeid(CUnitMobileBuildTask));
    }

    gpg::RType* const type = CUnitMobileBuildTask::sType;
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho
