#pragma once

#include "moho/animation/CAniSkel.h"

namespace gpg
{
  class ReadArchive;
  class RRef;
  class SerConstructResult;
  class SerSaveConstructArgsResult;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CAniDefaultSkel : public CAniSkel
  {
  public:
    /**
     * What it does:
     * Hands back the one default skeleton, shared. Inlined into
     * `SerConstructHelper<CAniDefaultSkel>::Construct` 0x0054ABB0.
     */
    static void MemberConstruct(
      gpg::ReadArchive& archive, int version, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
    );

    /**
     * What it does:
     * Saves nothing but the ownership (owned). Inlined into
     * `SerSaveConstructHelper<CAniDefaultSkel>::SaveConstructArgs` 0x0054AAA0.
     */
    void MemberSaveConstructArgs(
      gpg::WriteArchive& archive, int version, const gpg::RRef& ownerRef, gpg::SerSaveConstructArgsResult& result
    );

    static gpg::RType* sType;

    /**
     * Address: 0x0054A390 (FUN_0054A390, Moho::CAniDefaultSkel::CAniDefaultSkel)
     * Mangled: ??0CAniDefaultSkel@Moho@@IAE@XZ
     *
     * What it does:
     * Initializes the process-default skeleton with one `Root` bone and one
     * matching bone-name index entry, then rebuilds bounds.
     */
    CAniDefaultSkel();

    /**
     * Address: 0x0054A4C0 (FUN_0054A4C0, Moho::CAniDefaultSkel::~CAniDefaultSkel)
     * Mangled: ??1CAniDefaultSkel@Moho@@QAE@XZ
     * Deleting thunk: 0x0054AD50 (FUN_0054AD50, ??_GCAniDefaultSkel@Moho@@UAEPAXI@Z)
     *
     * What it does:
     * Resets vftable to `CAniSkel`, releases skeleton vectors/shared SCM file,
     * then returns to scalar deleting destructor thunk for optional delete.
     */
    ~CAniDefaultSkel() override;
  };

  static_assert(sizeof(CAniDefaultSkel) == 0x2C, "CAniDefaultSkel size must be 0x2C");
} // namespace moho
