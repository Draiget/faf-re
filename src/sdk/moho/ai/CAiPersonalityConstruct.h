#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E1CA98
   * COL:  0x00E72A98
   */
  class CAiPersonalityConstruct
  {
  public:
    /**
     * Address: 0x005B69E0 (FUN_005B69E0)
     *
     * What it does:
     * Allocates a `CAiPersonality`, wraps it in `gpg::RRef`, and returns it to
     * the serialization construct result as an unowned object.
     */
    static void Construct(
      gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result
    );

    /**
     * Address: 0x005B9580 (FUN_005B9580)
     *
     * What it does:
     * Deletes one `CAiPersonality` object created through the construct path.
     */
    static void Deconstruct(void* object);

    /**
     * Address: 0x005B92D0 (FUN_005B92D0)
     *
     * What it does:
     * Binds construct/delete callbacks into CAiPersonality RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    // Intrusive list links from gpg::DListItem<gpg::SerHelperBase>.
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    // Serializer callbacks consumed by gpg::serialization.h registration flow.
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(CAiPersonalityConstruct, mHelperNext) == 0x04,
    "CAiPersonalityConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CAiPersonalityConstruct, mHelperPrev) == 0x08,
    "CAiPersonalityConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CAiPersonalityConstruct, mConstructCallback) == 0x0C,
    "CAiPersonalityConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiPersonalityConstruct, mDeleteCallback) == 0x10,
    "CAiPersonalityConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiPersonalityConstruct) == 0x14, "CAiPersonalityConstruct size must be 0x14");

  /**
   * Address: 0x00BCD620 (FUN_00BCD620, register_CAiPersonalityConstruct)
   *
   * What it does:
   * Initializes the global personality construct helper and installs
   * process-exit cleanup.
   */
  int register_CAiPersonalityConstruct();
} // namespace moho
