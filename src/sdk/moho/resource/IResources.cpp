#include "IResources.h"

namespace moho
{
  gpg::RType* IResources::sType = nullptr;

  /**
   * Address: 0x00546E80 (loc_00546E80, shared constructor/destructor helper chunk)
   *
   * What it does:
   * Initializes the IResources base-subobject vtable slot.
   */
  IResources::IResources() noexcept = default;

  /**
   * Address: 0x00546E80 (loc_00546E80, shared constructor/destructor helper chunk)
   *
   * What it does:
   * Tears down the IResources base-subobject vtable state.
   */
  IResources::~IResources() noexcept = default;

  /**
   * Address: 0x005491C0 (FUN_005491C0, func_SearchStringArrayFor)
   *
   * What it does:
   * Walks one `[begin,end)` string array and returns the first exact match for
   * `value`; otherwise returns `end`.
   */
  msvc8::string* SearchStringArrayFor(
    msvc8::string* const begin,
    msvc8::string* const end,
    const msvc8::string* const value
  )
  {
    msvc8::string* cursor = begin;
    while (cursor != end) {
      if (cursor->compare(value->view()) == 0) {
        break;
      }
      ++cursor;
    }
    return cursor;
  }
} // namespace moho
