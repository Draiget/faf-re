#include "IResources.h"

namespace
{
  [[nodiscard]] msvc8::string* ResourceDepositTypeNameTable() noexcept
  {
    static msvc8::string sResourceDepositTypeNames[3] = {
      msvc8::string(""),
      msvc8::string("Mass"),
      msvc8::string("Hydrocarbon"),
    };

    return sResourceDepositTypeNames;
  }
}

namespace moho
{
  gpg::RType* IResources::sType = nullptr;

  /**
   * Address: 0x00546CB0 (FUN_00546CB0, ??0IResources@Moho@@IAE@XZ)
   * Shared helper: 0x00546E80 (loc_00546E80)
   *
   * What it does:
   * Initializes the IResources base-subobject vtable slot.
   */
  IResources::IResources() noexcept = default;

  /**
   * Address: 0x00546CC0 (FUN_00546CC0, ??1IResources@Moho@@UAE@XZ)
   * Shared helper: 0x00546E80 (loc_00546E80)
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

  /**
   * Address: 0x00546CD0 (FUN_00546CD0, ?Translate@IResources@Moho@@SA?AW4EResourceType@2@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z)
   *
   * What it does:
   * Finds one deposit type enum by searching the static type-name table and
   * returns `kNone` when the text is unknown.
   */
  EDepositType IResources::Translate(const msvc8::string& depositTypeName)
  {
    msvc8::string* const begin = ResourceDepositTypeNameTable();
    msvc8::string* const end = begin + 3;
    msvc8::string* const found = SearchStringArrayFor(begin, end, &depositTypeName);
    if (found == end) {
      return kNone;
    }

    return static_cast<EDepositType>(found - begin);
  }

  /**
   * Address: 0x00546D10 (FUN_00546D10)
   *
   * What it does:
   * Resolves one deposit-type enum lane back to its string table entry.
   */
  const msvc8::string* IResources::Translate(const EDepositType depositType)
  {
    msvc8::string* const begin = ResourceDepositTypeNameTable();
    return begin + static_cast<int>(depositType);
  }
} // namespace moho
