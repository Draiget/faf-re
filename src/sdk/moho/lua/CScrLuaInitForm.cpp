#include "moho/lua/CScrLuaInitForm.h"

#include <algorithm>
#include <cstring>
#include <string_view>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Vector.h"
#include "lua/LuaRuntimeTypes.h"

namespace
{
  struct LuaDocEntry
  {
    msvc8::string mGroupName;
    msvc8::string mDocString;
    msvc8::string mName;
  };

  [[nodiscard]] bool LessText(const msvc8::string& lhs, const msvc8::string& rhs)
  {
    return std::string_view(lhs.c_str()) < std::string_view(rhs.c_str());
  }

  [[nodiscard]] bool LessEntry(const LuaDocEntry& lhs, const LuaDocEntry& rhs)
  {
    if (lhs.mGroupName == rhs.mGroupName) {
      if (lhs.mDocString == rhs.mDocString) {
        return LessText(lhs.mName, rhs.mName);
      }
      return LessText(lhs.mDocString, rhs.mDocString);
    }
    return LessText(lhs.mGroupName, rhs.mGroupName);
  }
} // namespace

namespace moho
{
  /**
   * Address context:
   * - recurring Lua callback-thunk context unwrap sequence.
   *
   * What it does:
   * Resolves LuaPlus wrapper state pointer from raw `lua_State` callback lane.
   */
  LuaPlus::LuaState* SCR_ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  /**
   * Address context:
   * - recurring `CScrLuaInitFormSet` intrusive list lookup sequence.
   *
   * What it does:
   * Returns first init-form set whose name exactly matches `setName`.
   */
  CScrLuaInitFormSet* SCR_FindLuaInitFormSet(const char* const setName) noexcept
  {
    if (setName == nullptr) {
      return nullptr;
    }

    for (CScrLuaInitFormSet* set = CScrLuaInitFormSet::GetFirst(); set != nullptr; set = set->GetNext()) {
      if (set->mSetName != nullptr && std::strcmp(set->mSetName, setName) == 0) {
        return set;
      }
    }

    return nullptr;
  }

  CScrLuaInitFormSet* CScrLuaInitFormSet::sSets = nullptr;

  /**
   * Address: 0x100BEAF0 (FUN_100BEAF0)
   * Address: 0x004CCF80 (FUN_004CCF80, Moho::CScrLuaInitFormSet::CScrLuaInitFormSet)
   *
   * What it does:
   * Initializes the set name and inserts this set into the global set list.
   */
  CScrLuaInitFormSet::CScrLuaInitFormSet(const char* const setName)
    : mSetName(setName)
    , mNextSet(sSets)
  {
    sSets = this;
  }

  /**
   * Address: 0x100158D0 (FUN_100158D0)
   * Address: 0x004CCB90 (FUN_004CCB90, Moho::CScrLuaInitFormSet::GetFirst)
   *
   * What it does:
   * Returns the current head set pointer for Lua init form registration.
   */
  CScrLuaInitFormSet* CScrLuaInitFormSet::GetFirst()
  {
    return sSets;
  }

  /**
   * Address: 0x100158E0 (FUN_100158E0)
   * Address: 0x004CCBA0 (FUN_004CCBA0, Moho::CScrLuaInitFormSet::GetNext)
   *
   * What it does:
   * Returns the linked-list successor set.
   */
  CScrLuaInitFormSet* CScrLuaInitFormSet::GetNext()
  {
    return mNextSet;
  }

  /**
   * Address: 0x100158F0 (FUN_100158F0)
   *
   * What it does:
   * Performs a direct field copy of the 4-word set record.
   */
  CScrLuaInitFormSet& CScrLuaInitFormSet::operator=(const CScrLuaInitFormSet& other)
  {
    mSetName = other.mSetName;
    mForms = other.mForms;
    mRegistered = other.mRegistered;
    mRegistrationPadding[0] = other.mRegistrationPadding[0];
    mRegistrationPadding[1] = other.mRegistrationPadding[1];
    mRegistrationPadding[2] = other.mRegistrationPadding[2];
    mNextSet = other.mNextSet;
    return *this;
  }

  /**
   * Address: 0x100BEB10 (FUN_100BEB10)
   * Address: 0x004CCFA0 (FUN_004CCFA0, Moho::CScrLuaInitFormSet::AddInit)
   *
   * What it does:
   * Inserts an init form at the head of this set.
   */
  void CScrLuaInitFormSet::AddInit(CScrLuaInitForm* const form)
  {
    form->mNextInSet = mForms;
    mForms = form;
  }

  /**
   * Address: 0x100BEB20 (FUN_100BEB20)
   *
   * What it does:
   * Marks this set as registered and runs every linked init form.
   */
  void CScrLuaInitFormSet::RunInits(LuaPlus::LuaState* const state)
  {
    mRegistered = 1;
    for (CScrLuaInitForm* form = mForms; form; form = form->mNextInSet) {
      form->Run(state);
    }
  }

  /**
   * Address: 0x004CCFE0 (FUN_004CCFE0, Moho::CScrLuaInitFormSet::DumpDocs)
   *
   * What it does:
   * Emits Lua binding docs grouped by group/doc/name with nested gpg log contexts.
   */
  void CScrLuaInitFormSet::DumpDocs()
  {
    msvc8::vector<LuaDocEntry> entries;

    for (CScrLuaInitForm* form = mForms; form; form = form->mNextInSet) {
      if (!form->GetName() || !form->GetGroupName() || !form->GetDocString()) {
        continue;
      }

      entries.push_back(
        LuaDocEntry{
          msvc8::string(form->GetGroupName()),
          msvc8::string(form->GetDocString()),
          msvc8::string(form->GetName()),
        }
      );
    }

    std::sort(entries.begin(), entries.end(), LessEntry);

    const char* const setName = mSetName ? mSetName : "";
    gpg::ScopedLogContext setScope(setName);

    std::size_t index = 0;
    while (index < entries.size()) {
      const msvc8::string groupName = entries[index].mGroupName;
      const msvc8::string groupScopeName = gpg::STR_Printf("%s.%s", setName, groupName.c_str());
      gpg::ScopedLogContext groupScope(groupScopeName);

      while (index < entries.size() && entries[index].mGroupName == groupName) {
        gpg::ScopedLogContext docScope(entries[index].mDocString);
        gpg::Logf("%s", entries[index].mName.c_str());
        ++index;
      }
    }
  }

  /**
   * Address: 0x100BEE50 (FUN_100BEE50)
   * Address: 0x004CD370 (FUN_004CD370, Moho::CScrLuaInitForm::CScrLuaInitForm)
   *
   * What it does:
   * Initializes metadata and links this form into the set head.
   */
  CScrLuaInitForm::CScrLuaInitForm(
    CScrLuaInitFormSet& set, const char* name, const char* groupName, const char* docString
  )
    : mName(name)
    , mGroupName(groupName)
    , mDocString(docString)
  {
    set.AddInit(this);
  }

  /**
   * Address: 0x10015940 (FUN_10015940)
   *
   * What it does:
   * Copy-constructs the init-form metadata and chain link.
   */
  CScrLuaInitForm::CScrLuaInitForm(const CScrLuaInitForm& other)
    : mName(other.mName)
    , mGroupName(other.mGroupName)
    , mDocString(other.mDocString)
    , mNextInSet(other.mNextInSet)
  {}

  /**
   * Address: 0x10015910 (FUN_10015910)
   * Address: 0x004CCBB0 (FUN_004CCBB0, Moho::CScrLuaInitForm::GetName)
   *
   * What it does:
   * Returns this form's name string pointer.
   */
  const char* CScrLuaInitForm::GetName() const
  {
    return mName;
  }

  /**
   * Address: 0x10015920 (FUN_10015920)
   * Address: 0x004CCBC0 (FUN_004CCBC0, Moho::CScrLuaInitForm::GetGroupName)
   *
   * What it does:
   * Returns this form's grouping label pointer.
   */
  const char* CScrLuaInitForm::GetGroupName() const
  {
    return mGroupName;
  }

  /**
   * Address: 0x10015930 (FUN_10015930)
   *
   * What it does:
   * Returns this form's doc/source string pointer.
   */
  const char* CScrLuaInitForm::GetDocString() const
  {
    return mDocString;
  }
} // namespace moho
