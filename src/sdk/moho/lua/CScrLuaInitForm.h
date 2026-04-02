#pragma once

#include <cstddef>
#include <cstdint>

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  class CScrLuaInitForm;

  class CScrLuaInitFormSet
  {
  public:
    /**
     * Address: 0x100BEAF0 (FUN_100BEAF0)
     *
     * char const *
     *
     * What it does:
     * Initializes the set name and links this set into the global set list head.
     */
    explicit CScrLuaInitFormSet(const char* setName);

    /**
     * Address: 0x100158D0 (FUN_100158D0)
     *
     * CScrLuaInitFormSet *
     *
     * What it does:
     * Returns the head of the global Lua-init-form-set intrusive list.
     */
    static CScrLuaInitFormSet* GetFirst();

    /**
     * Address: 0x100158E0 (FUN_100158E0)
     *
     * CScrLuaInitFormSet *
     *
     * What it does:
     * Returns the next set in the intrusive set chain.
     */
    [[nodiscard]] CScrLuaInitFormSet* GetNext();

    /**
     * Address: 0x100158F0 (FUN_100158F0)
     *
     * CScrLuaInitFormSet &, CScrLuaInitFormSet const &
     *
     * What it does:
     * Copies the raw 4-dword set record fields.
     */
    CScrLuaInitFormSet& operator=(const CScrLuaInitFormSet& other);

    /**
     * Address: 0x100BEB10 (FUN_100BEB10)
     *
     * CScrLuaInitForm *
     *
     * What it does:
     * Pushes a Lua init form at the set head.
     */
    void AddInit(CScrLuaInitForm* form);

    /**
     * Address: 0x100BEB20 (FUN_100BEB20)
     *
     * LuaState *
     *
     * What it does:
     * Marks the set as registered and executes all form handlers in list order.
     */
    void RunInits(LuaPlus::LuaState* state);

    /**
     * Address: 0x004CCFE0 (FUN_004CCFE0, Moho::CScrLuaInitFormSet::DumpDocs)
     *
     * What it does:
     * Dumps grouped Lua binder documentation entries for this set.
     */
    void DumpDocs();

  public:
    const char* mSetName;                 // +0x00 (doc/context set label)
    CScrLuaInitForm* mForms;              // +0x04
    std::uint8_t mRegistered;             // +0x08
    std::uint8_t mRegistrationPadding[3]; // +0x09 (tail bytes copied by operator=; no direct semantic use observed)
    CScrLuaInitFormSet* mNextSet;         // +0x0C

    static CScrLuaInitFormSet* sSets;
  };
  static_assert(offsetof(CScrLuaInitFormSet, mSetName) == 0x00, "CScrLuaInitFormSet::mSetName offset must be 0x00");
  static_assert(offsetof(CScrLuaInitFormSet, mForms) == 0x04, "CScrLuaInitFormSet::mForms offset must be 0x04");
  static_assert(
    offsetof(CScrLuaInitFormSet, mRegistered) == 0x08, "CScrLuaInitFormSet::mRegistered offset must be 0x08"
  );
  static_assert(offsetof(CScrLuaInitFormSet, mNextSet) == 0x0C, "CScrLuaInitFormSet::mNextSet offset must be 0x0C");
  static_assert(sizeof(CScrLuaInitFormSet) == 0x10, "CScrLuaInitFormSet size must be 0x10");

  class CScrLuaInitForm
  {
  public:
    /**
     * Address: 0x100BEE50 (FUN_100BEE50)
     *
     * CScrLuaInitFormSet &, char const *, char const *, char const *
     *
     * IDA signature:
     * Moho::CScrLuaInitForm *__thiscall Moho::CScrLuaInitForm::CScrLuaInitForm(
     *     Moho::CScrLuaInitForm *this,
     *     struct Moho::CScrLuaInitFormSet *a2,
     *     const char *a3,
     *     const char *a4,
     *     const char *a5)
     *
     * What it does:
     * Stores form metadata and inserts this form at the head of the owning set list.
     */
    CScrLuaInitForm(CScrLuaInitFormSet& set, const char* name, const char* groupName, const char* docString);

    /**
     * Address: 0x10015940 (FUN_10015940)
     *
     * CScrLuaInitForm &, CScrLuaInitForm const &
     *
     * What it does:
     * Copies the base Lua init form metadata and next-link field.
     */
    CScrLuaInitForm(const CScrLuaInitForm& other);

    /**
     * Address: 0x10015910 (FUN_10015910)
     *
     * char const *
     *
     * What it does:
     * Returns the registered Lua symbol name for this init form.
     */
    [[nodiscard]] const char* GetName() const;

    /**
     * Address: 0x10015920 (FUN_10015920)
     *
     * char const *
     *
     * What it does:
     * Returns the group/category label used for doc grouping.
     */
    [[nodiscard]] const char* GetGroupName() const;

    /**
     * Address: 0x10015930 (FUN_10015930)
     *
     * char const *
     *
     * What it does:
     * Returns the per-symbol doc/source string.
     */
    [[nodiscard]] const char* GetDocString() const;
    virtual ~CScrLuaInitForm() = default;

    virtual void Run(LuaPlus::LuaState* state) = 0;

  public:
    const char* mName;           // +0x04
    const char* mGroupName;      // +0x08
    const char* mDocString;      // +0x0C
    CScrLuaInitForm* mNextInSet; // +0x10
  };
  static_assert(offsetof(CScrLuaInitForm, mName) == 0x04, "CScrLuaInitForm::mName offset must be 0x04");
  static_assert(offsetof(CScrLuaInitForm, mGroupName) == 0x08, "CScrLuaInitForm::mGroupName offset must be 0x08");
  static_assert(offsetof(CScrLuaInitForm, mDocString) == 0x0C, "CScrLuaInitForm::mDocString offset must be 0x0C");
  static_assert(offsetof(CScrLuaInitForm, mNextInSet) == 0x10, "CScrLuaInitForm::mNextInSet offset must be 0x10");
  static_assert(sizeof(CScrLuaInitForm) == 0x14, "CScrLuaInitForm size must be 0x14");
} // namespace moho
