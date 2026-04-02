#include "moho/misc/ScrGotoDialog.h"

#include <cstdlib>

#include "moho/misc/StartupHelpers.h"

void* moho::ScrGotoDialog::sm_eventTable[1] = {nullptr};

/**
 * Address: 0x004BBEA0 (FUN_004BBEA0)
 *
 * What it does:
 * Runs non-deleting teardown for one script goto dialog instance.
 */
moho::ScrGotoDialog* moho::ScrGotoDialog::DestroyWithoutDelete(ScrGotoDialog* const object) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  return reinterpret_cast<ScrGotoDialog*>(
    wxDialogRuntime::DeleteWithFlag(static_cast<wxDialogRuntime*>(object), 0u)
  );
}

/**
 * Address: 0x004BC0C0 (FUN_004BC0C0)
 *
 * What it does:
 * Implements deleting-dtor thunk semantics for one script goto dialog.
 */
moho::ScrGotoDialog* moho::ScrGotoDialog::DeleteWithFlag(
  ScrGotoDialog* const object,
  const std::uint8_t deleteFlags
) noexcept
{
  if (object == nullptr) {
    return nullptr;
  }

  DestroyWithoutDelete(object);
  if ((deleteFlags & 1u) != 0u) {
    operator delete(object);
  }
  return object;
}

/**
 * Address: 0x004BC0F0 (FUN_004BC0F0)
 *
 * What it does:
 * Returns this dialog runtime event-table lane.
 */
const void* moho::ScrGotoDialog::GetEventTable() const
{
  return sm_eventTable;
}

/**
 * Address: 0x004BBEB0 (FUN_004BBEB0)
 *
 * What it does:
 * Persists goto-dialog window position to user preferences after move
 * handling when startup initialization has completed.
 */
void moho::ScrGotoDialog::PersistWindowPositionToPreferences()
{
  if (mIsInitializing != 0u) {
    return;
  }

  moho::IUserPrefs* const preferences = moho::USER_GetPreferences();
  if (preferences == nullptr) {
    return;
  }

  std::int32_t windowX = 0;
  std::int32_t windowY = 0;
  DoGetPosition(&windowX, &windowY);

  preferences->SetInteger(msvc8::string("Windows.Debug.Goto.x"), windowX);
  preferences->SetInteger(msvc8::string("Windows.Debug.Goto.y"), windowY);
}

/**
 * Address: 0x004BBFF0 (FUN_004BBFF0)
 *
 * What it does:
 * Reads goto-line text input and converts it to an integer line index.
 */
int moho::ScrGotoDialog::ParseRequestedLineNumber() const
{
  const msvc8::string lineTextUtf8 = mLineTextControl->GetValueUtf8();
  return std::atoi(lineTextUtf8.c_str());
}

