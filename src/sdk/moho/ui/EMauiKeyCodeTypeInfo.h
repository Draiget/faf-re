#pragma once

#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

#define MOHO_EMAUI_KEYCODE_LIST(X) \
  X(MKEY_BACK, 8) \
  X(MKEY_TAB, 9) \
  X(MKEY_RETURN, 13) \
  X(MKEY_ESCAPE, 27) \
  X(MKEY_SPACE, 32) \
  X(MKEY_DELETE, 127) \
  X(MKEY_START, 300) \
  X(MKEY_LBUTTON, 301) \
  X(MKEY_RBUTTON, 302) \
  X(MKEY_CANCEL, 303) \
  X(MKEY_MBUTTON, 304) \
  X(MKEY_CLEAR, 305) \
  X(MKEY_SHIFT, 306) \
  X(MKEY_ALT, 307) \
  X(MKEY_CONTROL, 308) \
  X(MKEY_MENU, 309) \
  X(MKEY_PAUSE, 310) \
  X(MKEY_CAPITAL, 311) \
  X(MKEY_PRIOR, 312) \
  X(MKEY_NEXT, 313) \
  X(MKEY_END, 314) \
  X(MKEY_HOME, 315) \
  X(MKEY_LEFT, 316) \
  X(MKEY_UP, 317) \
  X(MKEY_RIGHT, 318) \
  X(MKEY_DOWN, 319) \
  X(MKEY_SELECT, 320) \
  X(MKEY_PRINT, 321) \
  X(MKEY_EXECUTE, 322) \
  X(MKEY_SNAPSHOT, 323) \
  X(MKEY_INSERT, 324) \
  X(MKEY_HELP, 325) \
  X(MKEY_NUMPAD0, 326) \
  X(MKEY_NUMPAD1, 327) \
  X(MKEY_NUMPAD2, 328) \
  X(MKEY_NUMPAD3, 329) \
  X(MKEY_NUMPAD4, 330) \
  X(MKEY_NUMPAD5, 331) \
  X(MKEY_NUMPAD6, 332) \
  X(MKEY_NUMPAD7, 333) \
  X(MKEY_NUMPAD8, 334) \
  X(MKEY_NUMPAD9, 335) \
  X(MKEY_MULTIPLY, 336) \
  X(MKEY_ADD, 337) \
  X(MKEY_SEPARATOR, 338) \
  X(MKEY_SUBTRACT, 339) \
  X(MKEY_DECIMAL, 340) \
  X(MKEY_DIVIDE, 341) \
  X(MKEY_F1, 342) \
  X(MKEY_F2, 343) \
  X(MKEY_F3, 344) \
  X(MKEY_F4, 345) \
  X(MKEY_F5, 346) \
  X(MKEY_F6, 347) \
  X(MKEY_F7, 348) \
  X(MKEY_F8, 349) \
  X(MKEY_F9, 350) \
  X(MKEY_F10, 351) \
  X(MKEY_F11, 352) \
  X(MKEY_F12, 353) \
  X(MKEY_F13, 354) \
  X(MKEY_F14, 355) \
  X(MKEY_F15, 356) \
  X(MKEY_F16, 357) \
  X(MKEY_F17, 358) \
  X(MKEY_F18, 359) \
  X(MKEY_F19, 360) \
  X(MKEY_F20, 361) \
  X(MKEY_F21, 362) \
  X(MKEY_F22, 363) \
  X(MKEY_F23, 364) \
  X(MKEY_F24, 365) \
  X(MKEY_NUMLOCK, 366) \
  X(MKEY_SCROLL, 367) \
  X(MKEY_PAGEUP, 368) \
  X(MKEY_PAGEDOWN, 369) \
  X(MKEY_NUMPAD_SPACE, 370) \
  X(MKEY_NUMPAD_TAB, 371) \
  X(MKEY_NUMPAD_ENTER, 372) \
  X(MKEY_NUMPAD_F1, 373) \
  X(MKEY_NUMPAD_F2, 374) \
  X(MKEY_NUMPAD_F3, 375) \
  X(MKEY_NUMPAD_F4, 376) \
  X(MKEY_NUMPAD_HOME, 377) \
  X(MKEY_NUMPAD_LEFT, 378) \
  X(MKEY_NUMPAD_UP, 379) \
  X(MKEY_NUMPAD_RIGHT, 380) \
  X(MKEY_NUMPAD_DOWN, 381) \
  X(MKEY_NUMPAD_PRIOR, 382) \
  X(MKEY_NUMPAD_PAGEUP, 383) \
  X(MKEY_NUMPAD_NEXT, 384) \
  X(MKEY_NUMPAD_PAGEDOWN, 385) \
  X(MKEY_NUMPAD_END, 386) \
  X(MKEY_NUMPAD_BEGIN, 387) \
  X(MKEY_NUMPAD_INSERT, 388) \
  X(MKEY_NUMPAD_DELETE, 389) \
  X(MKEY_NUMPAD_EQUAL, 390) \
  X(MKEY_NUMPAD_MULTIPLY, 391) \
  X(MKEY_NUMPAD_ADD, 392) \
  X(MKEY_NUMPAD_SEPARATOR, 393) \
  X(MKEY_NUMPAD_SUBTRACT, 394) \
  X(MKEY_NUMPAD_DECIMAL, 395) \
  X(MKEY_NUMPAD_DIVIDE, 396)

namespace moho
{
  /**
   * Owns the reflected MAUI keycode integer lanes.
   */
  enum EMauiKeyCode : std::int32_t
  {
#define MOHO_DEFINE_EMAUI_KEYCODE(name, value) name = value,
    MOHO_EMAUI_KEYCODE_LIST(MOHO_DEFINE_EMAUI_KEYCODE)
#undef MOHO_DEFINE_EMAUI_KEYCODE
  };

  static_assert(sizeof(EMauiKeyCode) == 0x4, "EMauiKeyCode size must be 0x4");

  /**
   * Owns reflected metadata for the `EMauiKeyCode` enum.
   */
  class EMauiKeyCodeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x0079CCD0 (FUN_0079CCD0, Moho::EMauiKeyCodeTypeInfo::ctor)
     *
     * What it does:
     * Preregisters the reflected `EMauiKeyCode` enum metadata.
     */
    EMauiKeyCodeTypeInfo();

    /**
     * Address: 0x0079CD60 (FUN_0079CD60, Moho::EMauiKeyCodeTypeInfo::dtr)
     *
     * What it does:
     * Scalar deleting-destructor lane for MAUI keycode enum metadata.
     */
    ~EMauiKeyCodeTypeInfo() override;

    /**
     * Address: 0x0079CD50 (FUN_0079CD50, Moho::EMauiKeyCodeTypeInfo::GetName)
     *
     * What it does:
     * Returns the reflected type label for MAUI keycode values.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0079CD30 (FUN_0079CD30, Moho::EMauiKeyCodeTypeInfo::Init)
     *
     * What it does:
     * Writes enum width, installs keycode labels, and finalizes metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x0079CD90 (FUN_0079CD90, Moho::EMauiKeyCodeTypeInfo::AddEnums)
     *
     * What it does:
     * Registers the `MKEY_` keycode name/value map in reflected enum metadata.
     */
    void AddEnums();
  };

  static_assert(sizeof(EMauiKeyCodeTypeInfo) == 0x78, "EMauiKeyCodeTypeInfo size must be 0x78");
} // namespace moho
