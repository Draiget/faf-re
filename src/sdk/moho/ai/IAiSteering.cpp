#include "moho/ai/IAiSteering.h"

using namespace moho;

gpg::RType* IAiSteering::sType = nullptr;

/**
 * Address: 0x005D1F00 (FUN_005D1F00, ??0IAiSteering@Moho@@QAE@XZ)
 * Address: 0x005D2750 (FUN_005D2750)
 *
 * What it does:
 * Initializes the IAiSteering interface base lane for derived steering
 * implementations; the second constructor lane is an equivalent alias.
 */
IAiSteering::IAiSteering() = default;

/**
 * Address: 0x005D1F10 (FUN_005D1F10, scalar deleting thunk)
 */
IAiSteering::~IAiSteering() = default;
