#include "moho/ai/IAiCommandDispatch.h"

using namespace moho;

gpg::RType* IAiCommandDispatch::sType = nullptr;

/**
 * Address: 0x005989F0 (FUN_005989F0, ??0IAiCommandDispatch@Moho@@QAE@XZ)
 * Address: 0x00599110 (FUN_00599110, the same body with `this` in EAX)
 *
 * What it does:
 * Initializes one AI-command-dispatch base object with interface vtable
 * ownership. Both emissions are a single `mov [this], offset ??_7IAiCommandDispatch`
 * -- what MSVC produces for a defaulted constructor on a class whose only
 * member is its vptr -- so there is no body to write here.
 *
 * `InitializeIAiCommandDispatchInterfaceLane` used to transcribe 0x00599110 as
 * a free function over a `ListenerQueueStatusRuntimeView` stand-in, and
 * `InitializeQueueStatusListenerLane` did the same for 0x00599120. Neither had
 * a caller, and neither was source: 0x00599120 is
 * `Listener<EUnitCommandQueueStatus>::Listener()`, now annotated on the
 * template in `moho/misc/Listener.h` beside its five sibling instantiations.
 * `IAiCommandDispatchImpl` constructs both bases by name, which is what emits
 * the pair.
 */
IAiCommandDispatch::IAiCommandDispatch() = default;

/**
 * Address: 0x00598A00 (FUN_00598A00, scalar deleting thunk)
 */
IAiCommandDispatch::~IAiCommandDispatch() = default;
