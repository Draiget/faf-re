#include "INetConnector.h"

using namespace moho;

/**
 * Address: 0x0047EAC0 (FUN_0047EAC0)
 * Address: 0x0047EC70 (FUN_0047EC70, ctor alias lane)
 * Address: 0x0047EC80 (FUN_0047EC80, ctor alias lane)
 *
 * What it does:
 * Base constructor lane that installs the INetConnector vtable.
 */
INetConnector::INetConnector() = default;

/**
 * Address: 0x0047EAE0 (FUN_0047EAE0)
 * Address: 0x10079090 (sub_10079090)
 *
 * What it does:
 * Deleting-destructor thunk for the interface base.
 */
INetConnector::~INetConnector() = default;

/**
 * Address: 0x0047EAD0 (FUN_0047EAD0)
 * Address: 0x10079080 (sub_10079080)
 *
 * What it does:
 * Default no-op debug hook for connectors that do not override it.
 */
void INetConnector::Debug() {}
