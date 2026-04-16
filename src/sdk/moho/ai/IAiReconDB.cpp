#include "moho/ai/IAiReconDB.h"

using namespace moho;

gpg::RType* IAiReconDB::sType = nullptr;

/**
 * Address: 0x005C2320 (FUN_005C2320)
 */
IAiReconDB::IAiReconDB() = default;

/**
 * Address: 0x005BE010 (??1IAiReconDB@Moho@@UAE@XZ)
 * Address: 0x005BE020 (FUN_005BE020, scalar deleting thunk)
 *
 * What it does:
 * Executes the base interface destructor body; the associated deleting thunk
 * (`0x005BE020`) resets the IAiReconDB vtable lane and frees `this` when
 * requested by delete flags.
 */
IAiReconDB::~IAiReconDB() = default;

/**
  * Alias of FUN_005C29C0 (non-canonical helper lane).
 *
 * What it does:
 * No-op checksum update hook in the base recon DB interface lane.
 */
void IAiReconDB::UpdateSimChecksum()
{
}
