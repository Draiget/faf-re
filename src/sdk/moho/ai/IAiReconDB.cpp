#include "moho/ai/IAiReconDB.h"

using namespace moho;

gpg::RType* IAiReconDB::sType = nullptr;

/**
 * Address: 0x005BE010 (??1IAiReconDB@Moho@@UAE@XZ)
 */
IAiReconDB::~IAiReconDB() = default;

/**
 * Address: 0x005C29C0 (FUN_005C29C0, nullsub_1553)
 *
 * What it does:
 * No-op checksum update hook in the base recon DB interface lane.
 */
void IAiReconDB::UpdateSimChecksum()
{
}
