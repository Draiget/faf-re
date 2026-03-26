#include "moho/ai/IAiAttacker.h"

using namespace moho;

gpg::RType* Broadcaster_EAiAttackerEvent::sType = nullptr;
gpg::RType* IAiAttacker::sType = nullptr;

/**
 * Address: 0x005D5780 (FUN_005D5780)
 */
IAiAttacker::~IAiAttacker()
{
  Broadcaster* const link = static_cast<Broadcaster*>(&mListeners);
  link->mPrev->mNext = link->mNext;
  link->mNext->mPrev = link->mPrev;
  link->mNext = link;
  link->mPrev = link;
}
