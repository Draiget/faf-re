#pragma once

#include "../../gpg/core/utils/BoostUtils.h"
#include "ISessionListener.h"

namespace moho
{
  class IdleUnitSelector : public ISessionListener, boost::noncopyable_::noncopyable
  {
    // Primary vftable (2 entries)
  public:
    virtual void OnIdleSelectionEvent0() = 0; // 0x8656A0 (slot 0)
    virtual void OnIdleSelectionEvent1() = 0; // 0x8656E0 (slot 1)
  };
} // namespace moho
