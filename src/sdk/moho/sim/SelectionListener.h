#pragma once
#include "../../gpg/core/utils/BoostUtils.h"
#include "ISessionListener.h"

namespace moho
{
  class SelectionListener : public ISessionListener, boost::noncopyable_::noncopyable
  {
    // Primary vftable (2 entries)
  public:
    virtual void OnSelectionEvent0() = 0; // 0x869540 (slot 0)
    virtual void OnSelectionEvent1() = 0; // 0x869580 (slot 1)
  };
} // namespace moho
