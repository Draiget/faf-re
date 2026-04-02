#pragma once
#include "../../gpg/core/utils/BoostUtils.h"
#include "ISessionListener.h"

namespace moho
{
  class PauseListener : public ISessionListener, boost::noncopyable_::noncopyable
  {
  public:
    virtual void OnPauseEvent0() = 0; // 0x869700 (slot 0)
    virtual void OnPauseEvent1() = 0; // 0x869750 (slot 1)
  };
} // namespace moho
