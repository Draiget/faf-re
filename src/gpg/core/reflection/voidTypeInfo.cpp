#include "gpg/core/reflection/voidTypeInfo.h"

#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

using TypeInfo = voidTypeInfo;

namespace
{
  /**
   * Address: 0x00C08FB0 (FUN_00C08FB0, atexit destructor of the voidTypeInfo object)
   */
  [[nodiscard]] TypeInfo& Acquire()
  {
    static TypeInfo sInstance;
    return sInstance;
  }

  struct Bootstrap { Bootstrap() { register_voidTypeInfoStartup(); } };
  Bootstrap gBootstrap;
}

/** Address: 0x008DF9E0 */
voidTypeInfo::voidTypeInfo() : gpg::RType()
{
  gpg::PreRegisterRType(typeid(void), this);
}

voidTypeInfo::~voidTypeInfo() = default;

/** Address: 0x008DFA60 */
const char* voidTypeInfo::GetName() const { return "void"; }

/** Address: 0x008DFA50 */
void voidTypeInfo::Init()
{
  size_ = 0;
  gpg::RType::Init();
  Finish();
}

/** Address: 0x00BE97E0 */
void register_voidTypeInfoStartup()
{
  (void)Acquire();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_voidTypeInfoStartup_e05f0b, register_voidTypeInfoStartup)
