#include "moho/misc/ThreadSafeCountedObjectTypeInfo.h"

#include <cstdlib>
#include <typeinfo>

#include "moho/misc/ThreadSafeCountedObject.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace moho
{
  void register_ThreadSafeCountedObjectTypeInfo();
}

namespace
{
  /**
   * Address: 0x00BEDFA0 (FUN_00BEDFA0, atexit destructor of the ThreadSafeCountedObjectTypeInfo object)
   */
  [[nodiscard]] moho::ThreadSafeCountedObjectTypeInfo* AcquireThreadSafeCountedObjectTypeInfo()
  {
    static moho::ThreadSafeCountedObjectTypeInfo sInstance;
    return &sInstance;
  }

  struct ThreadSafeCountedObjectTypeInfoRegistration
  {
    ThreadSafeCountedObjectTypeInfoRegistration()
    {
      moho::register_ThreadSafeCountedObjectTypeInfo();
    }
  };

  ThreadSafeCountedObjectTypeInfoRegistration gThreadSafeCountedObjectTypeInfoRegistration;
}

namespace moho
{
  /**
   * Address: 0x00BC2D60 (FUN_00BC2D60, register_ThreadSafeCountedObjectTypeInfo)
   *
   * What it does:
   * Constructs the startup `ThreadSafeCountedObjectTypeInfo` object.
   */
  void register_ThreadSafeCountedObjectTypeInfo()
  {
    (void)AcquireThreadSafeCountedObjectTypeInfo();
  }

  /**
   * Address: 0x00403470 (FUN_00403470, Moho::ThreadSafeCountedObjectTypeInfo::ThreadSafeCountedObjectTypeInfo)
   *
   * What it does:
   * Constructs the descriptor and preregisters it for `ThreadSafeCountedObject`
   * RTTI lookup.
   */
  ThreadSafeCountedObjectTypeInfo::ThreadSafeCountedObjectTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(ThreadSafeCountedObject), this);
  }

  /**
   * Address: 0x00403500 (FUN_00403500, Moho::ThreadSafeCountedObjectTypeInfo::dtr)
   */
  ThreadSafeCountedObjectTypeInfo::~ThreadSafeCountedObjectTypeInfo() = default;

  /**
   * Address: 0x004034F0 (FUN_004034F0, Moho::ThreadSafeCountedObjectTypeInfo::GetName)
   */
  const char* ThreadSafeCountedObjectTypeInfo::GetName() const
  {
    return "ThreadSafeCountedObject";
  }

  /**
   * Address: 0x004034D0 (FUN_004034D0, Moho::ThreadSafeCountedObjectTypeInfo::Init)
   */
  void ThreadSafeCountedObjectTypeInfo::Init()
  {
    size_ = sizeof(ThreadSafeCountedObject);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ThreadSafeCountedObjectTypeInfo_c782a3, moho::register_ThreadSafeCountedObjectTypeInfo)
