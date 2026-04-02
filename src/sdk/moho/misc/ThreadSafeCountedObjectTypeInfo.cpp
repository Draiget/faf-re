#include "moho/misc/ThreadSafeCountedObjectTypeInfo.h"

#include <typeinfo>

#include "moho/misc/ThreadSafeCountedObject.h"

#pragma init_seg(lib)

namespace
{
  moho::ThreadSafeCountedObjectTypeInfo gThreadSafeCountedObjectTypeInfo;
}

namespace moho
{
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

