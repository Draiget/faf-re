#include "moho/misc/ThreadSafeCountedObjectTypeInfo.h"

#include <cstdlib>
#include <typeinfo>

#include "moho/misc/ThreadSafeCountedObject.h"

#pragma init_seg(lib)

namespace moho
{
  void register_ThreadSafeCountedObjectTypeInfo();
}

namespace
{
  moho::ThreadSafeCountedObjectTypeInfo gThreadSafeCountedObjectTypeInfo;

  /**
   * Address: 0x00BEDFA0 (FUN_00BEDFA0, ??1ThreadSafeCountedObjectTypeInfo@Moho@@QAE@@Z)
   *
   * What it does:
   * Process-exit cleanup for global `ThreadSafeCountedObjectTypeInfo` dynamic
   * field/base lanes.
   */
  void cleanup_ThreadSafeCountedObjectTypeInfo()
  {
    gThreadSafeCountedObjectTypeInfo.fields_.clear();
    gThreadSafeCountedObjectTypeInfo.bases_.clear();
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
   * Materializes startup `ThreadSafeCountedObjectTypeInfo` storage and
   * registers process-exit teardown.
   */
  void register_ThreadSafeCountedObjectTypeInfo()
  {
    (void)gThreadSafeCountedObjectTypeInfo;
    (void)std::atexit(&cleanup_ThreadSafeCountedObjectTypeInfo);
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
