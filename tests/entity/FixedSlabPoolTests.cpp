#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <thread>
#include <vector>

#include "moho/entity/FixedSlabPool.h"
#include "moho/entity/EntityMemoryManager.h"
#include "moho/unit/core/Unit.h"
#include "moho/sim/ReconBlip.h"
#include "moho/projectile/Projectile.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/entity/Prop.h"
#include "moho/entity/Shield.h"
#include "moho/entity/Entity.h"

#define TEST_ASSERT(cond) \
  do { \
    if (!(cond)) { \
      fprintf(stderr, "TEST ASSERTION FAILED: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
      std::abort(); \
    } \
  } while (false)

static void TestBasicAllocation()
{
  printf("Running TestBasicAllocation...\n");
  moho::FixedSlabPool pool(sizeof(moho::Projectile), 16);

  void* ptr1 = pool.Allocate();
  TEST_ASSERT(ptr1 != nullptr);
  TEST_ASSERT(reinterpret_cast<std::uintptr_t>(ptr1) % 16 == 0);
  TEST_ASSERT(moho::slab_region::Owns(ptr1));

  void* ptr2 = pool.Allocate();
  TEST_ASSERT(ptr2 != nullptr);
  TEST_ASSERT(ptr2 != ptr1);
  TEST_ASSERT(reinterpret_cast<std::uintptr_t>(ptr2) % 16 == 0);
  TEST_ASSERT(moho::slab_region::Owns(ptr2));

  pool.Deallocate(ptr1);
  void* ptr3 = pool.Allocate();
  // In LIFO free list, ptr3 should reuse ptr1
  TEST_ASSERT(ptr3 == ptr1);

  pool.Deallocate(ptr2);
  pool.Deallocate(ptr3);

  TEST_ASSERT(pool.GetAllocatedCount() == 0);
  printf("TestBasicAllocation passed.\n");
}

static void TestSlabReclamation()
{
  printf("Running TestSlabReclamation...\n");
  moho::FixedSlabPool pool(sizeof(moho::Unit), 16);

  std::vector<void*> objects;
  objects.reserve(200);

  // Allocate 200 objects (~6 slabs)
  for (int i = 0; i < 200; ++i) {
    void* p = pool.Allocate();
    TEST_ASSERT(p != nullptr);
    objects.push_back(p);
  }

  TEST_ASSERT(pool.GetAllocatedCount() == 200);
  std::size_t peakSlabs = pool.GetActiveSlabCount();
  TEST_ASSERT(peakSlabs >= 3);

  // Deallocate all objects
  for (void* p : objects) {
    pool.Deallocate(p);
  }

  TEST_ASSERT(pool.GetAllocatedCount() == 0);
  // Unused slabs should have been reclaimed to OS, keeping at most kMaxCachedEmptySlabs (2)
  TEST_ASSERT(pool.GetCachedEmptySlabCount() <= moho::FixedSlabPool::kMaxCachedEmptySlabs);
  TEST_ASSERT(pool.GetActiveSlabCount() == 0);
  printf("TestSlabReclamation passed.\n");
}

static void TestConcurrentAllocation()
{
  printf("Running TestConcurrentAllocation...\n");
  moho::FixedSlabPool pool(sizeof(moho::Shield), 16);

  constexpr int kThreads = 8;
  constexpr int kOpsPerThread = 500;
  std::vector<std::thread> threads;
  threads.reserve(kThreads);

  for (int t = 0; t < kThreads; ++t) {
    threads.emplace_back([&pool]() {
      std::vector<void*> local;
      local.reserve(kOpsPerThread);
      for (int i = 0; i < kOpsPerThread; ++i) {
        local.push_back(pool.Allocate());
      }
      for (void* p : local) {
        pool.Deallocate(p);
      }
    });
  }

  for (auto& th : threads) {
    th.join();
  }

  TEST_ASSERT(pool.GetAllocatedCount() == 0);
  printf("TestConcurrentAllocation passed.\n");
}

static void TestEntityMemoryManagerRouting()
{
  printf("Running TestEntityMemoryManagerRouting...\n");
  moho::EntityMemoryManager& mgr = moho::EntityMemoryManager::Instance();

  // Verify known sizes resolve dynamically to pools via sizeof
  TEST_ASSERT(mgr.FindPoolForSize(sizeof(moho::Unit)) != nullptr);
  TEST_ASSERT(mgr.FindPoolForSize(sizeof(moho::ReconBlip)) != nullptr);
  TEST_ASSERT(mgr.FindPoolForSize(sizeof(moho::Projectile)) != nullptr);
  TEST_ASSERT(mgr.FindPoolForSize(sizeof(moho::CollisionBeamEntity)) != nullptr);
  TEST_ASSERT(mgr.FindPoolForSize(sizeof(moho::Prop)) != nullptr);
  TEST_ASSERT(mgr.FindPoolForSize(sizeof(moho::Shield)) != nullptr);
  TEST_ASSERT(mgr.FindPoolForSize(sizeof(moho::Entity)) != nullptr);

  // Unknown size must return nullptr (fallback to global operator new)
  TEST_ASSERT(mgr.FindPoolForSize(12345) == nullptr);

  moho::sim_EntityPools = true;

  // Allocate pooled
  void* unitPtr = mgr.Allocate(sizeof(moho::Unit));
  TEST_ASSERT(unitPtr != nullptr);
  TEST_ASSERT(reinterpret_cast<std::uintptr_t>(unitPtr) % 16 == 0);
  TEST_ASSERT(moho::slab_region::Owns(unitPtr));

  // Allocate unpooled (fallback)
  void* fallbackPtr = mgr.Allocate(12345);
  TEST_ASSERT(fallbackPtr != nullptr);
  TEST_ASSERT(!moho::slab_region::Owns(fallbackPtr));

  mgr.Deallocate(unitPtr, sizeof(moho::Unit));
  mgr.Deallocate(fallbackPtr, 12345);

  TEST_ASSERT(mgr.GetTotalAllocatedCount() == 0);
  printf("TestEntityMemoryManagerRouting passed.\n");
}

static void TestHeapPointerRangeCheckSafety()
{
  printf("Running TestHeapPointerRangeCheckSafety...\n");
  moho::EntityMemoryManager& mgr = moho::EntityMemoryManager::Instance();

  // Pointer from heap
  void* heapPtr = ::operator new(1024);
  TEST_ASSERT(heapPtr != nullptr);
  TEST_ASSERT(!moho::slab_region::Owns(heapPtr));

  // Range check must safely bypass any slab header dereferencing and delete via global operator delete
  mgr.Deallocate(heapPtr, 1024);
  printf("TestHeapPointerRangeCheckSafety passed.\n");
}

static void TestClearWithLiveBlocksSafety()
{
  printf("Running TestClearWithLiveBlocksSafety...\n");
  moho::FixedSlabPool pool(sizeof(moho::Unit), 16);

  void* p1 = pool.Allocate();
  TEST_ASSERT(p1 != nullptr);
  TEST_ASSERT(pool.GetAllocatedCount() == 1);

  // Clear must NOT free active slabs containing live objects
  pool.Clear();
  TEST_ASSERT(pool.GetAllocatedCount() == 1);
  TEST_ASSERT(pool.GetActiveSlabCount() > 0);

  // Deallocate the remaining object
  pool.Deallocate(p1);
  TEST_ASSERT(pool.GetAllocatedCount() == 0);

  // Now Clear can safely free all slabs
  pool.Clear();
  TEST_ASSERT(pool.GetActiveSlabCount() == 0);
  TEST_ASSERT(pool.GetCachedEmptySlabCount() == 0);
  printf("TestClearWithLiveBlocksSafety passed.\n");
}

static void TestSwitchAndHybridSafety()
{
  printf("Running TestSwitchAndHybridSafety...\n");
  moho::EntityMemoryManager& mgr = moho::EntityMemoryManager::Instance();

  moho::sim_EntityPools = true;
  void* p1 = mgr.Allocate(sizeof(moho::Projectile));
  TEST_ASSERT(p1 != nullptr);
  TEST_ASSERT(moho::slab_region::Owns(p1));
  TEST_ASSERT(mgr.GetTotalAllocatedCount() == 1);

  // Toggle switch off mid-simulation
  moho::sim_EntityPools = false;
  void* p2 = mgr.Allocate(sizeof(moho::Projectile));
  TEST_ASSERT(p2 != nullptr);
  TEST_ASSERT(!moho::slab_region::Owns(p2));
  TEST_ASSERT(mgr.GetTotalAllocatedCount() == 1); // Pool count didn't increase

  // Deallocate p1 (must return to pool via Owns and magic check)
  mgr.Deallocate(p1, sizeof(moho::Projectile));
  TEST_ASSERT(mgr.GetTotalAllocatedCount() == 0);

  // Deallocate p2 (must return to heap via Owns == false)
  mgr.Deallocate(p2, sizeof(moho::Projectile));
  TEST_ASSERT(mgr.GetTotalAllocatedCount() == 0);

  // Default is false until replays are checked
  moho::sim_EntityPools = false;
  printf("TestSwitchAndHybridSafety passed.\n");
}

int main()
{
  printf("=== Starting Robust Entity Memory Pool Tests ===\n");
  TestBasicAllocation();
  TestSlabReclamation();
  TestConcurrentAllocation();
  TestEntityMemoryManagerRouting();
  TestHeapPointerRangeCheckSafety();
  TestClearWithLiveBlocksSafety();
  TestSwitchAndHybridSafety();
  printf("=== All Robust Entity Memory Pool Tests Passed! ===\n");
  return 0;
}
