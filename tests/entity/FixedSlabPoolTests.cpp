#include <cassert>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <vector>

#include "moho/entity/FixedSlabPool.h"
#include "moho/entity/EntityMemoryManager.h"

static void TestBasicAllocation()
{
    printf("Running TestBasicAllocation...\n");
    moho::FixedSlabPool pool(896, 16); // Projectile-sized block

    void* ptr1 = pool.Allocate();
    assert(ptr1 != nullptr);
    assert(reinterpret_cast<std::uintptr_t>(ptr1) % 16 == 0);

    void* ptr2 = pool.Allocate();
    assert(ptr2 != nullptr);
    assert(ptr2 != ptr1);
    assert(reinterpret_cast<std::uintptr_t>(ptr2) % 16 == 0);

    pool.Deallocate(ptr1);
    void* ptr3 = pool.Allocate();
    // In LIFO free list, ptr3 should reuse ptr1
    assert(ptr3 == ptr1);

    pool.Deallocate(ptr2);
    pool.Deallocate(ptr3);

    assert(pool.GetAllocatedCount() == 0);
    printf("TestBasicAllocation passed.\n");
}

static void TestSlabReclamation()
{
    printf("Running TestSlabReclamation...\n");
    // Unit size: 1704 bytes. A 64KB slab holds ~(65536 - sizeof(SlabHeader)) / 1704 ≈ 38 blocks.
    moho::FixedSlabPool pool(1704, 16);

    std::vector<void*> objects;
    objects.reserve(200);

    // Allocate 200 objects (~6 slabs)
    for (int i = 0; i < 200; ++i) {
        void* p = pool.Allocate();
        assert(p != nullptr);
        objects.push_back(p);
    }

    assert(pool.GetAllocatedCount() == 200);
    std::size_t peakSlabs = pool.GetActiveSlabCount();
    assert(peakSlabs >= 5);

    // Deallocate all objects
    for (void* p : objects) {
        pool.Deallocate(p);
    }

    assert(pool.GetAllocatedCount() == 0);
    // Unused slabs should have been reclaimed to OS, keeping at most kMaxCachedEmptySlabs (2)
    assert(pool.GetCachedEmptySlabCount() <= moho::FixedSlabPool::kMaxCachedEmptySlabs);
    assert(pool.GetActiveSlabCount() == 0);
    printf("TestSlabReclamation passed.\n");
}

static void TestConcurrentAllocation()
{
    printf("Running TestConcurrentAllocation...\n");
    moho::FixedSlabPool pool(624, 16); // Shield size

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

    assert(pool.GetAllocatedCount() == 0);
    printf("TestConcurrentAllocation passed.\n");
}

static void TestEntityMemoryManagerRouting()
{
    printf("Running TestEntityMemoryManagerRouting...\n");
    moho::EntityMemoryManager& mgr = moho::EntityMemoryManager::Instance();

    // Verify known sizes resolve to pools
    assert(mgr.FindPoolForSize(0x6A8) != nullptr); // Unit
    assert(mgr.FindPoolForSize(0x380) != nullptr); // Projectile
    assert(mgr.FindPoolForSize(0x2A0) != nullptr); // CollisionBeamEntity
    assert(mgr.FindPoolForSize(0x288) != nullptr); // Prop
    assert(mgr.FindPoolForSize(0x280) != nullptr); // ReconBlip
    assert(mgr.FindPoolForSize(0x270) != nullptr); // Shield / Entity

    // Unknown size must return nullptr (fallback to global operator new)
    assert(mgr.FindPoolForSize(1234) == nullptr);

    // Allocate pooled
    void* unitPtr = mgr.Allocate(0x6A8);
    assert(unitPtr != nullptr);
    assert(reinterpret_cast<std::uintptr_t>(unitPtr) % 16 == 0);

    // Allocate unpooled (fallback)
    void* fallbackPtr = mgr.Allocate(1234);
    assert(fallbackPtr != nullptr);

    mgr.Deallocate(unitPtr, 0x6A8);
    mgr.Deallocate(fallbackPtr, 1234);

    assert(mgr.GetTotalAllocatedCount() == 0);
    printf("TestEntityMemoryManagerRouting passed.\n");
}

static void TestSwitchAndHybridSafety()
{
    printf("Running TestSwitchAndHybridSafety...\n");
    moho::EntityMemoryManager& mgr = moho::EntityMemoryManager::Instance();

    moho::sim_EntityPools = true;
    void* p1 = mgr.Allocate(0x380); // Allocated from slab pool
    assert(p1 != nullptr);
    assert(mgr.GetTotalAllocatedCount() == 1);

    // Toggle switch off mid-simulation
    moho::sim_EntityPools = false;
    void* p2 = mgr.Allocate(0x380); // Allocated from heap fallback
    assert(p2 != nullptr);
    assert(mgr.GetTotalAllocatedCount() == 1); // Pool count didn't increase

    // Deallocate p1 (must return to pool via magic check)
    mgr.Deallocate(p1, 0x380);
    assert(mgr.GetTotalAllocatedCount() == 0);

    // Deallocate p2 (must return to heap via fallback)
    mgr.Deallocate(p2, 0x380);
    assert(mgr.GetTotalAllocatedCount() == 0);

    // Restore switch
    moho::sim_EntityPools = true;
    printf("TestSwitchAndHybridSafety passed.\n");
}

int main()
{
    printf("=== Starting Entity Memory Pool Tests ===\n");
    TestBasicAllocation();
    TestSlabReclamation();
    TestConcurrentAllocation();
    TestEntityMemoryManagerRouting();
    TestSwitchAndHybridSafety();
    printf("=== All Entity Memory Pool Tests Passed! ===\n");
    return 0;
}
