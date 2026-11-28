// The checks of the simulation per water of a map with water bodies that need no GPU: the shore fields per domain
// against a brute-force reference, the fetch of small lakes, the window centre on several levels. The checks that run
// the compute shader are in the water lab (tools/watersimlab.py domains, docs/WATER_SIMULATION.md). Pure C++, no engine
// objects.

#include <gtest/gtest.h>

// The checks themselves are shared with the water lab (tools/watersimlab/domains_cpu.h), which also runs them next to
// the GPU checks; the code they run is the engine's (ShoreField.h, WaterDomains.h, WaterSourceGate.h), not a copy.
#include "../../tools/watersimlab/domains_cpu.h"

TEST(
  WaterDomains,
  CpuChecks
)
{
  domains::Check check;
  RunDomainsCpu(check);
  EXPECT_GT(check.ok, 0);
  EXPECT_EQ(check.failed, 0);
}
