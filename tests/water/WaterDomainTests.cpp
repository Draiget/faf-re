// The checks of the simulation per water of a map with water bodies that need no GPU: the shore fields per domain
// against a brute-force reference, the fetch of small lakes, the window centre on several levels. The checks that run
// the compute shader are in the water lab (tools/watersimlab.py domains, docs/WATER_SIMULATION.md). Pure C++, no engine
// objects.

#include "../../tools/watersimlab/domains_cpu.h"

int main()
{
  domains::Check check;
  RunDomainsCpu(check);
  std::printf("%d checks passed, %d failed\n", check.ok, check.failed);
  return check.failed == 0 ? 0 : 1;
}
