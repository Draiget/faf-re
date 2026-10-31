#include <cstdio>
extern "C" int FafRunAllocatorBoundsCase(const char* mode);
int main(int argc, char** argv)
{
    if (argc != 2) { std::fputs("one case required\n", stderr); return 2; }
    return FafRunAllocatorBoundsCase(argv[1]);
}
