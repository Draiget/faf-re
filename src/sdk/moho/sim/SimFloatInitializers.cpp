#include "moho/sim/SimFloatInitializers.h"

#include <cstdint>
#include <cmath>
#include <limits>

namespace
{
  template <int Slot>
  struct SimFloatSlot
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  template <int Slot>
  float SimFloatSlot<Slot>::pInf = 0.0f;
  template <int Slot>
  float SimFloatSlot<Slot>::nInf = 0.0f;
  template <int Slot>
  float SimFloatSlot<Slot>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<9>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<9>::pInf = 0.0f;
  float SimFloatSlot<9>::nInf = 0.0f;
  float SimFloatSlot<9>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<10>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<10>::pInf = 0.0f;
  float SimFloatSlot<10>::nInf = 0.0f;
  float SimFloatSlot<10>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<11>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<11>::pInf = 0.0f;
  float SimFloatSlot<11>::nInf = 0.0f;
  float SimFloatSlot<11>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<12>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<12>::pInf = 0.0f;
  float SimFloatSlot<12>::nInf = 0.0f;
  float SimFloatSlot<12>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<13>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<13>::pInf = 0.0f;
  float SimFloatSlot<13>::nInf = 0.0f;
  float SimFloatSlot<13>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<14>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<14>::pInf = 0.0f;
  float SimFloatSlot<14>::nInf = 0.0f;
  float SimFloatSlot<14>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<15>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<15>::pInf = 0.0f;
  float SimFloatSlot<15>::nInf = 0.0f;
  float SimFloatSlot<15>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<16>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<16>::pInf = 0.0f;
  float SimFloatSlot<16>::nInf = 0.0f;
  float SimFloatSlot<16>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<17>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<17>::pInf = 0.0f;
  float SimFloatSlot<17>::nInf = 0.0f;
  float SimFloatSlot<17>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<18>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<18>::pInf = 0.0f;
  float SimFloatSlot<18>::nInf = 0.0f;
  float SimFloatSlot<18>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<19>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<19>::pInf = 0.0f;
  float SimFloatSlot<19>::nInf = 0.0f;
  float SimFloatSlot<19>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<28>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<28>::pInf = 0.0f;
  float SimFloatSlot<28>::nInf = 0.0f;
  float SimFloatSlot<28>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<29>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<29>::pInf = 0.0f;
  float SimFloatSlot<29>::nInf = 0.0f;
  float SimFloatSlot<29>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<30>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<30>::pInf = 0.0f;
  float SimFloatSlot<30>::nInf = 0.0f;
  float SimFloatSlot<30>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<31>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<31>::pInf = 0.0f;
  float SimFloatSlot<31>::nInf = 0.0f;
  float SimFloatSlot<31>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<32>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<32>::pInf = 0.0f;
  float SimFloatSlot<32>::nInf = 0.0f;
  float SimFloatSlot<32>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<33>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<33>::pInf = 0.0f;
  float SimFloatSlot<33>::nInf = 0.0f;
  float SimFloatSlot<33>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<34>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<34>::pInf = 0.0f;
  float SimFloatSlot<34>::nInf = 0.0f;
  float SimFloatSlot<34>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<35>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<35>::pInf = 0.0f;
  float SimFloatSlot<35>::nInf = 0.0f;
  float SimFloatSlot<35>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<36>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<36>::pInf = 0.0f;
  float SimFloatSlot<36>::nInf = 0.0f;
  float SimFloatSlot<36>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<37>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<37>::pInf = 0.0f;
  float SimFloatSlot<37>::nInf = 0.0f;
  float SimFloatSlot<37>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<38>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<38>::pInf = 0.0f;
  float SimFloatSlot<38>::nInf = 0.0f;
  float SimFloatSlot<38>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<39>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<39>::pInf = 0.0f;
  float SimFloatSlot<39>::nInf = 0.0f;
  float SimFloatSlot<39>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<40>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<40>::pInf = 0.0f;
  float SimFloatSlot<40>::nInf = 0.0f;
  float SimFloatSlot<40>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<41>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<41>::pInf = 0.0f;
  float SimFloatSlot<41>::nInf = 0.0f;
  float SimFloatSlot<41>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<42>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<42>::pInf = 0.0f;
  float SimFloatSlot<42>::nInf = 0.0f;
  float SimFloatSlot<42>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<43>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<43>::pInf = 0.0f;
  float SimFloatSlot<43>::nInf = 0.0f;
  float SimFloatSlot<43>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<44>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<44>::pInf = 0.0f;
  float SimFloatSlot<44>::nInf = 0.0f;
  float SimFloatSlot<44>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<45>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<45>::pInf = 0.0f;
  float SimFloatSlot<45>::nInf = 0.0f;
  float SimFloatSlot<45>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<46>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<46>::pInf = 0.0f;
  float SimFloatSlot<46>::nInf = 0.0f;
  float SimFloatSlot<46>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<47>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<47>::pInf = 0.0f;
  float SimFloatSlot<47>::nInf = 0.0f;
  float SimFloatSlot<47>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<48>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<48>::pInf = 0.0f;
  float SimFloatSlot<48>::nInf = 0.0f;
  float SimFloatSlot<48>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<49>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<49>::pInf = 0.0f;
  float SimFloatSlot<49>::nInf = 0.0f;
  float SimFloatSlot<49>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<50>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<50>::pInf = 0.0f;
  float SimFloatSlot<50>::nInf = 0.0f;
  float SimFloatSlot<50>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<51>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<51>::pInf = 0.0f;
  float SimFloatSlot<51>::nInf = 0.0f;
  float SimFloatSlot<51>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<52>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<52>::pInf = 0.0f;
  float SimFloatSlot<52>::nInf = 0.0f;
  float SimFloatSlot<52>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<53>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<53>::pInf = 0.0f;
  float SimFloatSlot<53>::nInf = 0.0f;
  float SimFloatSlot<53>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<54>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<54>::pInf = 0.0f;
  float SimFloatSlot<54>::nInf = 0.0f;
  float SimFloatSlot<54>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<55>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<55>::pInf = 0.0f;
  float SimFloatSlot<55>::nInf = 0.0f;
  float SimFloatSlot<55>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<56>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<56>::pInf = 0.0f;
  float SimFloatSlot<56>::nInf = 0.0f;
  float SimFloatSlot<56>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<57>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<57>::pInf = 0.0f;
  float SimFloatSlot<57>::nInf = 0.0f;
  float SimFloatSlot<57>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<58>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<58>::pInf = 0.0f;
  float SimFloatSlot<58>::nInf = 0.0f;
  float SimFloatSlot<58>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<59>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<59>::pInf = 0.0f;
  float SimFloatSlot<59>::nInf = 0.0f;
  float SimFloatSlot<59>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<60>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<60>::pInf = 0.0f;
  float SimFloatSlot<60>::nInf = 0.0f;
  float SimFloatSlot<60>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<61>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<61>::pInf = 0.0f;
  float SimFloatSlot<61>::nInf = 0.0f;
  float SimFloatSlot<61>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<62>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<62>::pInf = 0.0f;
  float SimFloatSlot<62>::nInf = 0.0f;
  float SimFloatSlot<62>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<63>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<63>::pInf = 0.0f;
  float SimFloatSlot<63>::nInf = 0.0f;
  float SimFloatSlot<63>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<64>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<64>::pInf = 0.0f;
  float SimFloatSlot<64>::nInf = 0.0f;
  float SimFloatSlot<64>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<65>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<65>::pInf = 0.0f;
  float SimFloatSlot<65>::nInf = 0.0f;
  float SimFloatSlot<65>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<66>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<66>::pInf = 0.0f;
  float SimFloatSlot<66>::nInf = 0.0f;
  float SimFloatSlot<66>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<67>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<67>::pInf = 0.0f;
  float SimFloatSlot<67>::nInf = 0.0f;
  float SimFloatSlot<67>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<68>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<68>::pInf = 0.0f;
  float SimFloatSlot<68>::nInf = 0.0f;
  float SimFloatSlot<68>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<69>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<69>::pInf = 0.0f;
  float SimFloatSlot<69>::nInf = 0.0f;
  float SimFloatSlot<69>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<70>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<70>::pInf = 0.0f;
  float SimFloatSlot<70>::nInf = 0.0f;
  float SimFloatSlot<70>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<71>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<71>::pInf = 0.0f;
  float SimFloatSlot<71>::nInf = 0.0f;
  float SimFloatSlot<71>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<72>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<72>::pInf = 0.0f;
  float SimFloatSlot<72>::nInf = 0.0f;
  float SimFloatSlot<72>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<73>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<73>::pInf = 0.0f;
  float SimFloatSlot<73>::nInf = 0.0f;
  float SimFloatSlot<73>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<74>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<74>::pInf = 0.0f;
  float SimFloatSlot<74>::nInf = 0.0f;
  float SimFloatSlot<74>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<75>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<75>::pInf = 0.0f;
  float SimFloatSlot<75>::nInf = 0.0f;
  float SimFloatSlot<75>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<76>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<76>::pInf = 0.0f;
  float SimFloatSlot<76>::nInf = 0.0f;
  float SimFloatSlot<76>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<77>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<77>::pInf = 0.0f;
  float SimFloatSlot<77>::nInf = 0.0f;
  float SimFloatSlot<77>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<78>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<78>::pInf = 0.0f;
  float SimFloatSlot<78>::nInf = 0.0f;
  float SimFloatSlot<78>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<79>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<79>::pInf = 0.0f;
  float SimFloatSlot<79>::nInf = 0.0f;
  float SimFloatSlot<79>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<80>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<80>::pInf = 0.0f;
  float SimFloatSlot<80>::nInf = 0.0f;
  float SimFloatSlot<80>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<81>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<81>::pInf = 0.0f;
  float SimFloatSlot<81>::nInf = 0.0f;
  float SimFloatSlot<81>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<82>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<82>::pInf = 0.0f;
  float SimFloatSlot<82>::nInf = 0.0f;
  float SimFloatSlot<82>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<83>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<83>::pInf = 0.0f;
  float SimFloatSlot<83>::nInf = 0.0f;
  float SimFloatSlot<83>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<84>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<84>::pInf = 0.0f;
  float SimFloatSlot<84>::nInf = 0.0f;
  float SimFloatSlot<84>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<85>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<85>::pInf = 0.0f;
  float SimFloatSlot<85>::nInf = 0.0f;
  float SimFloatSlot<85>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<86>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<86>::pInf = 0.0f;
  float SimFloatSlot<86>::nInf = 0.0f;
  float SimFloatSlot<86>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<87>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<87>::pInf = 0.0f;
  float SimFloatSlot<87>::nInf = 0.0f;
  float SimFloatSlot<87>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<88>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<88>::pInf = 0.0f;
  float SimFloatSlot<88>::nInf = 0.0f;
  float SimFloatSlot<88>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<89>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<89>::pInf = 0.0f;
  float SimFloatSlot<89>::nInf = 0.0f;
  float SimFloatSlot<89>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<90>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<90>::pInf = 0.0f;
  float SimFloatSlot<90>::nInf = 0.0f;
  float SimFloatSlot<90>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<91>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<91>::pInf = 0.0f;
  float SimFloatSlot<91>::nInf = 0.0f;
  float SimFloatSlot<91>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<92>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<92>::pInf = 0.0f;
  float SimFloatSlot<92>::nInf = 0.0f;
  float SimFloatSlot<92>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<93>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<93>::pInf = 0.0f;
  float SimFloatSlot<93>::nInf = 0.0f;
  float SimFloatSlot<93>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<94>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<94>::pInf = 0.0f;
  float SimFloatSlot<94>::nInf = 0.0f;
  float SimFloatSlot<94>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<95>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<95>::pInf = 0.0f;
  float SimFloatSlot<95>::nInf = 0.0f;
  float SimFloatSlot<95>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<96>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<96>::pInf = 0.0f;
  float SimFloatSlot<96>::nInf = 0.0f;
  float SimFloatSlot<96>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<97>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<97>::pInf = 0.0f;
  float SimFloatSlot<97>::nInf = 0.0f;
  float SimFloatSlot<97>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<98>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<98>::pInf = 0.0f;
  float SimFloatSlot<98>::nInf = 0.0f;
  float SimFloatSlot<98>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<99>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<99>::pInf = 0.0f;
  float SimFloatSlot<99>::nInf = 0.0f;
  float SimFloatSlot<99>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<100>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<100>::pInf = 0.0f;
  float SimFloatSlot<100>::nInf = 0.0f;
  float SimFloatSlot<100>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<101>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<101>::pInf = 0.0f;
  float SimFloatSlot<101>::nInf = 0.0f;
  float SimFloatSlot<101>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<102>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<102>::pInf = 0.0f;
  float SimFloatSlot<102>::nInf = 0.0f;
  float SimFloatSlot<102>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<103>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<103>::pInf = 0.0f;
  float SimFloatSlot<103>::nInf = 0.0f;
  float SimFloatSlot<103>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<104>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<104>::pInf = 0.0f;
  float SimFloatSlot<104>::nInf = 0.0f;
  float SimFloatSlot<104>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<105>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<105>::pInf = 0.0f;
  float SimFloatSlot<105>::nInf = 0.0f;
  float SimFloatSlot<105>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<106>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<106>::pInf = 0.0f;
  float SimFloatSlot<106>::nInf = 0.0f;
  float SimFloatSlot<106>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<107>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<107>::pInf = 0.0f;
  float SimFloatSlot<107>::nInf = 0.0f;
  float SimFloatSlot<107>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<108>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<108>::pInf = 0.0f;
  float SimFloatSlot<108>::nInf = 0.0f;
  float SimFloatSlot<108>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<109>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<109>::pInf = 0.0f;
  float SimFloatSlot<109>::nInf = 0.0f;
  float SimFloatSlot<109>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<110>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<110>::pInf = 0.0f;
  float SimFloatSlot<110>::nInf = 0.0f;
  float SimFloatSlot<110>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<111>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<111>::pInf = 0.0f;
  float SimFloatSlot<111>::nInf = 0.0f;
  float SimFloatSlot<111>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<112>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<112>::pInf = 0.0f;
  float SimFloatSlot<112>::nInf = 0.0f;
  float SimFloatSlot<112>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<113>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<113>::pInf = 0.0f;
  float SimFloatSlot<113>::nInf = 0.0f;
  float SimFloatSlot<113>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<114>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<114>::pInf = 0.0f;
  float SimFloatSlot<114>::nInf = 0.0f;
  float SimFloatSlot<114>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<115>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<115>::pInf = 0.0f;
  float SimFloatSlot<115>::nInf = 0.0f;
  float SimFloatSlot<115>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<116>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<116>::pInf = 0.0f;
  float SimFloatSlot<116>::nInf = 0.0f;
  float SimFloatSlot<116>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<117>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<117>::pInf = 0.0f;
  float SimFloatSlot<117>::nInf = 0.0f;
  float SimFloatSlot<117>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<118>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<118>::pInf = 0.0f;
  float SimFloatSlot<118>::nInf = 0.0f;
  float SimFloatSlot<118>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<119>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<119>::pInf = 0.0f;
  float SimFloatSlot<119>::nInf = 0.0f;
  float SimFloatSlot<119>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<120>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<120>::pInf = 0.0f;
  float SimFloatSlot<120>::nInf = 0.0f;
  float SimFloatSlot<120>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<121>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<121>::pInf = 0.0f;
  float SimFloatSlot<121>::nInf = 0.0f;
  float SimFloatSlot<121>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<122>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<122>::pInf = 0.0f;
  float SimFloatSlot<122>::nInf = 0.0f;
  float SimFloatSlot<122>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<123>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<123>::pInf = 0.0f;
  float SimFloatSlot<123>::nInf = 0.0f;
  float SimFloatSlot<123>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<124>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<124>::pInf = 0.0f;
  float SimFloatSlot<124>::nInf = 0.0f;
  float SimFloatSlot<124>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<125>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<125>::pInf = 0.0f;
  float SimFloatSlot<125>::nInf = 0.0f;
  float SimFloatSlot<125>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<126>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<126>::pInf = 0.0f;
  float SimFloatSlot<126>::nInf = 0.0f;
  float SimFloatSlot<126>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<127>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<127>::pInf = 0.0f;
  float SimFloatSlot<127>::nInf = 0.0f;
  float SimFloatSlot<127>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<128>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<128>::pInf = 0.0f;
  float SimFloatSlot<128>::nInf = 0.0f;
  float SimFloatSlot<128>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<129>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<129>::pInf = 0.0f;
  float SimFloatSlot<129>::nInf = 0.0f;
  float SimFloatSlot<129>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<130>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<130>::pInf = 0.0f;
  float SimFloatSlot<130>::nInf = 0.0f;
  float SimFloatSlot<130>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<131>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<131>::pInf = 0.0f;
  float SimFloatSlot<131>::nInf = 0.0f;
  float SimFloatSlot<131>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<132>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<132>::pInf = 0.0f;
  float SimFloatSlot<132>::nInf = 0.0f;
  float SimFloatSlot<132>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<133>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<133>::pInf = 0.0f;
  float SimFloatSlot<133>::nInf = 0.0f;
  float SimFloatSlot<133>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<134>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<134>::pInf = 0.0f;
  float SimFloatSlot<134>::nInf = 0.0f;
  float SimFloatSlot<134>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<135>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<135>::pInf = 0.0f;
  float SimFloatSlot<135>::nInf = 0.0f;
  float SimFloatSlot<135>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<136>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<136>::pInf = 0.0f;
  float SimFloatSlot<136>::nInf = 0.0f;
  float SimFloatSlot<136>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<137>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<137>::pInf = 0.0f;
  float SimFloatSlot<137>::nInf = 0.0f;
  float SimFloatSlot<137>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<138>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<138>::pInf = 0.0f;
  float SimFloatSlot<138>::nInf = 0.0f;
  float SimFloatSlot<138>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<139>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<139>::pInf = 0.0f;
  float SimFloatSlot<139>::nInf = 0.0f;
  float SimFloatSlot<139>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<140>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<140>::pInf = 0.0f;
  float SimFloatSlot<140>::nInf = 0.0f;
  float SimFloatSlot<140>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<141>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<141>::pInf = 0.0f;
  float SimFloatSlot<141>::nInf = 0.0f;
  float SimFloatSlot<141>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<142>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<142>::pInf = 0.0f;
  float SimFloatSlot<142>::nInf = 0.0f;
  float SimFloatSlot<142>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<143>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<143>::pInf = 0.0f;
  float SimFloatSlot<143>::nInf = 0.0f;
  float SimFloatSlot<143>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<144>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<144>::pInf = 0.0f;
  float SimFloatSlot<144>::nInf = 0.0f;
  float SimFloatSlot<144>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<145>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<145>::pInf = 0.0f;
  float SimFloatSlot<145>::nInf = 0.0f;
  float SimFloatSlot<145>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<146>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<146>::pInf = 0.0f;
  float SimFloatSlot<146>::nInf = 0.0f;
  float SimFloatSlot<146>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<147>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<147>::pInf = 0.0f;
  float SimFloatSlot<147>::nInf = 0.0f;
  float SimFloatSlot<147>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<148>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<148>::pInf = 0.0f;
  float SimFloatSlot<148>::nInf = 0.0f;
  float SimFloatSlot<148>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<149>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<149>::pInf = 0.0f;
  float SimFloatSlot<149>::nInf = 0.0f;
  float SimFloatSlot<149>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<150>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<150>::pInf = 0.0f;
  float SimFloatSlot<150>::nInf = 0.0f;
  float SimFloatSlot<150>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<151>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<151>::pInf = 0.0f;
  float SimFloatSlot<151>::nInf = 0.0f;
  float SimFloatSlot<151>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<152>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<152>::pInf = 0.0f;
  float SimFloatSlot<152>::nInf = 0.0f;
  float SimFloatSlot<152>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<153>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<153>::pInf = 0.0f;
  float SimFloatSlot<153>::nInf = 0.0f;
  float SimFloatSlot<153>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<154>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<154>::pInf = 0.0f;
  float SimFloatSlot<154>::nInf = 0.0f;
  float SimFloatSlot<154>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<155>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<155>::pInf = 0.0f;
  float SimFloatSlot<155>::nInf = 0.0f;
  float SimFloatSlot<155>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<156>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<156>::pInf = 0.0f;
  float SimFloatSlot<156>::nInf = 0.0f;
  float SimFloatSlot<156>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<157>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<157>::pInf = 0.0f;
  float SimFloatSlot<157>::nInf = 0.0f;
  float SimFloatSlot<157>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<158>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<158>::pInf = 0.0f;
  float SimFloatSlot<158>::nInf = 0.0f;
  float SimFloatSlot<158>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<159>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<159>::pInf = 0.0f;
  float SimFloatSlot<159>::nInf = 0.0f;
  float SimFloatSlot<159>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<164>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<164>::pInf = 0.0f;
  float SimFloatSlot<164>::nInf = 0.0f;
  float SimFloatSlot<164>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<165>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<165>::pInf = 0.0f;
  float SimFloatSlot<165>::nInf = 0.0f;
  float SimFloatSlot<165>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<166>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<166>::pInf = 0.0f;
  float SimFloatSlot<166>::nInf = 0.0f;
  float SimFloatSlot<166>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<167>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<167>::pInf = 0.0f;
  float SimFloatSlot<167>::nInf = 0.0f;
  float SimFloatSlot<167>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<168>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<168>::pInf = 0.0f;
  float SimFloatSlot<168>::nInf = 0.0f;
  float SimFloatSlot<168>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<169>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<169>::pInf = 0.0f;
  float SimFloatSlot<169>::nInf = 0.0f;
  float SimFloatSlot<169>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<170>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<170>::pInf = 0.0f;
  float SimFloatSlot<170>::nInf = 0.0f;
  float SimFloatSlot<170>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<171>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<171>::pInf = 0.0f;
  float SimFloatSlot<171>::nInf = 0.0f;
  float SimFloatSlot<171>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<172>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<172>::pInf = 0.0f;
  float SimFloatSlot<172>::nInf = 0.0f;
  float SimFloatSlot<172>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<173>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<173>::pInf = 0.0f;
  float SimFloatSlot<173>::nInf = 0.0f;
  float SimFloatSlot<173>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<174>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<174>::pInf = 0.0f;
  float SimFloatSlot<174>::nInf = 0.0f;
  float SimFloatSlot<174>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<175>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<175>::pInf = 0.0f;
  float SimFloatSlot<175>::nInf = 0.0f;
  float SimFloatSlot<175>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<176>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<176>::pInf = 0.0f;
  float SimFloatSlot<176>::nInf = 0.0f;
  float SimFloatSlot<176>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<177>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<177>::pInf = 0.0f;
  float SimFloatSlot<177>::nInf = 0.0f;
  float SimFloatSlot<177>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<178>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<178>::pInf = 0.0f;
  float SimFloatSlot<178>::nInf = 0.0f;
  float SimFloatSlot<178>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<179>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<179>::pInf = 0.0f;
  float SimFloatSlot<179>::nInf = 0.0f;
  float SimFloatSlot<179>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<180>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<180>::pInf = 0.0f;
  float SimFloatSlot<180>::nInf = 0.0f;
  float SimFloatSlot<180>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<20>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<20>::pInf = 0.0f;
  float SimFloatSlot<20>::nInf = 0.0f;
  float SimFloatSlot<20>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<21>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<21>::pInf = 0.0f;
  float SimFloatSlot<21>::nInf = 0.0f;
  float SimFloatSlot<21>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<22>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<22>::pInf = 0.0f;
  float SimFloatSlot<22>::nInf = 0.0f;
  float SimFloatSlot<22>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<23>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<23>::pInf = 0.0f;
  float SimFloatSlot<23>::nInf = 0.0f;
  float SimFloatSlot<23>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<24>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<24>::pInf = 0.0f;
  float SimFloatSlot<24>::nInf = 0.0f;
  float SimFloatSlot<24>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<25>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<25>::pInf = 0.0f;
  float SimFloatSlot<25>::nInf = 0.0f;
  float SimFloatSlot<25>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<26>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<26>::pInf = 0.0f;
  float SimFloatSlot<26>::nInf = 0.0f;
  float SimFloatSlot<26>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<27>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<27>::pInf = 0.0f;
  float SimFloatSlot<27>::nInf = 0.0f;
  float SimFloatSlot<27>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<181>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<181>::pInf = 0.0f;
  float SimFloatSlot<181>::nInf = 0.0f;
  float SimFloatSlot<181>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<182>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<182>::pInf = 0.0f;
  float SimFloatSlot<182>::nInf = 0.0f;
  float SimFloatSlot<182>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<183>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<183>::pInf = 0.0f;
  float SimFloatSlot<183>::nInf = 0.0f;
  float SimFloatSlot<183>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<184>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<184>::pInf = 0.0f;
  float SimFloatSlot<184>::nInf = 0.0f;
  float SimFloatSlot<184>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<185>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<185>::pInf = 0.0f;
  float SimFloatSlot<185>::nInf = 0.0f;
  float SimFloatSlot<185>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<186>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<186>::pInf = 0.0f;
  float SimFloatSlot<186>::nInf = 0.0f;
  float SimFloatSlot<186>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<187>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<187>::pInf = 0.0f;
  float SimFloatSlot<187>::nInf = 0.0f;
  float SimFloatSlot<187>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<188>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<188>::pInf = 0.0f;
  float SimFloatSlot<188>::nInf = 0.0f;
  float SimFloatSlot<188>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<189>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<189>::pInf = 0.0f;
  float SimFloatSlot<189>::nInf = 0.0f;
  float SimFloatSlot<189>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<190>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<190>::pInf = 0.0f;
  float SimFloatSlot<190>::nInf = 0.0f;
  float SimFloatSlot<190>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<191>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<191>::pInf = 0.0f;
  float SimFloatSlot<191>::nInf = 0.0f;
  float SimFloatSlot<191>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<192>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<192>::pInf = 0.0f;
  float SimFloatSlot<192>::nInf = 0.0f;
  float SimFloatSlot<192>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<193>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<193>::pInf = 0.0f;
  float SimFloatSlot<193>::nInf = 0.0f;
  float SimFloatSlot<193>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<194>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<194>::pInf = 0.0f;
  float SimFloatSlot<194>::nInf = 0.0f;
  float SimFloatSlot<194>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<195>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<195>::pInf = 0.0f;
  float SimFloatSlot<195>::nInf = 0.0f;
  float SimFloatSlot<195>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<196>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<196>::pInf = 0.0f;
  float SimFloatSlot<196>::nInf = 0.0f;
  float SimFloatSlot<196>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<197>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<197>::pInf = 0.0f;
  float SimFloatSlot<197>::nInf = 0.0f;
  float SimFloatSlot<197>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<198>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<198>::pInf = 0.0f;
  float SimFloatSlot<198>::nInf = 0.0f;
  float SimFloatSlot<198>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<199>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<199>::pInf = 0.0f;
  float SimFloatSlot<199>::nInf = 0.0f;
  float SimFloatSlot<199>::qNaN = 0.0f;

  template <std::uintptr_t BaseAddress>
  struct TrigLaneGroup
  {
    static float cosine;
    static float sine;
    static float zeroLane0;
    static float zeroLane1;
  };
  template <std::uintptr_t BaseAddress>
  float TrigLaneGroup<BaseAddress>::cosine = 0.0f;
  template <std::uintptr_t BaseAddress>
  float TrigLaneGroup<BaseAddress>::sine = 0.0f;
  template <std::uintptr_t BaseAddress>
  float TrigLaneGroup<BaseAddress>::zeroLane0 = 0.0f;
  template <std::uintptr_t BaseAddress>
  float TrigLaneGroup<BaseAddress>::zeroLane1 = 0.0f;

#define DEFINE_TRIG_LANE_GROUP(BASE_ADDRESS) \
  template <> \
  struct TrigLaneGroup<BASE_ADDRESS> \
  { \
    static float cosine; \
    static float sine; \
    static float zeroLane0; \
    static float zeroLane1; \
  }; \
  float TrigLaneGroup<BASE_ADDRESS>::cosine = 0.0f; \
  float TrigLaneGroup<BASE_ADDRESS>::sine = 0.0f; \
  float TrigLaneGroup<BASE_ADDRESS>::zeroLane0 = 0.0f; \
  float TrigLaneGroup<BASE_ADDRESS>::zeroLane1 = 0.0f;

  DEFINE_TRIG_LANE_GROUP(0x10AD488u)
  DEFINE_TRIG_LANE_GROUP(0x10AD5C0u)
  DEFINE_TRIG_LANE_GROUP(0x10AD560u)
  DEFINE_TRIG_LANE_GROUP(0x10AD60Cu)
  DEFINE_TRIG_LANE_GROUP(0x10AD7BCu)
  DEFINE_TRIG_LANE_GROUP(0x10AE018u)
  DEFINE_TRIG_LANE_GROUP(0x10ADFF4u)
  DEFINE_TRIG_LANE_GROUP(0x10AE028u)
  DEFINE_TRIG_LANE_GROUP(0x10AE1CCu)
  DEFINE_TRIG_LANE_GROUP(0x10AE278u)
  DEFINE_TRIG_LANE_GROUP(0x10AE1DCu)
  DEFINE_TRIG_LANE_GROUP(0x10AE288u)
  DEFINE_TRIG_LANE_GROUP(0x10AE438u)
  DEFINE_TRIG_LANE_GROUP(0x10AE458u)
  DEFINE_TRIG_LANE_GROUP(0x10AE448u)
  DEFINE_TRIG_LANE_GROUP(0x10AE468u)
  DEFINE_TRIG_LANE_GROUP(0x10AE6DCu)
  DEFINE_TRIG_LANE_GROUP(0x10AE7B0u)
  DEFINE_TRIG_LANE_GROUP(0x10AE764u)
  DEFINE_TRIG_LANE_GROUP(0x10AE838u)
  DEFINE_TRIG_LANE_GROUP(0x10AEC44u)
  DEFINE_TRIG_LANE_GROUP(0x10AED90u)
  DEFINE_TRIG_LANE_GROUP(0x10AECCCu)
  DEFINE_TRIG_LANE_GROUP(0x10AEDA0u)
  DEFINE_TRIG_LANE_GROUP(0x10AEE10u)
  DEFINE_TRIG_LANE_GROUP(0x10AEEC0u)
  DEFINE_TRIG_LANE_GROUP(0x10AEEB0u)
  DEFINE_TRIG_LANE_GROUP(0x10AEED0u)
  DEFINE_TRIG_LANE_GROUP(0x10AEF64u)
  DEFINE_TRIG_LANE_GROUP(0x10AF088u)
  DEFINE_TRIG_LANE_GROUP(0x10AF078u)
  DEFINE_TRIG_LANE_GROUP(0x10AF114u)
  DEFINE_TRIG_LANE_GROUP(0x10AF144u)
  DEFINE_TRIG_LANE_GROUP(0x10AF18Cu)
  DEFINE_TRIG_LANE_GROUP(0x10AF17Cu)
  DEFINE_TRIG_LANE_GROUP(0x10AF19Cu)
  DEFINE_TRIG_LANE_GROUP(0x10AF788u)
  DEFINE_TRIG_LANE_GROUP(0x10AF8D0u)
  DEFINE_TRIG_LANE_GROUP(0x10AF8B0u)
  DEFINE_TRIG_LANE_GROUP(0x10AFA68u)
  DEFINE_TRIG_LANE_GROUP(0x10AFDC0u)
  DEFINE_TRIG_LANE_GROUP(0x10AFDF4u)
  DEFINE_TRIG_LANE_GROUP(0x10AFDE4u)
  DEFINE_TRIG_LANE_GROUP(0x10AFE04u)
  DEFINE_TRIG_LANE_GROUP(0x10AFF40u)
  DEFINE_TRIG_LANE_GROUP(0x10B026Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B01F8u)
  DEFINE_TRIG_LANE_GROUP(0x10B027Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B0964u)
  DEFINE_TRIG_LANE_GROUP(0x10B0998u)
  DEFINE_TRIG_LANE_GROUP(0x10B0974u)
  DEFINE_TRIG_LANE_GROUP(0x10B09A8u)
  DEFINE_TRIG_LANE_GROUP(0x10B09C8u)
  DEFINE_TRIG_LANE_GROUP(0x10B09FCu)
  DEFINE_TRIG_LANE_GROUP(0x10B09D8u)
  DEFINE_TRIG_LANE_GROUP(0x10B0A0Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B0AB8u)
  DEFINE_TRIG_LANE_GROUP(0x10B0BDCu)
  DEFINE_TRIG_LANE_GROUP(0x10B0B54u)
  DEFINE_TRIG_LANE_GROUP(0x10B0BECu)
  DEFINE_TRIG_LANE_GROUP(0x10B0E40u)
  DEFINE_TRIG_LANE_GROUP(0x10B0EC4u)
  DEFINE_TRIG_LANE_GROUP(0x10B0EB4u)
  DEFINE_TRIG_LANE_GROUP(0x10B0EE8u)
  DEFINE_TRIG_LANE_GROUP(0x10B105Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B1090u)
  DEFINE_TRIG_LANE_GROUP(0x10B1080u)
  DEFINE_TRIG_LANE_GROUP(0x10B10A0u)
  DEFINE_TRIG_LANE_GROUP(0x10B1124u)
  DEFINE_TRIG_LANE_GROUP(0x10B11BCu)
  DEFINE_TRIG_LANE_GROUP(0x10B11ACu)
  DEFINE_TRIG_LANE_GROUP(0x10B11E0u)
  DEFINE_TRIG_LANE_GROUP(0x10B1354u)
  DEFINE_TRIG_LANE_GROUP(0x10B13B0u)
  DEFINE_TRIG_LANE_GROUP(0x10B138Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B1424u)
  DEFINE_TRIG_LANE_GROUP(0x10B159Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B1624u)
  DEFINE_TRIG_LANE_GROUP(0x10B15ACu)
  DEFINE_TRIG_LANE_GROUP(0x10B1634u)
  DEFINE_TRIG_LANE_GROUP(0x10B16DCu)
  DEFINE_TRIG_LANE_GROUP(0x10B1774u)
  DEFINE_TRIG_LANE_GROUP(0x10B1764u)
  DEFINE_TRIG_LANE_GROUP(0x10B1784u)
  DEFINE_TRIG_LANE_GROUP(0x10B17A4u)
  DEFINE_TRIG_LANE_GROUP(0x10B183Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B182Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B184Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B186Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B197Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B18F4u)
  DEFINE_TRIG_LANE_GROUP(0x10B198Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B1F70u)
  DEFINE_TRIG_LANE_GROUP(0x10B1FF4u)
  DEFINE_TRIG_LANE_GROUP(0x10B1FA8u)
  DEFINE_TRIG_LANE_GROUP(0x10B2004u)
  DEFINE_TRIG_LANE_GROUP(0x10B19ACu)
  DEFINE_TRIG_LANE_GROUP(0x10B1A44u)
  DEFINE_TRIG_LANE_GROUP(0x10B1A34u)
  DEFINE_TRIG_LANE_GROUP(0x10B1A54u)
  DEFINE_TRIG_LANE_GROUP(0x10B1A88u)
  DEFINE_TRIG_LANE_GROUP(0x10B1AA8u)
  DEFINE_TRIG_LANE_GROUP(0x10B1A98u)
  DEFINE_TRIG_LANE_GROUP(0x10B1AB8u)
  DEFINE_TRIG_LANE_GROUP(0x10B1B50u)
  DEFINE_TRIG_LANE_GROUP(0x10B1BD4u)
  DEFINE_TRIG_LANE_GROUP(0x10B1BC4u)
  DEFINE_TRIG_LANE_GROUP(0x10B1BE4u)
  DEFINE_TRIG_LANE_GROUP(0x10B2614u)
  DEFINE_TRIG_LANE_GROUP(0x10B26BCu)
  DEFINE_TRIG_LANE_GROUP(0x10B5504u)
  DEFINE_TRIG_LANE_GROUP(0x10B559Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B5514u)
  DEFINE_TRIG_LANE_GROUP(0x10B55C0u)
  DEFINE_TRIG_LANE_GROUP(0x10B5AD8u)
  DEFINE_TRIG_LANE_GROUP(0x10B5B94u)
  DEFINE_TRIG_LANE_GROUP(0x10B5B70u)
  DEFINE_TRIG_LANE_GROUP(0x10B5BA4u)
  DEFINE_TRIG_LANE_GROUP(0x10B5DE8u)
  DEFINE_TRIG_LANE_GROUP(0x10B5E98u)
  DEFINE_TRIG_LANE_GROUP(0x10B5EBCu)
  DEFINE_TRIG_LANE_GROUP(0x10B5EE0u)
  DEFINE_TRIG_LANE_GROUP(0x10B6158u)
  DEFINE_TRIG_LANE_GROUP(0x10B6178u)
  DEFINE_TRIG_LANE_GROUP(0x10B6168u)
  DEFINE_TRIG_LANE_GROUP(0x10B7FD8u)
  DEFINE_TRIG_LANE_GROUP(0x10B85E8u)
  DEFINE_TRIG_LANE_GROUP(0x10B85D8u)
  DEFINE_TRIG_LANE_GROUP(0x10B8608u)
  DEFINE_TRIG_LANE_GROUP(0x10B61B0u)
  DEFINE_TRIG_LANE_GROUP(0x10B76D4u)
  DEFINE_TRIG_LANE_GROUP(0x10B7BD8u)
  DEFINE_TRIG_LANE_GROUP(0x10B7784u)
  DEFINE_TRIG_LANE_GROUP(0x10B7BE8u)
  DEFINE_TRIG_LANE_GROUP(0x10B4194u)
  DEFINE_TRIG_LANE_GROUP(0x10B4250u)
  DEFINE_TRIG_LANE_GROUP(0x10B4230u)
  DEFINE_TRIG_LANE_GROUP(0x10B86ECu)
  DEFINE_TRIG_LANE_GROUP(0x10B8734u)
  DEFINE_TRIG_LANE_GROUP(0x10B8724u)
  DEFINE_TRIG_LANE_GROUP(0x10B8744u)
  DEFINE_TRIG_LANE_GROUP(0x10B61E4u)
  DEFINE_TRIG_LANE_GROUP(0x10B6204u)
  DEFINE_TRIG_LANE_GROUP(0x10B61F4u)
  DEFINE_TRIG_LANE_GROUP(0x10B6214u)
  DEFINE_TRIG_LANE_GROUP(0x10B6244u)
  DEFINE_TRIG_LANE_GROUP(0x10B727Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B721Cu)
  DEFINE_TRIG_LANE_GROUP(0x10B729Cu)

#undef DEFINE_TRIG_LANE_GROUP

  template <int Slot>
  void RegisterPositiveInfinity() noexcept
  {
    SimFloatSlot<Slot>::pInf = std::numeric_limits<float>::infinity();
  }

  template <int Slot>
  void RegisterNegativeInfinity() noexcept
  {
    SimFloatSlot<Slot>::nInf = -0.0f - SimFloatSlot<Slot>::pInf;
  }

  template <int Slot>
  void RegisterQuietNaN() noexcept
  {
    SimFloatSlot<Slot>::qNaN = std::numeric_limits<float>::quiet_NaN();
  }

  template <std::uintptr_t BaseAddress>
  void RegisterTrigLaneGroup(float angle) noexcept
  {
    const float sine = std::sin(angle);

    TrigLaneGroup<BaseAddress>::cosine = std::cos(angle);
    TrigLaneGroup<BaseAddress>::sine = sine;
    TrigLaneGroup<BaseAddress>::zeroLane0 = sine * 0.0f;
    TrigLaneGroup<BaseAddress>::zeroLane1 = sine * 0.0f;
  }

  /**
   * Address: 0x00BCAED0 (FUN_00BCAED0, InitializeTrigLaneGroupSlot10AD488NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AD488NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AD488u>(-0.78539819f);
  }

  /**
   * Address: 0x00BCAF30 (FUN_00BCAF30, InitializeTrigLaneGroupSlot10AD5C0PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AD5C0PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AD5C0u>(0.78539819f);
  }

  /**
   * Address: 0x00BCAF90 (FUN_00BCAF90, InitializeTrigLaneGroupSlot10AD560NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AD560NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10AD560u>(-0.39269909f);
  }

  /**
   * Address: 0x00BCAFF0 (FUN_00BCAFF0, InitializeTrigLaneGroupSlot10AD60CPosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AD60CPosEighthPi()
  {
    RegisterTrigLaneGroup<0x10AD60Cu>(0.39269909f);
  }

  /**
   * Address: 0x00BCB540 (FUN_00BCB540, InitializeTrigLaneGroupSlot10AD7BCNegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AD7BCNegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AD7BCu>(-0.78539819f);
  }

  /**
   * Address: 0x00BCB5A0 (FUN_00BCB5A0, InitializeTrigLaneGroupSlot10AE018PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AE018PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AE018u>(0.78539819f);
  }

  /**
   * Address: 0x00BCB600 (FUN_00BCB600, InitializeTrigLaneGroupSlot10ADFF4NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10ADFF4NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10ADFF4u>(-0.39269909f);
  }

  /**
   * Address: 0x00BCB660 (FUN_00BCB660, InitializeTrigLaneGroupSlot10AE028PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AE028PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10AE028u>(0.39269909f);
  }

  /**
   * Address: 0x00BCBBD0 (FUN_00BCBBD0, InitializeTrigLaneGroupSlot10AE1CCNegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AE1CCNegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AE1CCu>(-0.78539819f);
  }

  /**
   * Address: 0x00BCBC30 (FUN_00BCBC30, InitializeTrigLaneGroupSlot10AE278PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AE278PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AE278u>(0.78539819f);
  }

  /**
   * Address: 0x00BCBC90 (FUN_00BCBC90, InitializeTrigLaneGroupSlot10AE1DCNegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AE1DCNegEighthPi()
  {
    RegisterTrigLaneGroup<0x10AE1DCu>(-0.39269909f);
  }

  /**
   * Address: 0x00BCBCF0 (FUN_00BCBCF0, InitializeTrigLaneGroupSlot10AE288PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AE288PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10AE288u>(0.39269909f);
  }

  /**
   * Address: 0x00BCBFB0 (FUN_00BCBFB0, InitializeTrigLaneGroupSlot10AE438NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AE438NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AE438u>(-0.78539819f);
  }

  /**
   * Address: 0x00BCC010 (FUN_00BCC010, InitializeTrigLaneGroupSlot10AE458PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AE458PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AE458u>(0.78539819f);
  }

  /**
   * Address: 0x00BCC070 (FUN_00BCC070, InitializeTrigLaneGroupSlot10AE448NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AE448NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10AE448u>(-0.39269909f);
  }

  /**
   * Address: 0x00BCC0D0 (FUN_00BCC0D0, InitializeTrigLaneGroupSlot10AE468PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AE468PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10AE468u>(0.39269909f);
  }

  /**
   * Address: 0x00BCC460 (FUN_00BCC460, InitializeTrigLaneGroupSlot10AE6DCNegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AE6DCNegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AE6DCu>(-0.78539819f);
  }

  /**
   * Address: 0x00BCC4C0 (FUN_00BCC4C0, InitializeTrigLaneGroupSlot10AE7B0PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AE7B0PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AE7B0u>(0.78539819f);
  }

  /**
   * Address: 0x00BCC520 (FUN_00BCC520, InitializeTrigLaneGroupSlot10AE764NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AE764NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10AE764u>(-0.39269909f);
  }

  /**
   * Address: 0x00BCC580 (FUN_00BCC580, InitializeTrigLaneGroupSlot10AE838PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AE838PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10AE838u>(0.39269909f);
  }

  /**
   * Address: 0x00BCCA70 (FUN_00BCCA70, InitializeTrigLaneGroupSlot10AEC44NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AEC44NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AEC44u>(-0.78539819f);
  }

  /**
   * Address: 0x00BCCAD0 (FUN_00BCCAD0, InitializeTrigLaneGroupSlot10AED90PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AED90PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AED90u>(0.78539819f);
  }

  /**
   * Address: 0x00BCCB30 (FUN_00BCCB30, InitializeTrigLaneGroupSlot10AECCCNegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AECCCNegEighthPi()
  {
    RegisterTrigLaneGroup<0x10AECCCu>(-0.39269909f);
  }

  /**
   * Address: 0x00BCCB90 (FUN_00BCCB90, InitializeTrigLaneGroupSlot10AEDA0PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AEDA0PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10AEDA0u>(0.39269909f);
  }

  /**
   * Address: 0x00BCCE40 (FUN_00BCCE40, InitializeTrigLaneGroupSlot10AEE10NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AEE10NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AEE10u>(-0.78539819f);
  }

  /**
   * Address: 0x00BCCEA0 (FUN_00BCCEA0, InitializeTrigLaneGroupSlot10AEEC0PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AEEC0PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AEEC0u>(0.78539819f);
  }

  /**
   * Address: 0x00BCCF00 (FUN_00BCCF00, InitializeTrigLaneGroupSlot10AEEB0NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AEEB0NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10AEEB0u>(-0.39269909f);
  }

  /**
   * Address: 0x00BCCF60 (FUN_00BCCF60, InitializeTrigLaneGroupSlot10AEED0PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AEED0PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10AEED0u>(0.39269909f);
  }

  /**
   * Address: 0x00BCD0F0 (FUN_00BCD0F0, InitializeTrigLaneGroupSlot10AEF64NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AEF64NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AEF64u>(-0.78539819f);
  }

  /**
   * Address: 0x00BCD150 (FUN_00BCD150, InitializeTrigLaneGroupSlot10AF088PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AF088PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AF088u>(0.78539819f);
  }

  /**
   * Address: 0x00BCD1B0 (FUN_00BCD1B0, InitializeTrigLaneGroupSlot10AF078NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AF078NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10AF078u>(-0.39269909f);
  }

  /**
   * Address: 0x00BCD210 (FUN_00BCD210, InitializeTrigLaneGroupSlot10AF114PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AF114PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10AF114u>(0.39269909f);
  }

  /**
   * Address: 0x00BCD420 (FUN_00BCD420, InitializeTrigLaneGroupSlot10AF144NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AF144NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AF144u>(-0.78539819f);
  }

  /**
   * Address: 0x00BCD480 (FUN_00BCD480, InitializeTrigLaneGroupSlot10AF18CPosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AF18CPosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AF18Cu>(0.78539819f);
  }

  /**
   * Address: 0x00BCD4E0 (FUN_00BCD4E0, InitializeTrigLaneGroupSlot10AF17CNegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AF17CNegEighthPi()
  {
    RegisterTrigLaneGroup<0x10AF17Cu>(-0.39269909f);
  }

  /**
   * Address: 0x00BCD540 (FUN_00BCD540, InitializeTrigLaneGroupSlot10AF19CPosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AF19CPosEighthPi()
  {
    RegisterTrigLaneGroup<0x10AF19Cu>(0.39269909f);
  }

  /**
   * Address: 0x00BCD9F0 (FUN_00BCD9F0, InitializeTrigLaneGroupSlot10AF788NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AF788NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AF788u>(-0.78539819f);
  }

  /**
   * Address: 0x00BCDA50 (FUN_00BCDA50, InitializeTrigLaneGroupSlot10AF8D0PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AF8D0PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AF8D0u>(0.78539819f);
  }

  /**
   * Address: 0x00BCDAB0 (FUN_00BCDAB0, InitializeTrigLaneGroupSlot10AF8B0NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AF8B0NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10AF8B0u>(-0.39269909f);
  }

  /**
   * Address: 0x00BCDB10 (FUN_00BCDB10, InitializeTrigLaneGroupSlot10AFA68PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AFA68PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10AFA68u>(0.39269909f);
  }

  /**
   * Address: 0x00BCE220 (FUN_00BCE220, InitializeTrigLaneGroupSlot10AFDC0NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AFDC0NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AFDC0u>(-0.78539819f);
  }

  /**
   * Address: 0x00BCE280 (FUN_00BCE280, InitializeTrigLaneGroupSlot10AFDF4PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AFDF4PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AFDF4u>(0.78539819f);
  }

  /**
   * Address: 0x00BCE2E0 (FUN_00BCE2E0, InitializeTrigLaneGroupSlot10AFDE4NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AFDE4NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10AFDE4u>(-0.39269909f);
  }

  /**
   * Address: 0x00BCE340 (FUN_00BCE340, InitializeTrigLaneGroupSlot10AFE04PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AFE04PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10AFE04u>(0.39269909f);
  }

  /**
   * Address: 0x00BCE550 (FUN_00BCE550, InitializeTrigLaneGroupSlot10AFF40NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10AFF40NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10AFF40u>(-0.78539819f);
  }

  /**
   * Address: 0x00BCE5B0 (FUN_00BCE5B0, InitializeTrigLaneGroupSlot10B026CPosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B026CPosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B026Cu>(0.78539819f);
  }

  /**
   * Address: 0x00BCE610 (FUN_00BCE610, InitializeTrigLaneGroupSlot10B01F8NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B01F8NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B01F8u>(-0.39269909f);
  }

  /**
   * Address: 0x00BCE670 (FUN_00BCE670, InitializeTrigLaneGroupSlot10B027CPosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B027CPosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B027Cu>(0.39269909f);
  }

  /**
   * Address: 0x00BCF0D0 (FUN_00BCF0D0, InitializeTrigLaneGroupSlot10B0964NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B0964NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B0964u>(-0.78539819f);
  }

  /**
   * Address: 0x00BCF130 (FUN_00BCF130, InitializeTrigLaneGroupSlot10B0998PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B0998PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B0998u>(0.78539819f);
  }

  /**
   * Address: 0x00BCF190 (FUN_00BCF190, InitializeTrigLaneGroupSlot10B0974NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B0974NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B0974u>(-0.39269909f);
  }

  /**
   * Address: 0x00BCF1F0 (FUN_00BCF1F0, InitializeTrigLaneGroupSlot10B09A8PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B09A8PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B09A8u>(0.39269909f);
  }

  /**
   * Address: 0x00BCF320 (FUN_00BCF320, InitializeTrigLaneGroupSlot10B09C8NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B09C8NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B09C8u>(-0.78539819f);
  }

  /**
   * Address: 0x00BCF380 (FUN_00BCF380, InitializeTrigLaneGroupSlot10B09FCPosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B09FCPosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B09FCu>(0.78539819f);
  }

  /**
   * Address: 0x00BCF3E0 (FUN_00BCF3E0, InitializeTrigLaneGroupSlot10B09D8NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B09D8NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B09D8u>(-0.39269909f);
  }

  /**
   * Address: 0x00BCF440 (FUN_00BCF440, InitializeTrigLaneGroupSlot10B0A0CPosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B0A0CPosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B0A0Cu>(0.39269909f);
  }

  /**
   * Address: 0x00BCF590 (FUN_00BCF590, InitializeTrigLaneGroupSlot10B0AB8NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B0AB8NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B0AB8u>(-0.78539819f);
  }

  /**
   * Address: 0x00BCF5F0 (FUN_00BCF5F0, InitializeTrigLaneGroupSlot10B0BDCPosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B0BDCPosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B0BDCu>(0.78539819f);
  }

  /**
   * Address: 0x00BCF650 (FUN_00BCF650, InitializeTrigLaneGroupSlot10B0B54NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B0B54NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B0B54u>(-0.39269909f);
  }

  /**
   * Address: 0x00BCF6B0 (FUN_00BCF6B0, InitializeTrigLaneGroupSlot10B0BECPosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B0BECPosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B0BECu>(0.39269909f);
  }

  /**
   * Address: 0x00BCFAC0 (FUN_00BCFAC0, InitializeTrigLaneGroupSlot10B0E40NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B0E40NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B0E40u>(-0.78539819f);
  }

  /**
   * Address: 0x00BCFB20 (FUN_00BCFB20, InitializeTrigLaneGroupSlot10B0EC4PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B0EC4PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B0EC4u>(0.78539819f);
  }

  /**
   * Address: 0x00BCFB80 (FUN_00BCFB80, InitializeTrigLaneGroupSlot10B0EB4NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B0EB4NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B0EB4u>(-0.39269909f);
  }

  /**
   * Address: 0x00BCFBE0 (FUN_00BCFBE0, InitializeTrigLaneGroupSlot10B0EE8PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B0EE8PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B0EE8u>(0.39269909f);
  }

  /**
   * Address: 0x00BCFE30 (FUN_00BCFE30, InitializeTrigLaneGroupSlot10B105CNegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B105CNegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B105Cu>(-0.78539819f);
  }

  /**
   * Address: 0x00BCFE90 (FUN_00BCFE90, InitializeTrigLaneGroupSlot10B1090PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1090PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B1090u>(0.78539819f);
  }

  /**
   * Address: 0x00BCFEF0 (FUN_00BCFEF0, InitializeTrigLaneGroupSlot10B1080NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1080NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B1080u>(-0.39269909f);
  }

  /**
   * Address: 0x00BCFF50 (FUN_00BCFF50, InitializeTrigLaneGroupSlot10B10A0PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B10A0PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B10A0u>(0.39269909f);
  }

  /**
   * Address: 0x00BD0080 (FUN_00BD0080, InitializeTrigLaneGroupSlot10B1124NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1124NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B1124u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD00E0 (FUN_00BD00E0, InitializeTrigLaneGroupSlot10B11BCPosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B11BCPosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B11BCu>(0.78539819f);
  }

  /**
   * Address: 0x00BD0140 (FUN_00BD0140, InitializeTrigLaneGroupSlot10B11ACNegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B11ACNegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B11ACu>(-0.39269909f);
  }

  /**
   * Address: 0x00BD01A0 (FUN_00BD01A0, InitializeTrigLaneGroupSlot10B11E0PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B11E0PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B11E0u>(0.39269909f);
  }

  /**
   * Address: 0x00BD0390 (FUN_00BD0390, InitializeTrigLaneGroupSlot10B1354NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1354NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B1354u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD03F0 (FUN_00BD03F0, InitializeTrigLaneGroupSlot10B13B0PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B13B0PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B13B0u>(0.78539819f);
  }

  /**
   * Address: 0x00BD0450 (FUN_00BD0450, InitializeTrigLaneGroupSlot10B138CNegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B138CNegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B138Cu>(-0.39269909f);
  }

  /**
   * Address: 0x00BD04B0 (FUN_00BD04B0, InitializeTrigLaneGroupSlot10B1424PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1424PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B1424u>(0.39269909f);
  }

  /**
   * Address: 0x00BD0760 (FUN_00BD0760, InitializeTrigLaneGroupSlot10B159CNegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B159CNegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B159Cu>(-0.78539819f);
  }

  /**
   * Address: 0x00BD07C0 (FUN_00BD07C0, InitializeTrigLaneGroupSlot10B1624PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1624PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B1624u>(0.78539819f);
  }

  /**
   * Address: 0x00BD0820 (FUN_00BD0820, InitializeTrigLaneGroupSlot10B15ACNegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B15ACNegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B15ACu>(-0.39269909f);
  }

  /**
   * Address: 0x00BD0880 (FUN_00BD0880, InitializeTrigLaneGroupSlot10B1634PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1634PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B1634u>(0.39269909f);
  }

  /**
   * Address: 0x00BD0A10 (FUN_00BD0A10, InitializeTrigLaneGroupSlot10B16DCNegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B16DCNegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B16DCu>(-0.78539819f);
  }

  /**
   * Address: 0x00BD0A70 (FUN_00BD0A70, InitializeTrigLaneGroupSlot10B1774PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1774PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B1774u>(0.78539819f);
  }

  /**
   * Address: 0x00BD0AD0 (FUN_00BD0AD0, InitializeTrigLaneGroupSlot10B1764NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1764NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B1764u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD0B30 (FUN_00BD0B30, InitializeTrigLaneGroupSlot10B1784PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1784PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B1784u>(0.39269909f);
  }

  /**
   * Address: 0x00BD0C60 (FUN_00BD0C60, InitializeTrigLaneGroupSlot10B17A4NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B17A4NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B17A4u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD0CC0 (FUN_00BD0CC0, InitializeTrigLaneGroupSlot10B183CPosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B183CPosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B183Cu>(0.78539819f);
  }

  /**
   * Address: 0x00BD0D20 (FUN_00BD0D20, InitializeTrigLaneGroupSlot10B182CNegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B182CNegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B182Cu>(-0.39269909f);
  }

  /**
   * Address: 0x00BD0D80 (FUN_00BD0D80, InitializeTrigLaneGroupSlot10B184CPosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B184CPosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B184Cu>(0.39269909f);
  }

  /**
   * Address: 0x00BD0EB0 (FUN_00BD0EB0, InitializeTrigLaneGroupSlot10B186CNegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B186CNegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B186Cu>(-0.78539819f);
  }

  /**
   * Address: 0x00BD0F10 (FUN_00BD0F10, InitializeTrigLaneGroupSlot10B197CPosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B197CPosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B197Cu>(0.78539819f);
  }

  /**
   * Address: 0x00BD0F70 (FUN_00BD0F70, InitializeTrigLaneGroupSlot10B18F4NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B18F4NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B18F4u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD0FD0 (FUN_00BD0FD0, InitializeTrigLaneGroupSlot10B198CPosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B198CPosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B198Cu>(0.39269909f);
  }

  /**
   * Address: 0x00BD1160 (FUN_00BD1160, InitializeTrigLaneGroupSlot10B19ACNegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B19ACNegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B19ACu>(-0.78539819f);
  }

  /**
   * Address: 0x00BD11C0 (FUN_00BD11C0, InitializeTrigLaneGroupSlot10B1A44PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1A44PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B1A44u>(0.78539819f);
  }

  /**
   * Address: 0x00BD1220 (FUN_00BD1220, InitializeTrigLaneGroupSlot10B1A34NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1A34NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B1A34u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD1280 (FUN_00BD1280, InitializeTrigLaneGroupSlot10B1A54PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1A54PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B1A54u>(0.39269909f);
  }

  /**
   * Address: 0x00BD1AB0 (FUN_00BD1AB0, InitializeTrigLaneGroupSlot10B1E94NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1E94NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B1E94u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD1B10 (FUN_00BD1B10, InitializeTrigLaneGroupSlot10B1F2CPosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1F2CPosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B1F2Cu>(0.78539819f);
  }

  /**
   * Address: 0x00BD1B70 (FUN_00BD1B70, InitializeTrigLaneGroupSlot10B1F1CNegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1F1CNegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B1F1Cu>(-0.39269909f);
  }

  /**
   * Address: 0x00BD1BD0 (FUN_00BD1BD0, InitializeTrigLaneGroupSlot10B1F3CPosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1F3CPosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B1F3Cu>(0.39269909f);
  }

  /**
   * Address: 0x00BD13F0 (FUN_00BD13F0, InitializeTrigLaneGroupSlot10B1A88NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1A88NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B1A88u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD1450 (FUN_00BD1450, InitializeTrigLaneGroupSlot10B1AA8PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1AA8PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B1AA8u>(0.78539819f);
  }

  /**
   * Address: 0x00BD14B0 (FUN_00BD14B0, InitializeTrigLaneGroupSlot10B1A98NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1A98NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B1A98u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD1510 (FUN_00BD1510, InitializeTrigLaneGroupSlot10B1AB8PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1AB8PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B1AB8u>(0.39269909f);
  }

  /**
   * Address: 0x00BD1640 (FUN_00BD1640, InitializeTrigLaneGroupSlot10B1B50NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1B50NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B1B50u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD16A0 (FUN_00BD16A0, InitializeTrigLaneGroupSlot10B1BD4PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1BD4PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B1BD4u>(0.78539819f);
  }

  /**
   * Address: 0x00BD1700 (FUN_00BD1700, InitializeTrigLaneGroupSlot10B1BC4NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1BC4NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B1BC4u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD1760 (FUN_00BD1760, InitializeTrigLaneGroupSlot10B1BE4PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1BE4PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B1BE4u>(0.39269909f);
  }

  struct SimFloatInitializersBootstrap9
  {
    SimFloatInitializersBootstrap9()
    {
      moho::register_pInf_9();
      moho::register_nInf_9();
      moho::register_NaN_9();
      moho::register_pInf_10();
      moho::register_nInf_10();
      moho::register_NaN_10();
      moho::register_pInf_11();
      moho::register_nInf_11();
      moho::register_NaN_11();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap9 gSimFloatInitializersBootstrap9;

  struct SimFloatInitializersBootstrap12
  {
    SimFloatInitializersBootstrap12()
    {
      moho::register_pInf_12();
      moho::register_nInf_12();
      moho::register_NaN_12();
      moho::register_pInf_13();
      moho::register_nInf_13();
      moho::register_NaN_13();
      moho::register_pInf_14();
      moho::register_nInf_14();
      moho::register_NaN_14();
      moho::register_pInf_15();
      moho::register_nInf_15();
      moho::register_NaN_15();
      moho::register_pInf_16();
      moho::register_nInf_16();
      moho::register_NaN_16();
      moho::register_pInf_17();
      moho::register_nInf_17();
      moho::register_NaN_17();
      moho::register_pInf_18();
      moho::register_nInf_18();
      moho::register_NaN_18();
      moho::register_pInf_19();
      moho::register_nInf_19();
      moho::register_NaN_19();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap12 gSimFloatInitializersBootstrap12;

  struct SimFloatInitializersBootstrap28
  {
    SimFloatInitializersBootstrap28()
  {
      moho::register_pInf_28();
      moho::register_nInf_28();
      moho::register_NaN_28();
      moho::register_pInf_29();
      moho::register_nInf_29();
      moho::register_NaN_29();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap28 gSimFloatInitializersBootstrap28;

  struct SimFloatInitializersBootstrap30
  {
    SimFloatInitializersBootstrap30()
    {
      moho::register_pInf_30();
      moho::register_nInf_30();
      moho::register_NaN_30();
      moho::register_pInf_31();
      moho::register_nInf_31();
      moho::register_NaN_31();
      moho::register_pInf_32();
      moho::register_nInf_32();
      moho::register_NaN_32();
      moho::register_pInf_33();
      moho::register_nInf_33();
      moho::register_NaN_33();
      moho::register_pInf_34();
      moho::register_nInf_34();
      moho::register_NaN_34();
      moho::register_pInf_35();
      moho::register_nInf_35();
      moho::register_NaN_35();
      moho::register_pInf_36();
      moho::register_nInf_36();
      moho::register_NaN_36();
      moho::register_pInf_37();
      moho::register_nInf_37();
      moho::register_NaN_37();
      moho::register_pInf_38();
      moho::register_nInf_38();
      moho::register_NaN_38();
      moho::register_pInf_39();
      moho::register_nInf_39();
      moho::register_NaN_39();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap30 gSimFloatInitializersBootstrap30;

  struct SimFloatInitializersBootstrap40
  {
    SimFloatInitializersBootstrap40()
    {
      moho::register_pInf_40();
      moho::register_nInf_40();
      moho::register_NaN_40();
      moho::register_pInf_41();
      moho::register_nInf_41();
      moho::register_NaN_41();
      moho::register_pInf_42();
      moho::register_nInf_42();
      moho::register_NaN_42();
      moho::register_pInf_43();
      moho::register_nInf_43();
      moho::register_NaN_43();
      moho::register_pInf_44();
      moho::register_nInf_44();
      moho::register_NaN_44();
      moho::register_pInf_45();
      moho::register_nInf_45();
      moho::register_NaN_45();
      moho::register_pInf_46();
      moho::register_nInf_46();
      moho::register_NaN_46();
      moho::register_pInf_47();
      moho::register_nInf_47();
      moho::register_NaN_47();
      moho::register_pInf_48();
      moho::register_nInf_48();
      moho::register_NaN_48();
      moho::register_pInf_49();
      moho::register_nInf_49();
      moho::register_NaN_49();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap40 gSimFloatInitializersBootstrap40;

  struct SimFloatInitializersBootstrap50
  {
    SimFloatInitializersBootstrap50()
    {
      moho::register_pInf_50();
      moho::register_nInf_50();
      moho::register_NaN_50();
      moho::register_pInf_51();
      moho::register_nInf_51();
      moho::register_NaN_51();
      moho::register_pInf_52();
      moho::register_nInf_52();
      moho::register_NaN_52();
      moho::register_pInf_53();
      moho::register_nInf_53();
      moho::register_NaN_53();
      moho::register_pInf_54();
      moho::register_nInf_54();
      moho::register_NaN_54();
      moho::register_pInf_55();
      moho::register_nInf_55();
      moho::register_NaN_55();
      moho::register_pInf_56();
      moho::register_nInf_56();
      moho::register_NaN_56();
      moho::register_pInf_57();
      moho::register_nInf_57();
      moho::register_NaN_57();
      moho::register_pInf_58();
      moho::register_nInf_58();
      moho::register_NaN_58();
      moho::register_pInf_59();
      moho::register_nInf_59();
      moho::register_NaN_59();
    }
  };
  [[maybe_unused]] SimFloatInitializersBootstrap50 gSimFloatInitializersBootstrap50;

  struct SimFloatInitializersBootstrap60
  {
    SimFloatInitializersBootstrap60()
    {
      moho::register_pInf_60();
      moho::register_nInf_60();
      moho::register_NaN_60();
      moho::register_pInf_61();
      moho::register_nInf_61();
      moho::register_NaN_61();
      moho::register_pInf_62();
      moho::register_nInf_62();
      moho::register_NaN_62();
      moho::register_pInf_63();
      moho::register_nInf_63();
      moho::register_NaN_63();
      moho::register_pInf_64();
      moho::register_nInf_64();
      moho::register_NaN_64();
      moho::register_pInf_65();
      moho::register_nInf_65();
      moho::register_NaN_65();
      moho::register_pInf_66();
      moho::register_nInf_66();
      moho::register_NaN_66();
      moho::register_pInf_67();
      moho::register_nInf_67();
      moho::register_NaN_67();
      moho::register_pInf_68();
      moho::register_nInf_68();
      moho::register_NaN_68();
      moho::register_pInf_69();
      moho::register_nInf_69();
      moho::register_NaN_69();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap60 gSimFloatInitializersBootstrap60;

  struct SimFloatInitializersBootstrap70
  {
    SimFloatInitializersBootstrap70()
    {
      moho::register_pInf_70();
      moho::register_nInf_70();
      moho::register_NaN_70();
      moho::register_pInf_71();
      moho::register_nInf_71();
      moho::register_NaN_71();
      moho::register_pInf_72();
      moho::register_nInf_72();
      moho::register_NaN_72();
      moho::register_pInf_73();
      moho::register_nInf_73();
      moho::register_NaN_73();
      moho::register_pInf_74();
      moho::register_nInf_74();
      moho::register_NaN_74();
      moho::register_pInf_75();
      moho::register_nInf_75();
      moho::register_NaN_75();
      moho::register_pInf_76();
      moho::register_nInf_76();
      moho::register_NaN_76();
      moho::register_pInf_77();
      moho::register_nInf_77();
      moho::register_NaN_77();
      moho::register_pInf_78();
      moho::register_nInf_78();
      moho::register_NaN_78();
      moho::register_pInf_79();
      moho::register_nInf_79();
      moho::register_NaN_79();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap70 gSimFloatInitializersBootstrap70;

  struct SimFloatInitializersBootstrap80
  {
    SimFloatInitializersBootstrap80()
    {
      moho::register_pInf_80();
      moho::register_nInf_80();
      moho::register_NaN_80();
      moho::register_pInf_81();
      moho::register_nInf_81();
      moho::register_NaN_81();
      moho::register_pInf_82();
      moho::register_nInf_82();
      moho::register_NaN_82();
      moho::register_pInf_83();
      moho::register_nInf_83();
      moho::register_NaN_83();
      moho::register_pInf_84();
      moho::register_nInf_84();
      moho::register_NaN_84();
      moho::register_pInf_85();
      moho::register_nInf_85();
      moho::register_NaN_85();
      moho::register_pInf_86();
      moho::register_nInf_86();
      moho::register_NaN_86();
      moho::register_pInf_87();
      moho::register_nInf_87();
      moho::register_NaN_87();
      moho::register_pInf_88();
      moho::register_nInf_88();
      moho::register_NaN_88();
      moho::register_pInf_89();
      moho::register_nInf_89();
      moho::register_NaN_89();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap80 gSimFloatInitializersBootstrap80;

  struct SimFloatInitializersBootstrap90
  {
    SimFloatInitializersBootstrap90()
    {
      moho::register_pInf_90();
      moho::register_nInf_90();
      moho::register_NaN_90();
      moho::register_pInf_91();
      moho::register_nInf_91();
      moho::register_NaN_91();
      moho::register_pInf_92();
      moho::register_nInf_92();
      moho::register_NaN_92();
      moho::register_pInf_93();
      moho::register_nInf_93();
      moho::register_NaN_93();
      moho::register_pInf_94();
      moho::register_nInf_94();
      moho::register_NaN_94();
      moho::register_pInf_95();
      moho::register_nInf_95();
      moho::register_NaN_95();
      moho::register_pInf_96();
      moho::register_nInf_96();
      moho::register_NaN_96();
      moho::register_pInf_97();
      moho::register_nInf_97();
      moho::register_NaN_97();
      moho::register_pInf_98();
      moho::register_nInf_98();
      moho::register_NaN_98();
      moho::register_pInf_99();
      moho::register_nInf_99();
      moho::register_NaN_99();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap90 gSimFloatInitializersBootstrap90;

  struct SimFloatInitializersBootstrap100
  {
    SimFloatInitializersBootstrap100()
    {
      moho::register_pInf_100();
      moho::register_nInf_100();
      moho::register_NaN_100();
      moho::register_pInf_101();
      moho::register_nInf_101();
      moho::register_NaN_101();
      moho::register_pInf_102();
      moho::register_nInf_102();
      moho::register_NaN_102();
      moho::register_pInf_103();
      moho::register_nInf_103();
      moho::register_NaN_103();
      InitializeTrigLaneGroupSlot10AD488NegQuarterPi();
      InitializeTrigLaneGroupSlot10AD5C0PosQuarterPi();
      InitializeTrigLaneGroupSlot10AD560NegEighthPi();
      InitializeTrigLaneGroupSlot10AD60CPosEighthPi();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap100 gSimFloatInitializersBootstrap100;

  struct SimFloatInitializersBootstrap104
  {
    SimFloatInitializersBootstrap104()
    {
      moho::register_pInf_104();
      moho::register_nInf_104();
      moho::register_NaN_104();
      InitializeTrigLaneGroupSlot10AD7BCNegQuarterPi();
      InitializeTrigLaneGroupSlot10AE018PosQuarterPi();
      InitializeTrigLaneGroupSlot10ADFF4NegEighthPi();
      InitializeTrigLaneGroupSlot10AE028PosEighthPi();
      moho::register_pInf_105();
      moho::register_nInf_105();
      moho::register_NaN_105();
      InitializeTrigLaneGroupSlot10AE1CCNegQuarterPi();
      InitializeTrigLaneGroupSlot10AE278PosQuarterPi();
      InitializeTrigLaneGroupSlot10AE1DCNegEighthPi();
      InitializeTrigLaneGroupSlot10AE288PosEighthPi();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap104 gSimFloatInitializersBootstrap104;

  struct SimFloatInitializersBootstrap106
  {
    SimFloatInitializersBootstrap106()
    {
      moho::register_pInf_106();
      moho::register_nInf_106();
      moho::register_NaN_106();
      moho::register_pInf_107();
      moho::register_nInf_107();
      moho::register_NaN_107();
      InitializeTrigLaneGroupSlot10AE438NegQuarterPi();
      InitializeTrigLaneGroupSlot10AE458PosQuarterPi();
      InitializeTrigLaneGroupSlot10AE448NegEighthPi();
      InitializeTrigLaneGroupSlot10AE468PosEighthPi();
      moho::register_pInf_108();
      moho::register_nInf_108();
      moho::register_NaN_108();
      moho::register_pInf_109();
      moho::register_nInf_109();
      moho::register_NaN_109();
      moho::register_pInf_110();
      moho::register_nInf_110();
      moho::register_NaN_110();
      InitializeTrigLaneGroupSlot10AE6DCNegQuarterPi();
      InitializeTrigLaneGroupSlot10AE7B0PosQuarterPi();
      InitializeTrigLaneGroupSlot10AE764NegEighthPi();
      InitializeTrigLaneGroupSlot10AE838PosEighthPi();
      moho::register_pInf_111();
      moho::register_nInf_111();
      moho::register_NaN_111();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap106 gSimFloatInitializersBootstrap106;

  struct SimFloatInitializersBootstrap112
  {
    SimFloatInitializersBootstrap112()
    {
      moho::register_pInf_112();
      moho::register_nInf_112();
      moho::register_NaN_112();
      InitializeTrigLaneGroupSlot10AEC44NegQuarterPi();
      InitializeTrigLaneGroupSlot10AED90PosQuarterPi();
      InitializeTrigLaneGroupSlot10AECCCNegEighthPi();
      InitializeTrigLaneGroupSlot10AEDA0PosEighthPi();
      moho::register_pInf_113();
      moho::register_nInf_113();
      moho::register_NaN_113();
      InitializeTrigLaneGroupSlot10AEE10NegQuarterPi();
      InitializeTrigLaneGroupSlot10AEEC0PosQuarterPi();
      InitializeTrigLaneGroupSlot10AEEB0NegEighthPi();
      InitializeTrigLaneGroupSlot10AEED0PosEighthPi();
      moho::register_pInf_114();
      moho::register_nInf_114();
      moho::register_NaN_114();
      InitializeTrigLaneGroupSlot10AEF64NegQuarterPi();
      InitializeTrigLaneGroupSlot10AF088PosQuarterPi();
      InitializeTrigLaneGroupSlot10AF078NegEighthPi();
      InitializeTrigLaneGroupSlot10AF114PosEighthPi();
      moho::register_pInf_115();
      moho::register_nInf_115();
      moho::register_NaN_115();
      InitializeTrigLaneGroupSlot10AF144NegQuarterPi();
      InitializeTrigLaneGroupSlot10AF18CPosQuarterPi();
      InitializeTrigLaneGroupSlot10AF17CNegEighthPi();
      InitializeTrigLaneGroupSlot10AF19CPosEighthPi();
      moho::register_pInf_116();
      moho::register_nInf_116();
      moho::register_NaN_116();
      InitializeTrigLaneGroupSlot10AF788NegQuarterPi();
      InitializeTrigLaneGroupSlot10AF8D0PosQuarterPi();
      InitializeTrigLaneGroupSlot10AF8B0NegEighthPi();
      InitializeTrigLaneGroupSlot10AFA68PosEighthPi();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap112 gSimFloatInitializersBootstrap112;

  struct SimFloatInitializersBootstrap117
  {
    SimFloatInitializersBootstrap117()
    {
      moho::register_pInf_117();
      moho::register_nInf_117();
      moho::register_NaN_117();
      moho::register_pInf_118();
      moho::register_nInf_118();
      moho::register_NaN_118();
      InitializeTrigLaneGroupSlot10AFDC0NegQuarterPi();
      InitializeTrigLaneGroupSlot10AFDF4PosQuarterPi();
      InitializeTrigLaneGroupSlot10AFDE4NegEighthPi();
      InitializeTrigLaneGroupSlot10AFE04PosEighthPi();
      moho::register_pInf_119();
      moho::register_nInf_119();
      moho::register_NaN_119();
      InitializeTrigLaneGroupSlot10AFF40NegQuarterPi();
      InitializeTrigLaneGroupSlot10B026CPosQuarterPi();
      InitializeTrigLaneGroupSlot10B01F8NegEighthPi();
      InitializeTrigLaneGroupSlot10B027CPosEighthPi();
      moho::register_pInf_120();
      moho::register_nInf_120();
      moho::register_NaN_120();
      moho::register_pInf_121();
      moho::register_nInf_121();
      moho::register_NaN_121();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap117 gSimFloatInitializersBootstrap117;

  struct SimFloatInitializersBootstrap122
  {
    SimFloatInitializersBootstrap122()
    {
      moho::register_pInf_122();
      moho::register_nInf_122();
      moho::register_NaN_122();
      InitializeTrigLaneGroupSlot10B0964NegQuarterPi();
      InitializeTrigLaneGroupSlot10B0998PosQuarterPi();
      InitializeTrigLaneGroupSlot10B0974NegEighthPi();
      InitializeTrigLaneGroupSlot10B09A8PosEighthPi();
      moho::register_pInf_123();
      moho::register_nInf_123();
      moho::register_NaN_123();
      InitializeTrigLaneGroupSlot10B09C8NegQuarterPi();
      InitializeTrigLaneGroupSlot10B09FCPosQuarterPi();
      InitializeTrigLaneGroupSlot10B09D8NegEighthPi();
      InitializeTrigLaneGroupSlot10B0A0CPosEighthPi();
      moho::register_pInf_124();
      moho::register_nInf_124();
      moho::register_NaN_124();
      InitializeTrigLaneGroupSlot10B0AB8NegQuarterPi();
      InitializeTrigLaneGroupSlot10B0BDCPosQuarterPi();
      InitializeTrigLaneGroupSlot10B0B54NegEighthPi();
      InitializeTrigLaneGroupSlot10B0BECPosEighthPi();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap122 gSimFloatInitializersBootstrap122;

  struct SimFloatInitializersBootstrap125
  {
    SimFloatInitializersBootstrap125()
    {
      moho::register_pInf_125();
      moho::register_nInf_125();
      moho::register_NaN_125();
      InitializeTrigLaneGroupSlot10B0E40NegQuarterPi();
      InitializeTrigLaneGroupSlot10B0EC4PosQuarterPi();
      InitializeTrigLaneGroupSlot10B0EB4NegEighthPi();
      InitializeTrigLaneGroupSlot10B0EE8PosEighthPi();
      moho::register_pInf_126();
      moho::register_nInf_126();
      moho::register_NaN_126();
      InitializeTrigLaneGroupSlot10B105CNegQuarterPi();
      InitializeTrigLaneGroupSlot10B1090PosQuarterPi();
      InitializeTrigLaneGroupSlot10B1080NegEighthPi();
      InitializeTrigLaneGroupSlot10B10A0PosEighthPi();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap125 gSimFloatInitializersBootstrap125;

  struct SimFloatInitializersBootstrap127
  {
    SimFloatInitializersBootstrap127()
    {
      moho::register_pInf_127();
      moho::register_nInf_127();
      moho::register_NaN_127();
      InitializeTrigLaneGroupSlot10B1124NegQuarterPi();
      InitializeTrigLaneGroupSlot10B11BCPosQuarterPi();
      InitializeTrigLaneGroupSlot10B11ACNegEighthPi();
      InitializeTrigLaneGroupSlot10B11E0PosEighthPi();
      moho::register_pInf_128();
      moho::register_nInf_128();
      moho::register_NaN_128();
      InitializeTrigLaneGroupSlot10B1354NegQuarterPi();
      InitializeTrigLaneGroupSlot10B13B0PosQuarterPi();
      InitializeTrigLaneGroupSlot10B138CNegEighthPi();
      InitializeTrigLaneGroupSlot10B1424PosEighthPi();
      moho::register_pInf_129();
      moho::register_nInf_129();
      moho::register_NaN_129();
      InitializeTrigLaneGroupSlot10B159CNegQuarterPi();
      InitializeTrigLaneGroupSlot10B1624PosQuarterPi();
      InitializeTrigLaneGroupSlot10B15ACNegEighthPi();
      InitializeTrigLaneGroupSlot10B1634PosEighthPi();
      moho::register_pInf_130();
      moho::register_nInf_130();
      moho::register_NaN_130();
      InitializeTrigLaneGroupSlot10B16DCNegQuarterPi();
      InitializeTrigLaneGroupSlot10B1774PosQuarterPi();
      InitializeTrigLaneGroupSlot10B1764NegEighthPi();
      InitializeTrigLaneGroupSlot10B1784PosEighthPi();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap127 gSimFloatInitializersBootstrap127;

  struct SimFloatInitializersBootstrap131
  {
    SimFloatInitializersBootstrap131()
    {
      moho::register_pInf_131();
      moho::register_nInf_131();
      moho::register_NaN_131();
      InitializeTrigLaneGroupSlot10B17A4NegQuarterPi();
      InitializeTrigLaneGroupSlot10B183CPosQuarterPi();
      InitializeTrigLaneGroupSlot10B182CNegEighthPi();
      InitializeTrigLaneGroupSlot10B184CPosEighthPi();
      moho::register_pInf_132();
      moho::register_nInf_132();
      moho::register_NaN_132();
      InitializeTrigLaneGroupSlot10B186CNegQuarterPi();
      InitializeTrigLaneGroupSlot10B197CPosQuarterPi();
      InitializeTrigLaneGroupSlot10B18F4NegEighthPi();
      InitializeTrigLaneGroupSlot10B198CPosEighthPi();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap131 gSimFloatInitializersBootstrap131;

  struct SimFloatInitializersBootstrap133
  {
    SimFloatInitializersBootstrap133()
  {
      moho::register_pInf_133();
      moho::register_nInf_133();
      moho::register_NaN_133();
      InitializeTrigLaneGroupSlot10B19ACNegQuarterPi();
      InitializeTrigLaneGroupSlot10B1A44PosQuarterPi();
      InitializeTrigLaneGroupSlot10B1A34NegEighthPi();
      InitializeTrigLaneGroupSlot10B1A54PosEighthPi();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap133 gSimFloatInitializersBootstrap133;

  struct SimFloatInitializersBootstrap134
  {
    SimFloatInitializersBootstrap134()
    {
      moho::register_pInf_134();
      moho::register_nInf_134();
      moho::register_NaN_134();
      moho::register_pInf_135();
      moho::register_nInf_135();
      moho::register_NaN_135();
      moho::register_pInf_136();
      moho::register_nInf_136();
      moho::register_NaN_136();
      moho::register_pInf_137();
      moho::register_nInf_137();
      moho::register_NaN_137();
      InitializeTrigLaneGroupSlot10B1A88NegQuarterPi();
      InitializeTrigLaneGroupSlot10B1AA8PosQuarterPi();
      InitializeTrigLaneGroupSlot10B1A98NegEighthPi();
      InitializeTrigLaneGroupSlot10B1AB8PosEighthPi();
      InitializeTrigLaneGroupSlot10B1B50NegQuarterPi();
      InitializeTrigLaneGroupSlot10B1BD4PosQuarterPi();
      InitializeTrigLaneGroupSlot10B1BC4NegEighthPi();
      InitializeTrigLaneGroupSlot10B1BE4PosEighthPi();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap134 gSimFloatInitializersBootstrap134;

  struct SimFloatInitializersBootstrapEarly
  {
    SimFloatInitializersBootstrapEarly()
    {
      moho::register_pInf_138();
      moho::register_nInf_138();
      moho::register_NaN_138();
      InitializeTrigLaneGroupSlot10B1E94NegQuarterPi();
      InitializeTrigLaneGroupSlot10B1F2CPosQuarterPi();
      InitializeTrigLaneGroupSlot10B1F1CNegEighthPi();
      InitializeTrigLaneGroupSlot10B1F3CPosEighthPi();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrapEarly gSimFloatInitializersBootstrapEarly;

  /**
   * Address: 0x00BD1DE0 (FUN_00BD1DE0, InitializeTrigLaneGroupSlot10B1F70NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1F70NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B1F70u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD1E40 (FUN_00BD1E40, InitializeTrigLaneGroupSlot10B1FF4PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1FF4PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B1FF4u>(0.78539819f);
  }

  /**
   * Address: 0x00BD1EA0 (FUN_00BD1EA0, InitializeTrigLaneGroupSlot10B1FA8NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B1FA8NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B1FA8u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD1F00 (FUN_00BD1F00, InitializeTrigLaneGroupSlot10B2004PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B2004PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B2004u>(0.39269909f);
  }

  /**
   * Address: 0x00BD2840 (FUN_00BD2840, sub_BD2840)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B2614NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B2614u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD28A0 (FUN_00BD28A0, sub_BD28A0)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B26BCPosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B26BCu>(0.78539819f);
  }

  /**
   * Address: 0x00BD2900 (FUN_00BD2900, sub_BD2900)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B26ACNegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B26ACu>(-0.39269909f);
  }

  /**
   * Address: 0x00BD2960 (FUN_00BD2960, sub_BD2960)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B26CCPosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B26CCu>(0.39269909f);
  }

  /**
   * Address: 0x00BD32E0 (FUN_00BD32E0, sub_BD32E0)
   *
   * What it does:
   * Initializes a -pi/4 trig lane group with cosine/sine values and zeroed
   * companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B2E70NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B2E70u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD3340 (FUN_00BD3340, sub_BD3340)
   *
   * What it does:
   * Initializes a +pi/4 trig lane group with cosine/sine values and zeroed
   * companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B2F68PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B2F68u>(0.78539819f);
  }

  /**
   * Address: 0x00BD33A0 (FUN_00BD33A0, sub_BD33A0)
   *
   * What it does:
   * Initializes a -pi/8 trig lane group with cosine/sine values and zeroed
   * companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B2F58NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B2F58u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD3400 (FUN_00BD3400, sub_BD3400)
   *
   * What it does:
   * Initializes a +pi/8 trig lane group with cosine/sine values and zeroed
   * companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B2FDCPosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B2FDCu>(0.39269909f);
  }

  /**
   * Address: 0x00BD4A20 (FUN_00BD4A20, sub_BD4A20)
   *
   * What it does:
   * Initializes an earliest -pi/4 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B4194NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B4194u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD4A80 (FUN_00BD4A80, sub_BD4A80)
   *
   * What it does:
   * Initializes an earliest +pi/4 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B4250PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B4250u>(0.78539819f);
  }

  /**
   * Address: 0x00BD4AE0 (FUN_00BD4AE0, sub_BD4AE0)
   *
   * What it does:
   * Initializes an earliest -pi/8 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B4230NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B4230u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD6170 (FUN_00BD6170, InitializeTrigLaneGroupSlot10B5504NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group used alongside slot 177 startup.
   */
  void InitializeTrigLaneGroupSlot10B5504NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B5504u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD61D0 (FUN_00BD61D0, InitializeTrigLaneGroupSlot10B559CPosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group used alongside slot 177 startup.
   */
  void InitializeTrigLaneGroupSlot10B559CPosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B559Cu>(0.78539819f);
  }

  /**
   * Address: 0x00BD6230 (FUN_00BD6230, InitializeTrigLaneGroupSlot10B5514NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group used alongside slot 177 startup.
   */
  void InitializeTrigLaneGroupSlot10B5514NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B5514u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD6290 (FUN_00BD6290, InitializeTrigLaneGroupSlot10B55C0PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group used alongside slot 177 startup.
   */
  void InitializeTrigLaneGroupSlot10B55C0PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B55C0u>(0.39269909f);
  }

  /**
   * Address: 0x00BD6870 (FUN_00BD6870, InitializeTrigLaneGroupSlot10B5AD8NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group used alongside slot 180 startup.
   */
  void InitializeTrigLaneGroupSlot10B5AD8NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B5AD8u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD68D0 (FUN_00BD68D0, InitializeTrigLaneGroupSlot10B5B94PosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group used alongside slot 180 startup.
   */
  void InitializeTrigLaneGroupSlot10B5B94PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B5B94u>(0.78539819f);
  }

  /**
   * Address: 0x00BD6930 (FUN_00BD6930, InitializeTrigLaneGroupSlot10B5B70NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group used alongside slot 180 startup.
   */
  void InitializeTrigLaneGroupSlot10B5B70NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B5B70u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD6990 (FUN_00BD6990, InitializeTrigLaneGroupSlot10B5BA4PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group used alongside slot 180 startup.
   */
  void InitializeTrigLaneGroupSlot10B5BA4PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B5BA4u>(0.39269909f);
  }

  /**
   * Address: 0x00BD6DE0 (FUN_00BD6DE0, InitializeTrigLaneGroupSlot10B5DE8NegQuarterPi)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group used alongside slot 181 startup.
   */
  void InitializeTrigLaneGroupSlot10B5DE8NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B5DE8u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD6E40 (FUN_00BD6E40, InitializeTrigLaneGroupSlot10B5EBCPosQuarterPi)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group used alongside slot 181 startup.
   */
  void InitializeTrigLaneGroupSlot10B5EBCPosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B5EBCu>(0.78539819f);
  }

  /**
   * Address: 0x00BD6EA0 (FUN_00BD6EA0, InitializeTrigLaneGroupSlot10B5E98NegEighthPi)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group used alongside slot 181 startup.
   */
  void InitializeTrigLaneGroupSlot10B5E98NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B5E98u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD6F00 (FUN_00BD6F00, InitializeTrigLaneGroupSlot10B5EE0PosEighthPi)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group used alongside slot 181 startup.
   */
  void InitializeTrigLaneGroupSlot10B5EE0PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B5EE0u>(0.39269909f);
  }

  /**
   * Address: 0x00BD7330 (FUN_00BD7330, InitializeTrigLaneGroupSlot10B6158NegQuarterPi)
   *
   * What it does:
   * Initializes the earliest -pi/4 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B6158NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B6158u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD7390 (FUN_00BD7390, InitializeTrigLaneGroupSlot10B6178PosQuarterPi)
   *
   * What it does:
   * Initializes the earliest +pi/4 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B6178PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B6178u>(0.78539819f);
  }

  /**
   * Address: 0x00BD73F0 (FUN_00BD73F0, InitializeTrigLaneGroupSlot10B6168NegEighthPi)
   *
   * What it does:
   * Initializes the earliest -pi/8 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B6168NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B6168u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD7450 (FUN_00BD7450, InitializeTrigLaneGroupSlot10B61B0PosEighthPi)
   *
   * What it does:
   * Initializes the earliest +pi/8 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B61B0PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B61B0u>(0.39269909f);
  }

  /**
   * Address: 0x00BD75A0 (FUN_00BD75A0, sub_BD75A0)
   *
   * What it does:
   * Initializes an early -pi/4 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B61E4NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B61E4u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD7600 (FUN_00BD7600, sub_BD7600)
   *
   * What it does:
   * Initializes an early +pi/4 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B6204PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B6204u>(0.78539819f);
  }

  /**
   * Address: 0x00BD7660 (FUN_00BD7660, sub_BD7660)
   *
   * What it does:
   * Initializes an early -pi/8 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B61F4NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B61F4u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD76C0 (FUN_00BD76C0, sub_BD76C0)
   *
   * What it does:
   * Initializes an early +pi/8 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B6214PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B6214u>(0.39269909f);
  }

  /**
   * Address: 0x00BD7790 (FUN_00BD7790, sub_BD7790)
   *
   * What it does:
   * Initializes an early -pi/4 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B6244NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B6244u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD77F0 (FUN_00BD77F0, sub_BD77F0)
   *
   * What it does:
   * Initializes an early +pi/4 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B727CPosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B727Cu>(0.78539819f);
  }

  /**
   * Address: 0x00BD7850 (FUN_00BD7850, sub_BD7850)
   *
   * What it does:
   * Initializes an early -pi/8 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B721CNegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B721Cu>(-0.39269909f);
  }

  /**
   * Address: 0x00BD78B0 (FUN_00BD78B0, sub_BD78B0)
   *
   * What it does:
   * Initializes the earliest +pi/8 trig lane group with cosine/sine values and
   * zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B729CPosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B729Cu>(0.39269909f);
  }

  /**
   * Address: 0x00BD8590 (FUN_00BD8590, sub_BD8590)
   *
   * What it does:
   * Initializes the early -pi/4 trig lane group for slot set 187.
   */
  void InitializeTrigLaneGroupSlot10B76D4NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B76D4u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD85F0 (FUN_00BD85F0, sub_BD85F0)
   *
   * What it does:
   * Initializes the early +pi/4 trig lane group for slot set 187.
   */
  void InitializeTrigLaneGroupSlot10B7BD8PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B7BD8u>(0.78539819f);
  }

  /**
   * Address: 0x00BD8650 (FUN_00BD8650, sub_BD8650)
   *
   * What it does:
   * Initializes the early -pi/8 trig lane group for slot set 187.
   */
  void InitializeTrigLaneGroupSlot10B7784NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B7784u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD86B0 (FUN_00BD86B0, sub_BD86B0)
   *
   * What it does:
   * Initializes the early +pi/8 trig lane group for slot set 187.
   */
  void InitializeTrigLaneGroupSlot10B7BE8PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B7BE8u>(0.39269909f);
  }

  /**
   * Address: 0x00BD90E0 (FUN_00BD90E0, sub_BD90E0)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B7FD8NegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B7FD8u>(-0.78539819f);
  }

  /**
   * Address: 0x00BD9140 (FUN_00BD9140, sub_BD9140)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B85E8PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B85E8u>(0.78539819f);
  }

  /**
   * Address: 0x00BD91A0 (FUN_00BD91A0, sub_BD91A0)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B85D8NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B85D8u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD9200 (FUN_00BD9200, sub_BD9200)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B8608PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B8608u>(0.39269909f);
  }

  /**
   * Address: 0x00BD9680 (FUN_00BD9680, sub_BD9680)
   *
   * What it does:
   * Initializes the -pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B86ECNegQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B86ECu>(-0.78539819f);
  }

  /**
   * Address: 0x00BD96E0 (FUN_00BD96E0, sub_BD96E0)
   *
   * What it does:
   * Initializes the +pi/4 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B8734PosQuarterPi()
  {
    RegisterTrigLaneGroup<0x10B8734u>(0.78539819f);
  }

  /**
   * Address: 0x00BD9740 (FUN_00BD9740, sub_BD9740)
   *
   * What it does:
   * Initializes the -pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B8724NegEighthPi()
  {
    RegisterTrigLaneGroup<0x10B8724u>(-0.39269909f);
  }

  /**
   * Address: 0x00BD97A0 (FUN_00BD97A0, sub_BD97A0)
   *
   * What it does:
   * Initializes the +pi/8 trig lane group with cosine/sine values and zeroed companion lanes.
   */
  void InitializeTrigLaneGroupSlot10B8744PosEighthPi()
  {
    RegisterTrigLaneGroup<0x10B8744u>(0.39269909f);
  }

  struct SimFloatInitializersBootstrapA
  {
    SimFloatInitializersBootstrapA()
    {
      moho::register_pInf_139();
      moho::register_nInf_139();
      moho::register_NaN_139();
      InitializeTrigLaneGroupSlot10B1F70NegQuarterPi();
      InitializeTrigLaneGroupSlot10B1FF4PosQuarterPi();
      InitializeTrigLaneGroupSlot10B1FA8NegEighthPi();
      InitializeTrigLaneGroupSlot10B2004PosEighthPi();
      moho::register_pInf_140();
      moho::register_nInf_140();
      moho::register_NaN_140();
      moho::register_pInf_141();
      moho::register_nInf_141();
      moho::register_NaN_141();
      moho::register_pInf_142();
      moho::register_nInf_142();
      moho::register_NaN_142();
      moho::register_pInf_143();
      moho::register_nInf_143();
      moho::register_NaN_143();
      moho::register_pInf_144();
      moho::register_nInf_144();
      moho::register_NaN_144();
      moho::register_pInf_145();
      moho::register_nInf_145();
      moho::register_NaN_145();
      InitializeTrigLaneGroupSlot10B2614NegQuarterPi();
      InitializeTrigLaneGroupSlot10B26BCPosQuarterPi();
      InitializeTrigLaneGroupSlot10B26ACNegEighthPi();
      InitializeTrigLaneGroupSlot10B26CCPosEighthPi();
      moho::register_pInf_146();
      moho::register_nInf_146();
      moho::register_NaN_146();
      moho::register_pInf_147();
      moho::register_nInf_147();
      moho::register_NaN_147();
      moho::register_pInf_148();
      moho::register_nInf_148();
      moho::register_NaN_148();
      moho::register_pInf_149();
      moho::register_nInf_149();
      moho::register_NaN_149();
      moho::register_pInf_150();
      moho::register_nInf_150();
      moho::register_NaN_150();
      InitializeTrigLaneGroupSlot10B2E70NegQuarterPi();
      InitializeTrigLaneGroupSlot10B2F68PosQuarterPi();
      InitializeTrigLaneGroupSlot10B2F58NegEighthPi();
      InitializeTrigLaneGroupSlot10B2FDCPosEighthPi();
      moho::register_pInf_151();
      moho::register_nInf_151();
      moho::register_NaN_151();
      moho::register_pInf_152();
      moho::register_nInf_152();
      moho::register_NaN_152();
      moho::register_pInf_153();
      moho::register_nInf_153();
      moho::register_NaN_153();
      moho::register_pInf_154();
      moho::register_nInf_154();
      moho::register_NaN_154();
      moho::register_pInf_155();
      moho::register_nInf_155();
      moho::register_NaN_155();
      moho::register_pInf_156();
      moho::register_nInf_156();
      moho::register_NaN_156();
      moho::register_pInf_157();
      moho::register_nInf_157();
      moho::register_NaN_157();
      moho::register_pInf_158();
      moho::register_nInf_158();
      moho::register_NaN_158();
      moho::register_pInf_159();
      moho::register_nInf_159();
      moho::register_NaN_159();
      moho::register_pInf_160();
      moho::register_nInf_160();
      moho::register_NaN_160();
      moho::register_pInf_161();
      moho::register_nInf_161();
      moho::register_NaN_161();
      moho::register_pInf_164();
      moho::register_nInf_164();
      moho::register_NaN_164();
      moho::register_pInf_165();
      moho::register_nInf_165();
      moho::register_NaN_165();
      moho::register_pInf_166();
      moho::register_nInf_166();
      moho::register_NaN_166();
      InitializeTrigLaneGroupSlot10B4194NegQuarterPi();
      InitializeTrigLaneGroupSlot10B4250PosQuarterPi();
      InitializeTrigLaneGroupSlot10B4230NegEighthPi();
      moho::register_pInf_162();
      moho::register_nInf_162();
      moho::register_NaN_162();
      moho::register_pInf_163();
      moho::register_nInf_163();
      moho::register_NaN_163();
      moho::register_pInf_167();
      moho::register_nInf_167();
      moho::register_NaN_167();
      moho::register_pInf_168();
      moho::register_nInf_168();
      moho::register_NaN_168();
      moho::register_pInf_169();
      moho::register_nInf_169();
      moho::register_NaN_169();
      moho::register_pInf_170();
      moho::register_nInf_170();
      moho::register_NaN_170();
      moho::register_pInf_171();
      moho::register_nInf_171();
      moho::register_NaN_171();
      moho::register_pInf_172();
      moho::register_nInf_172();
      moho::register_NaN_172();
      moho::register_pInf_173();
      moho::register_nInf_173();
      moho::register_NaN_173();
      moho::register_pInf_174();
      moho::register_nInf_174();
      moho::register_NaN_174();
      moho::register_pInf_175();
      moho::register_nInf_175();
      moho::register_NaN_175();
      moho::register_pInf_176();
      moho::register_nInf_176();
      moho::register_NaN_176();
      moho::register_pInf_177();
      moho::register_nInf_177();
      moho::register_NaN_177();
      InitializeTrigLaneGroupSlot10B5504NegQuarterPi();
      InitializeTrigLaneGroupSlot10B559CPosQuarterPi();
      InitializeTrigLaneGroupSlot10B5514NegEighthPi();
      InitializeTrigLaneGroupSlot10B55C0PosEighthPi();
      moho::register_pInf_178();
      moho::register_nInf_178();
      moho::register_NaN_178();
      moho::register_pInf_179();
      moho::register_nInf_179();
      moho::register_NaN_179();
      moho::register_pInf_180();
      moho::register_nInf_180();
      moho::register_NaN_180();
      InitializeTrigLaneGroupSlot10B5AD8NegQuarterPi();
      InitializeTrigLaneGroupSlot10B5B94PosQuarterPi();
      InitializeTrigLaneGroupSlot10B5B70NegEighthPi();
      InitializeTrigLaneGroupSlot10B5BA4PosEighthPi();
      moho::register_pInf_20();
      moho::register_nInf_20();
      moho::register_NaN_20();
      moho::register_pInf_21();
      moho::register_nInf_21();
      moho::register_NaN_21();
      moho::register_pInf_22();
      moho::register_nInf_22();
      moho::register_NaN_22();
      moho::register_pInf_23();
      moho::register_nInf_23();
      moho::register_NaN_23();
      moho::register_pInf_24();
      moho::register_nInf_24();
      moho::register_NaN_24();
      moho::register_pInf_25();
      moho::register_nInf_25();
      moho::register_NaN_25();
      moho::register_pInf_26();
      moho::register_nInf_26();
      moho::register_NaN_26();
      moho::register_pInf_27();
      moho::register_nInf_27();
      moho::register_NaN_27();
      moho::register_pInf_181();
      moho::register_nInf_181();
      moho::register_NaN_181();
      InitializeTrigLaneGroupSlot10B5DE8NegQuarterPi();
      InitializeTrigLaneGroupSlot10B5EBCPosQuarterPi();
      InitializeTrigLaneGroupSlot10B5E98NegEighthPi();
      InitializeTrigLaneGroupSlot10B5EE0PosEighthPi();
      moho::register_pInf_182();
      moho::register_nInf_182();
      moho::register_NaN_182();

      moho::register_pInf_183();
      moho::register_nInf_183();
      moho::register_NaN_183();
      InitializeTrigLaneGroupSlot10B6158NegQuarterPi();
      InitializeTrigLaneGroupSlot10B6178PosQuarterPi();
      InitializeTrigLaneGroupSlot10B6168NegEighthPi();
      InitializeTrigLaneGroupSlot10B61B0PosEighthPi();
      moho::register_pInf_184();
      moho::register_nInf_184();
      moho::register_NaN_184();
      InitializeTrigLaneGroupSlot10B61E4NegQuarterPi();
      InitializeTrigLaneGroupSlot10B6204PosQuarterPi();
      InitializeTrigLaneGroupSlot10B61F4NegEighthPi();
      InitializeTrigLaneGroupSlot10B6214PosEighthPi();
      moho::register_pInf_185();
      moho::register_nInf_185();
      moho::register_NaN_185();
      InitializeTrigLaneGroupSlot10B6244NegQuarterPi();
      InitializeTrigLaneGroupSlot10B727CPosQuarterPi();
      InitializeTrigLaneGroupSlot10B721CNegEighthPi();
      InitializeTrigLaneGroupSlot10B729CPosEighthPi();
      moho::register_pInf_186();
      moho::register_nInf_186();
      moho::register_NaN_186();
      moho::register_pInf_187();
      moho::register_nInf_187();
      moho::register_NaN_187();
      InitializeTrigLaneGroupSlot10B76D4NegQuarterPi();
      InitializeTrigLaneGroupSlot10B7BD8PosQuarterPi();
      InitializeTrigLaneGroupSlot10B7784NegEighthPi();
      InitializeTrigLaneGroupSlot10B7BE8PosEighthPi();
      moho::register_pInf_188();
      moho::register_nInf_188();
      moho::register_NaN_188();
      moho::register_pInf_189();
      moho::register_nInf_189();
      moho::register_NaN_189();
      moho::register_pInf_190();
      moho::register_nInf_190();
      moho::register_NaN_190();
      moho::register_pInf_191();
      moho::register_nInf_191();
      moho::register_NaN_191();
      moho::register_pInf_192();
      moho::register_nInf_192();
      moho::register_NaN_192();
      moho::register_pInf_193();
      moho::register_nInf_193();
      moho::register_NaN_193();
      InitializeTrigLaneGroupSlot10B7FD8NegQuarterPi();
      InitializeTrigLaneGroupSlot10B85E8PosQuarterPi();
      InitializeTrigLaneGroupSlot10B85D8NegEighthPi();
      InitializeTrigLaneGroupSlot10B8608PosEighthPi();
      moho::register_pInf_194();
      moho::register_nInf_194();
      moho::register_NaN_194();
      InitializeTrigLaneGroupSlot10B86ECNegQuarterPi();
      InitializeTrigLaneGroupSlot10B8734PosQuarterPi();
      InitializeTrigLaneGroupSlot10B8724NegEighthPi();
      InitializeTrigLaneGroupSlot10B8744PosEighthPi();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrapA gSimFloatInitializersBootstrapA;

  struct SimFloatInitializersBootstrap
  {
    SimFloatInitializersBootstrap()
    {
      moho::register_pInf_195();
      moho::register_nInf_195();
      moho::register_NaN_195();
      moho::register_pInf_196();
      moho::register_nInf_196();
      moho::register_NaN_196();
      moho::register_pInf_197();
      moho::register_nInf_197();
      moho::register_NaN_197();
      moho::register_pInf_198();
      moho::register_nInf_198();
      moho::register_NaN_198();
      moho::register_pInf_199();
      moho::register_nInf_199();
      moho::register_NaN_199();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap gSimFloatInitializersBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BC2C80 (FUN_00BC2C80, register_pInf_9)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 9.
   */
  void register_pInf_9()
  {
    RegisterPositiveInfinity<9>();
  }

  /**
   * Address: 0x00BC2CA0 (FUN_00BC2CA0, register_nInf_9)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 9 from `pInf_9`.
   */
  void register_nInf_9()
  {
    RegisterNegativeInfinity<9>();
  }

  /**
   * Address: 0x00BC2CC0 (FUN_00BC2CC0, register_NaN_9)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 9.
   */
  void register_NaN_9()
  {
    RegisterQuietNaN<9>();
  }

  /**
   * Address: 0x00BC2DE0 (FUN_00BC2DE0, register_pInf_10)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 10.
   */
  void register_pInf_10()
  {
    RegisterPositiveInfinity<10>();
  }

  /**
   * Address: 0x00BC2E00 (FUN_00BC2E00, register_nInf_10)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 10 from `pInf_10`.
   */
  void register_nInf_10()
  {
    RegisterNegativeInfinity<10>();
  }

  /**
   * Address: 0x00BC2E20 (FUN_00BC2E20, register_NaN_10)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 10.
   */
  void register_NaN_10()
  {
    RegisterQuietNaN<10>();
  }

  /**
   * Address: 0x00BC2E40 (FUN_00BC2E40, register_pInf_11)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 11.
   */
  void register_pInf_11()
  {
    RegisterPositiveInfinity<11>();
  }

  /**
   * Address: 0x00BC2E60 (FUN_00BC2E60, register_nInf_11)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 11 from `pInf_11`.
   */
  void register_nInf_11()
  {
    RegisterNegativeInfinity<11>();
  }

  /**
   * Address: 0x00BC2E80 (FUN_00BC2E80, register_NaN_11)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 11.
   */
  void register_NaN_11()
  {
    RegisterQuietNaN<11>();
  }

  /**
   * Address: 0x00BC3140 (FUN_00BC3140, register_pInf_12)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 12.
   */
  void register_pInf_12()
  {
    RegisterPositiveInfinity<12>();
  }

  /**
   * Address: 0x00BC3160 (FUN_00BC3160, register_nInf_12)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 12 from `pInf_12`.
   */
  void register_nInf_12()
  {
    RegisterNegativeInfinity<12>();
  }

  /**
   * Address: 0x00BC3180 (FUN_00BC3180, register_NaN_12)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 12.
   */
  void register_NaN_12()
  {
    RegisterQuietNaN<12>();
  }

  /**
   * Address: 0x00BC31A0 (FUN_00BC31A0, register_pInf_13)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 13.
   */
  void register_pInf_13()
  {
    RegisterPositiveInfinity<13>();
  }

  /**
   * Address: 0x00BC31C0 (FUN_00BC31C0, register_nInf_13)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 13 from `pInf_13`.
   */
  void register_nInf_13()
  {
    RegisterNegativeInfinity<13>();
  }

  /**
   * Address: 0x00BC31E0 (FUN_00BC31E0, register_NaN_13)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 13.
   */
  void register_NaN_13()
  {
    RegisterQuietNaN<13>();
  }

  /**
   * Address: 0x00BC3200 (FUN_00BC3200, register_pInf_14)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 14.
   */
  void register_pInf_14()
  {
    RegisterPositiveInfinity<14>();
  }

  /**
   * Address: 0x00BC3220 (FUN_00BC3220, register_nInf_14)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 14 from `pInf_14`.
   */
  void register_nInf_14()
  {
    RegisterNegativeInfinity<14>();
  }

  /**
   * Address: 0x00BC3240 (FUN_00BC3240, register_NaN_14)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 14.
   */
  void register_NaN_14()
  {
    RegisterQuietNaN<14>();
  }

  /**
   * Address: 0x00BC33E0 (FUN_00BC33E0, register_pInf_15)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 15.
   */
  void register_pInf_15()
  {
    RegisterPositiveInfinity<15>();
  }

  /**
   * Address: 0x00BC3400 (FUN_00BC3400, register_nInf_15)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 15 from `pInf_15`.
   */
  void register_nInf_15()
  {
    RegisterNegativeInfinity<15>();
  }

  /**
   * Address: 0x00BC3420 (FUN_00BC3420, register_NaN_15)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 15.
   */
  void register_NaN_15()
  {
    RegisterQuietNaN<15>();
  }

  /**
   * Address: 0x00BC3570 (FUN_00BC3570, register_pInf_16)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 16.
   */
  void register_pInf_16()
  {
    RegisterPositiveInfinity<16>();
  }

  /**
   * Address: 0x00BC3590 (FUN_00BC3590, register_nInf_16)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 16 from `pInf_16`.
   */
  void register_nInf_16()
  {
    RegisterNegativeInfinity<16>();
  }

  /**
   * Address: 0x00BC35B0 (FUN_00BC35B0, register_NaN_16)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 16.
   */
  void register_NaN_16()
  {
    RegisterQuietNaN<16>();
  }

  /**
   * Address: 0x00BC3720 (FUN_00BC3720, register_pInf_17)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 17.
   */
  void register_pInf_17()
  {
    RegisterPositiveInfinity<17>();
  }

  /**
   * Address: 0x00BC3740 (FUN_00BC3740, register_nInf_17)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 17 from `pInf_17`.
   */
  void register_nInf_17()
  {
    RegisterNegativeInfinity<17>();
  }

  /**
   * Address: 0x00BC3760 (FUN_00BC3760, register_NaN_17)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 17.
   */
  void register_NaN_17()
  {
    RegisterQuietNaN<17>();
  }

  /**
   * Address: 0x00BC3790 (FUN_00BC3790, register_pInf_18)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 18.
   */
  void register_pInf_18()
  {
    RegisterPositiveInfinity<18>();
  }

  /**
   * Address: 0x00BC37B0 (FUN_00BC37B0, register_nInf_18)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 18 from `pInf_18`.
   */
  void register_nInf_18()
  {
    RegisterNegativeInfinity<18>();
  }

  /**
   * Address: 0x00BC37D0 (FUN_00BC37D0, register_NaN_18)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 18.
   */
  void register_NaN_18()
  {
    RegisterQuietNaN<18>();
  }

  /**
   * Address: 0x00BC3820 (FUN_00BC3820, register_pInf_19)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 19.
   */
  void register_pInf_19()
  {
    RegisterPositiveInfinity<19>();
  }

  /**
   * Address: 0x00BC3840 (FUN_00BC3840, register_nInf_19)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 19 from `pInf_19`.
   */
  void register_nInf_19()
  {
    RegisterNegativeInfinity<19>();
  }

  /**
   * Address: 0x00BC3860 (FUN_00BC3860, register_NaN_19)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 19.
   */
  void register_NaN_19()
  {
    RegisterQuietNaN<19>();
  }

  /**
   * Address: 0x00BC4470 (FUN_00BC4470, register_pInf_28)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 28.
   */
  void register_pInf_28()
  {
    RegisterPositiveInfinity<28>();
  }

  /**
   * Address: 0x00BC4490 (FUN_00BC4490, register_nInf_28)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 28 from `pInf_28`.
   */
  void register_nInf_28()
  {
    RegisterNegativeInfinity<28>();
  }

  /**
   * Address: 0x00BC44B0 (FUN_00BC44B0, register_NaN_28)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 28.
   */
  void register_NaN_28()
  {
    RegisterQuietNaN<28>();
  }

  /**
   * Address: 0x00BC44F0 (FUN_00BC44F0, register_pInf_29)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 29.
   */
  void register_pInf_29()
  {
    RegisterPositiveInfinity<29>();
  }

  /**
   * Address: 0x00BC4510 (FUN_00BC4510, register_nInf_29)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 29 from `pInf_29`.
   */
  void register_nInf_29()
  {
    RegisterNegativeInfinity<29>();
  }

  /**
   * Address: 0x00BC4530 (FUN_00BC4530, register_NaN_29)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 29.
   */
  void register_NaN_29()
  {
    RegisterQuietNaN<29>();
  }

  /**
   * Address: 0x00BC4550 (FUN_00BC4550, register_pInf_30)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 30.
   */
  void register_pInf_30()
  {
    RegisterPositiveInfinity<30>();
  }

  /**
   * Address: 0x00BC4570 (FUN_00BC4570, register_nInf_30)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 30 from `pInf_30`.
   */
  void register_nInf_30()
  {
    RegisterNegativeInfinity<30>();
  }

  /**
   * Address: 0x00BC4590 (FUN_00BC4590, register_NaN_30)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 30.
   */
  void register_NaN_30()
  {
    RegisterQuietNaN<30>();
  }

  /**
   * Address: 0x00BC4620 (FUN_00BC4620, register_pInf_31)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 31.
   */
  void register_pInf_31()
  {
    RegisterPositiveInfinity<31>();
  }

  /**
   * Address: 0x00BC4640 (FUN_00BC4640, register_nInf_31)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 31 from `pInf_31`.
   */
  void register_nInf_31()
  {
    RegisterNegativeInfinity<31>();
  }

  /**
   * Address: 0x00BC4660 (FUN_00BC4660, register_NaN_31)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 31.
   */
  void register_NaN_31()
  {
    RegisterQuietNaN<31>();
  }

  /**
   * Address: 0x00BC46B0 (FUN_00BC46B0, register_pInf_32)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 32.
   */
  void register_pInf_32()
  {
    RegisterPositiveInfinity<32>();
  }

  /**
   * Address: 0x00BC46D0 (FUN_00BC46D0, register_nInf_32)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 32 from `pInf_32`.
   */
  void register_nInf_32()
  {
    RegisterNegativeInfinity<32>();
  }

  /**
   * Address: 0x00BC46F0 (FUN_00BC46F0, register_NaN_32)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 32.
   */
  void register_NaN_32()
  {
    RegisterQuietNaN<32>();
  }

  /**
   * Address: 0x00BC4710 (FUN_00BC4710, register_pInf_33)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 33.
   */
  void register_pInf_33()
  {
    RegisterPositiveInfinity<33>();
  }

  /**
   * Address: 0x00BC4730 (FUN_00BC4730, register_nInf_33)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 33 from `pInf_33`.
   */
  void register_nInf_33()
  {
    RegisterNegativeInfinity<33>();
  }

  /**
   * Address: 0x00BC4750 (FUN_00BC4750, register_NaN_33)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 33.
   */
  void register_NaN_33()
  {
    RegisterQuietNaN<33>();
  }

  /**
   * Address: 0x00BC4780 (FUN_00BC4780, register_pInf_34)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 34.
   */
  void register_pInf_34()
  {
    RegisterPositiveInfinity<34>();
  }

  /**
   * Address: 0x00BC47A0 (FUN_00BC47A0, register_nInf_34)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 34 from `pInf_34`.
   */
  void register_nInf_34()
  {
    RegisterNegativeInfinity<34>();
  }

  /**
   * Address: 0x00BC47C0 (FUN_00BC47C0, register_NaN_34)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 34.
   */
  void register_NaN_34()
  {
    RegisterQuietNaN<34>();
  }

  /**
   * Address: 0x00BC48F0 (FUN_00BC48F0, register_pInf_35)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 35.
   */
  void register_pInf_35()
  {
    RegisterPositiveInfinity<35>();
  }

  /**
   * Address: 0x00BC4910 (FUN_00BC4910, register_nInf_35)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 35 from `pInf_35`.
   */
  void register_nInf_35()
  {
    RegisterNegativeInfinity<35>();
  }

  /**
   * Address: 0x00BC4930 (FUN_00BC4930, register_NaN_35)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 35.
   */
  void register_NaN_35()
  {
    RegisterQuietNaN<35>();
  }

  /**
   * Address: 0x00BC49C0 (FUN_00BC49C0, register_pInf_36)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 36.
   */
  void register_pInf_36()
  {
    RegisterPositiveInfinity<36>();
  }

  /**
   * Address: 0x00BC49E0 (FUN_00BC49E0, register_nInf_36)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 36 from `pInf_36`.
   */
  void register_nInf_36()
  {
    RegisterNegativeInfinity<36>();
  }

  /**
   * Address: 0x00BC4A00 (FUN_00BC4A00, register_NaN_36)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 36.
   */
  void register_NaN_36()
  {
    RegisterQuietNaN<36>();
  }

  /**
   * Address: 0x00BC4A90 (FUN_00BC4A90, register_pInf_37)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 37.
   */
  void register_pInf_37()
  {
    RegisterPositiveInfinity<37>();
  }

  /**
   * Address: 0x00BC4AB0 (FUN_00BC4AB0, register_nInf_37)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 37 from `pInf_37`.
   */
  void register_nInf_37()
  {
    RegisterNegativeInfinity<37>();
  }

  /**
   * Address: 0x00BC4AD0 (FUN_00BC4AD0, register_NaN_37)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 37.
   */
  void register_NaN_37()
  {
    RegisterQuietNaN<37>();
  }

  /**
   * Address: 0x00BC4AF0 (FUN_00BC4AF0, register_pInf_38)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 38.
   */
  void register_pInf_38()
  {
    RegisterPositiveInfinity<38>();
  }

  /**
   * Address: 0x00BC4B10 (FUN_00BC4B10, register_nInf_38)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 38 from `pInf_38`.
   */
  void register_nInf_38()
  {
    RegisterNegativeInfinity<38>();
  }

  /**
   * Address: 0x00BC4B30 (FUN_00BC4B30, register_NaN_38)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 38.
   */
  void register_NaN_38()
  {
    RegisterQuietNaN<38>();
  }

  /**
   * Address: 0x00BC4CF0 (FUN_00BC4CF0, register_pInf_39)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 39.
   */
  void register_pInf_39()
  {
    RegisterPositiveInfinity<39>();
  }

  /**
   * Address: 0x00BC4D10 (FUN_00BC4D10, register_nInf_39)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 39 from `pInf_39`.
   */
  void register_nInf_39()
  {
    RegisterNegativeInfinity<39>();
  }

  /**
   * Address: 0x00BC4D30 (FUN_00BC4D30, register_NaN_39)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 39.
   */
  void register_NaN_39()
  {
    RegisterQuietNaN<39>();
  }

  /**
   * Address: 0x00BC4DB0 (FUN_00BC4DB0, register_pInf_40)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 40.
   */
  void register_pInf_40()
  {
    RegisterPositiveInfinity<40>();
  }

  /**
   * Address: 0x00BC4DD0 (FUN_00BC4DD0, register_nInf_40)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 40 from `pInf_40`.
   */
  void register_nInf_40()
  {
    RegisterNegativeInfinity<40>();
  }

  /**
   * Address: 0x00BC4DF0 (FUN_00BC4DF0, register_NaN_40)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 40.
   */
  void register_NaN_40()
  {
    RegisterQuietNaN<40>();
  }

  /**
   * Address: 0x00BC4E10 (FUN_00BC4E10, register_pInf_41)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 41.
   */
  void register_pInf_41()
  {
    RegisterPositiveInfinity<41>();
  }

  /**
   * Address: 0x00BC4E30 (FUN_00BC4E30, register_nInf_41)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 41 from `pInf_41`.
   */
  void register_nInf_41()
  {
    RegisterNegativeInfinity<41>();
  }

  /**
   * Address: 0x00BC4E50 (FUN_00BC4E50, register_NaN_41)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 41.
   */
  void register_NaN_41()
  {
    RegisterQuietNaN<41>();
  }

  /**
   * Address: 0x00BC5180 (FUN_00BC5180, register_pInf_42)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 42.
   */
  void register_pInf_42()
  {
    RegisterPositiveInfinity<42>();
  }

  /**
   * Address: 0x00BC51A0 (FUN_00BC51A0, register_nInf_42)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 42 from `pInf_42`.
   */
  void register_nInf_42()
  {
    RegisterNegativeInfinity<42>();
  }

  /**
   * Address: 0x00BC51C0 (FUN_00BC51C0, register_NaN_42)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 42.
   */
  void register_NaN_42()
  {
    RegisterQuietNaN<42>();
  }

  /**
   * Address: 0x00BC51E0 (FUN_00BC51E0, register_pInf_43)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 43.
   */
  void register_pInf_43()
  {
    RegisterPositiveInfinity<43>();
  }

  /**
   * Address: 0x00BC5200 (FUN_00BC5200, register_nInf_43)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 43 from `pInf_43`.
   */
  void register_nInf_43()
  {
    RegisterNegativeInfinity<43>();
  }

  /**
   * Address: 0x00BC5220 (FUN_00BC5220, register_NaN_43)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 43.
   */
  void register_NaN_43()
  {
    RegisterQuietNaN<43>();
  }

  /**
   * Address: 0x00BC54C0 (FUN_00BC54C0, register_pInf_44)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 44.
   */
  void register_pInf_44()
  {
    RegisterPositiveInfinity<44>();
  }

  /**
   * Address: 0x00BC54E0 (FUN_00BC54E0, register_nInf_44)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 44 from `pInf_44`.
   */
  void register_nInf_44()
  {
    RegisterNegativeInfinity<44>();
  }

  /**
   * Address: 0x00BC5500 (FUN_00BC5500, register_NaN_44)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 44.
   */
  void register_NaN_44()
  {
    RegisterQuietNaN<44>();
  }

  /**
   * Address: 0x00BC5900 (FUN_00BC5900, register_pInf_45)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 45.
   */
  void register_pInf_45()
  {
    RegisterPositiveInfinity<45>();
  }

  /**
   * Address: 0x00BC5920 (FUN_00BC5920, register_nInf_45)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 45 from `pInf_45`.
   */
  void register_nInf_45()
  {
    RegisterNegativeInfinity<45>();
  }

  /**
   * Address: 0x00BC5940 (FUN_00BC5940, register_NaN_45)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 45.
   */
  void register_NaN_45()
  {
    RegisterQuietNaN<45>();
  }

  /**
   * Address: 0x00BC5C20 (FUN_00BC5C20, register_pInf_46)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 46.
   */
  void register_pInf_46()
  {
    RegisterPositiveInfinity<46>();
  }

  /**
   * Address: 0x00BC5C40 (FUN_00BC5C40, register_nInf_46)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 46 from `pInf_46`.
   */
  void register_nInf_46()
  {
    RegisterNegativeInfinity<46>();
  }

  /**
   * Address: 0x00BC5C60 (FUN_00BC5C60, register_NaN_46)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 46.
   */
  void register_NaN_46()
  {
    RegisterQuietNaN<46>();
  }

  /**
   * Address: 0x00BC5CE0 (FUN_00BC5CE0, register_pInf_47)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 47.
   */
  void register_pInf_47()
  {
    RegisterPositiveInfinity<47>();
  }

  /**
   * Address: 0x00BC5D00 (FUN_00BC5D00, register_nInf_47)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 47 from `pInf_47`.
   */
  void register_nInf_47()
  {
    RegisterNegativeInfinity<47>();
  }

  /**
   * Address: 0x00BC5D20 (FUN_00BC5D20, register_NaN_47)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 47.
   */
  void register_NaN_47()
  {
    RegisterQuietNaN<47>();
  }

  /**
   * Address: 0x00BC5D60 (FUN_00BC5D60, register_pInf_48)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 48.
   */
  void register_pInf_48()
  {
    RegisterPositiveInfinity<48>();
  }

  /**
   * Address: 0x00BC5D80 (FUN_00BC5D80, register_nInf_48)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 48 from `pInf_48`.
   */
  void register_nInf_48()
  {
    RegisterNegativeInfinity<48>();
  }

  /**
   * Address: 0x00BC5DA0 (FUN_00BC5DA0, register_NaN_48)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 48.
   */
  void register_NaN_48()
  {
    RegisterQuietNaN<48>();
  }

  /**
   * Address: 0x00BC5EE0 (FUN_00BC5EE0, register_pInf_49)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 49.
   */
  void register_pInf_49()
  {
    RegisterPositiveInfinity<49>();
  }

  /**
   * Address: 0x00BC5F00 (FUN_00BC5F00, register_nInf_49)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 49 from `pInf_49`.
   */
  void register_nInf_49()
  {
    RegisterNegativeInfinity<49>();
  }

  /**
   * Address: 0x00BC5F20 (FUN_00BC5F20, register_NaN_49)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 49.
   */
  void register_NaN_49()
  {
    RegisterQuietNaN<49>();
  }

  /**
   * Address: 0x00BC6000 (FUN_00BC6000, register_pInf_50)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 50.
   */
  void register_pInf_50()
  {
    RegisterPositiveInfinity<50>();
  }

  /**
   * Address: 0x00BC6020 (FUN_00BC6020, register_nInf_50)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 50 from `pInf_50`.
   */
  void register_nInf_50()
  {
    RegisterNegativeInfinity<50>();
  }

  /**
   * Address: 0x00BC6040 (FUN_00BC6040, register_NaN_50)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 50.
   */
  void register_NaN_50()
  {
    RegisterQuietNaN<50>();
  }

  /**
   * Address: 0x00BC6100 (FUN_00BC6100, register_pInf_51)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 51.
   */
  void register_pInf_51()
  {
    RegisterPositiveInfinity<51>();
  }

  /**
   * Address: 0x00BC6120 (FUN_00BC6120, register_nInf_51)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 51 from `pInf_51`.
   */
  void register_nInf_51()
  {
    RegisterNegativeInfinity<51>();
  }

  /**
   * Address: 0x00BC6140 (FUN_00BC6140, register_NaN_51)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 51.
   */
  void register_NaN_51()
  {
    RegisterQuietNaN<51>();
  }

  /**
   * Address: 0x00BC6360 (FUN_00BC6360, register_pInf_52)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 52.
   */
  void register_pInf_52()
  {
    RegisterPositiveInfinity<52>();
  }

  /**
   * Address: 0x00BC6380 (FUN_00BC6380, register_nInf_52)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 52 from `pInf_52`.
   */
  void register_nInf_52()
  {
    RegisterNegativeInfinity<52>();
  }

  /**
   * Address: 0x00BC63A0 (FUN_00BC63A0, register_NaN_52)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 52.
   */
  void register_NaN_52()
  {
    RegisterQuietNaN<52>();
  }

  /**
   * Address: 0x00BC6670 (FUN_00BC6670, register_pInf_53)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 53.
   */
  void register_pInf_53()
  {
    RegisterPositiveInfinity<53>();
  }

  /**
   * Address: 0x00BC6690 (FUN_00BC6690, register_nInf_53)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 53 from `pInf_53`.
   */
  void register_nInf_53()
  {
    RegisterNegativeInfinity<53>();
  }

  /**
   * Address: 0x00BC66B0 (FUN_00BC66B0, register_NaN_53)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 53.
   */
  void register_NaN_53()
  {
    RegisterQuietNaN<53>();
  }

  /**
   * Address: 0x00BC6710 (FUN_00BC6710, register_pInf_54)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 54.
   */
  void register_pInf_54()
  {
    RegisterPositiveInfinity<54>();
  }

  /**
   * Address: 0x00BC6730 (FUN_00BC6730, register_nInf_54)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 54 from `pInf_54`.
   */
  void register_nInf_54()
  {
    RegisterNegativeInfinity<54>();
  }

  /**
   * Address: 0x00BC6750 (FUN_00BC6750, register_NaN_54)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 54.
   */
  void register_NaN_54()
  {
    RegisterQuietNaN<54>();
  }

  /**
   * Address: 0x00BC67D0 (FUN_00BC67D0, register_pInf_55)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 55.
   */
  void register_pInf_55()
  {
    RegisterPositiveInfinity<55>();
  }

  /**
   * Address: 0x00BC67F0 (FUN_00BC67F0, register_nInf_55)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 55 from `pInf_55`.
   */
  void register_nInf_55()
  {
    RegisterNegativeInfinity<55>();
  }

  /**
   * Address: 0x00BC6810 (FUN_00BC6810, register_NaN_55)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 55.
   */
  void register_NaN_55()
  {
    RegisterQuietNaN<55>();
  }

  /**
   * Address: 0x00BC6B10 (FUN_00BC6B10, register_pInf_56)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 56.
   */
  void register_pInf_56()
  {
    RegisterPositiveInfinity<56>();
  }

  /**
   * Address: 0x00BC6B30 (FUN_00BC6B30, register_nInf_56)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 56 from `pInf_56`.
   */
  void register_nInf_56()
  {
    RegisterNegativeInfinity<56>();
  }

  /**
   * Address: 0x00BC6B50 (FUN_00BC6B50, register_NaN_56)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 56.
   */
  void register_NaN_56()
  {
    RegisterQuietNaN<56>();
  }

  /**
   * Address: 0x00BC6B80 (FUN_00BC6B80, register_pInf_57)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 57.
   */
  void register_pInf_57()
  {
    RegisterPositiveInfinity<57>();
  }

  /**
   * Address: 0x00BC6BA0 (FUN_00BC6BA0, register_nInf_57)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 57 from `pInf_57`.
   */
  void register_nInf_57()
  {
    RegisterNegativeInfinity<57>();
  }

  /**
   * Address: 0x00BC6BC0 (FUN_00BC6BC0, register_NaN_57)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 57.
   */
  void register_NaN_57()
  {
    RegisterQuietNaN<57>();
  }

  /**
   * Address: 0x00BC6BE0 (FUN_00BC6BE0, register_pInf_58)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 58.
   */
  void register_pInf_58()
  {
    RegisterPositiveInfinity<58>();
  }

  /**
   * Address: 0x00BC6C00 (FUN_00BC6C00, register_nInf_58)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 58 from `pInf_58`.
   */
  void register_nInf_58()
  {
    RegisterNegativeInfinity<58>();
  }

  /**
   * Address: 0x00BC6C20 (FUN_00BC6C20, register_NaN_58)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 58.
   */
  void register_NaN_58()
  {
    RegisterQuietNaN<58>();
  }

  /**
   * Address: 0x00BC6FA0 (FUN_00BC6FA0, register_pInf_59)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 59.
   */
  void register_pInf_59()
  {
    RegisterPositiveInfinity<59>();
  }

  /**
   * Address: 0x00BC6FC0 (FUN_00BC6FC0, register_nInf_59)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 59 from `pInf_59`.
   */
  void register_nInf_59()
  {
    RegisterNegativeInfinity<59>();
  }

  /**
   * Address: 0x00BC6FE0 (FUN_00BC6FE0, register_NaN_59)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 59.
   */
  void register_NaN_59()
  {
    RegisterQuietNaN<59>();
  }

  /**
   * Address: 0x00BC70F0 (FUN_00BC70F0, register_pInf_60)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 60.
   */
  void register_pInf_60()
  {
    RegisterPositiveInfinity<60>();
  }

  /**
   * Address: 0x00BC7110 (FUN_00BC7110, register_nInf_60)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 60 from `pInf_60`.
   */
  void register_nInf_60()
  {
    RegisterNegativeInfinity<60>();
  }

  /**
   * Address: 0x00BC7130 (FUN_00BC7130, register_NaN_60)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 60.
   */
  void register_NaN_60()
  {
    RegisterQuietNaN<60>();
  }

  /**
   * Address: 0x00BC71D0 (FUN_00BC71D0, register_pInf_61)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 61.
   */
  void register_pInf_61()
  {
    RegisterPositiveInfinity<61>();
  }

  /**
   * Address: 0x00BC71F0 (FUN_00BC71F0, register_nInf_61)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 61 from `pInf_61`.
   */
  void register_nInf_61()
  {
    RegisterNegativeInfinity<61>();
  }

  /**
   * Address: 0x00BC7210 (FUN_00BC7210, register_NaN_61)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 61.
   */
  void register_NaN_61()
  {
    RegisterQuietNaN<61>();
  }

  /**
   * Address: 0x00BC72A0 (FUN_00BC72A0, register_pInf_62)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 62.
   */
  void register_pInf_62()
  {
    RegisterPositiveInfinity<62>();
  }

  /**
   * Address: 0x00BC72C0 (FUN_00BC72C0, register_nInf_62)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 62 from `pInf_62`.
   */
  void register_nInf_62()
  {
    RegisterNegativeInfinity<62>();
  }

  /**
   * Address: 0x00BC72E0 (FUN_00BC72E0, register_NaN_62)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 62.
   */
  void register_NaN_62()
  {
    RegisterQuietNaN<62>();
  }

  /**
   * Address: 0x00BC7440 (FUN_00BC7440, register_pInf_63)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 63.
   */
  void register_pInf_63()
  {
    RegisterPositiveInfinity<63>();
  }

  /**
   * Address: 0x00BC7460 (FUN_00BC7460, register_nInf_63)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 63 from `pInf_63`.
   */
  void register_nInf_63()
  {
    RegisterNegativeInfinity<63>();
  }

  /**
   * Address: 0x00BC7480 (FUN_00BC7480, register_NaN_63)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 63.
   */
  void register_NaN_63()
  {
    RegisterQuietNaN<63>();
  }

  /**
   * Address: 0x00BC74B0 (FUN_00BC74B0, register_pInf_64)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 64.
   */
  void register_pInf_64()
  {
    RegisterPositiveInfinity<64>();
  }

  /**
   * Address: 0x00BC74D0 (FUN_00BC74D0, register_nInf_64)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 64 from `pInf_64`.
   */
  void register_nInf_64()
  {
    RegisterNegativeInfinity<64>();
  }

  /**
   * Address: 0x00BC74F0 (FUN_00BC74F0, register_NaN_64)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 64.
   */
  void register_NaN_64()
  {
    RegisterQuietNaN<64>();
  }

  /**
   * Address: 0x00BC7780 (FUN_00BC7780, register_pInf_65)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 65.
   */
  void register_pInf_65()
  {
    RegisterPositiveInfinity<65>();
  }

  /**
   * Address: 0x00BC77A0 (FUN_00BC77A0, register_nInf_65)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 65 from `pInf_65`.
   */
  void register_nInf_65()
  {
    RegisterNegativeInfinity<65>();
  }

  /**
   * Address: 0x00BC77C0 (FUN_00BC77C0, register_NaN_65)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 65.
   */
  void register_NaN_65()
  {
    RegisterQuietNaN<65>();
  }

  /**
   * Address: 0x00BC77E0 (FUN_00BC77E0, register_pInf_66)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 66.
   */
  void register_pInf_66()
  {
    RegisterPositiveInfinity<66>();
  }

  /**
   * Address: 0x00BC7800 (FUN_00BC7800, register_nInf_66)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 66 from `pInf_66`.
   */
  void register_nInf_66()
  {
    RegisterNegativeInfinity<66>();
  }

  /**
   * Address: 0x00BC7820 (FUN_00BC7820, register_NaN_66)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 66.
   */
  void register_NaN_66()
  {
    RegisterQuietNaN<66>();
  }

  /**
   * Address: 0x00BC7850 (FUN_00BC7850, register_pInf_67)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 67.
   */
  void register_pInf_67()
  {
    RegisterPositiveInfinity<67>();
  }

  /**
   * Address: 0x00BC7870 (FUN_00BC7870, register_nInf_67)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 67 from `pInf_67`.
   */
  void register_nInf_67()
  {
    RegisterNegativeInfinity<67>();
  }

  /**
   * Address: 0x00BC7890 (FUN_00BC7890, register_NaN_67)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 67.
   */
  void register_NaN_67()
  {
    RegisterQuietNaN<67>();
  }

  /**
   * Address: 0x00BC7C00 (FUN_00BC7C00, register_pInf_68)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 68.
   */
  void register_pInf_68()
  {
    RegisterPositiveInfinity<68>();
  }

  /**
   * Address: 0x00BC7C20 (FUN_00BC7C20, register_nInf_68)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 68 from `pInf_68`.
   */
  void register_nInf_68()
  {
    RegisterNegativeInfinity<68>();
  }

  /**
   * Address: 0x00BC7C40 (FUN_00BC7C40, register_NaN_68)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 68.
   */
  void register_NaN_68()
  {
    RegisterQuietNaN<68>();
  }

  /**
   * Address: 0x00BC7EB0 (FUN_00BC7EB0, register_pInf_69)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 69.
   */
  void register_pInf_69()
  {
    RegisterPositiveInfinity<69>();
  }

  /**
   * Address: 0x00BC7ED0 (FUN_00BC7ED0, register_nInf_69)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 69 from `pInf_69`.
   */
  void register_nInf_69()
  {
    RegisterNegativeInfinity<69>();
  }

  /**
   * Address: 0x00BC7EF0 (FUN_00BC7EF0, register_NaN_69)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 69.
   */
  void register_NaN_69()
  {
    RegisterQuietNaN<69>();
  }

  /**
   * Address: 0x00BC7F60 (FUN_00BC7F60, register_pInf_70)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 70.
   */
  void register_pInf_70()
  {
    RegisterPositiveInfinity<70>();
  }

  /**
   * Address: 0x00BC7F80 (FUN_00BC7F80, register_nInf_70)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 70 from `pInf_70`.
   */
  void register_nInf_70()
  {
    RegisterNegativeInfinity<70>();
  }

  /**
   * Address: 0x00BC7FA0 (FUN_00BC7FA0, register_NaN_70)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 70.
   */
  void register_NaN_70()
  {
    RegisterQuietNaN<70>();
  }

  /**
   * Address: 0x00BC7FE0 (FUN_00BC7FE0, register_pInf_71)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 71.
   */
  void register_pInf_71()
  {
    RegisterPositiveInfinity<71>();
  }

  /**
   * Address: 0x00BC8000 (FUN_00BC8000, register_nInf_71)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 71 from `pInf_71`.
   */
  void register_nInf_71()
  {
    RegisterNegativeInfinity<71>();
  }

  /**
   * Address: 0x00BC8020 (FUN_00BC8020, register_NaN_71)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 71.
   */
  void register_NaN_71()
  {
    RegisterQuietNaN<71>();
  }

  /**
   * Address: 0x00BC8230 (FUN_00BC8230, register_pInf_72)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 72.
   */
  void register_pInf_72()
  {
    RegisterPositiveInfinity<72>();
  }

  /**
   * Address: 0x00BC8250 (FUN_00BC8250, register_nInf_72)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 72 from `pInf_72`.
   */
  void register_nInf_72()
  {
    RegisterNegativeInfinity<72>();
  }

  /**
   * Address: 0x00BC8270 (FUN_00BC8270, register_NaN_72)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 72.
   */
  void register_NaN_72()
  {
    RegisterQuietNaN<72>();
  }

  /**
   * Address: 0x00BC82E0 (FUN_00BC82E0, register_pInf_73)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 73.
   */
  void register_pInf_73()
  {
    RegisterPositiveInfinity<73>();
  }

  /**
   * Address: 0x00BC8300 (FUN_00BC8300, register_nInf_73)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 73 from `pInf_73`.
   */
  void register_nInf_73()
  {
    RegisterNegativeInfinity<73>();
  }

  /**
   * Address: 0x00BC8320 (FUN_00BC8320, register_NaN_73)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 73.
   */
  void register_NaN_73()
  {
    RegisterQuietNaN<73>();
  }

  /**
   * Address: 0x00BC83C0 (FUN_00BC83C0, register_pInf_74)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 74.
   */
  void register_pInf_74()
  {
    RegisterPositiveInfinity<74>();
  }

  /**
   * Address: 0x00BC83E0 (FUN_00BC83E0, register_nInf_74)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 74 from `pInf_74`.
   */
  void register_nInf_74()
  {
    RegisterNegativeInfinity<74>();
  }

  /**
   * Address: 0x00BC8400 (FUN_00BC8400, register_NaN_74)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 74.
   */
  void register_NaN_74()
  {
    RegisterQuietNaN<74>();
  }

  /**
   * Address: 0x00BC85F0 (FUN_00BC85F0, register_pInf_75)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 75.
   */
  void register_pInf_75()
  {
    RegisterPositiveInfinity<75>();
  }

  /**
   * Address: 0x00BC8610 (FUN_00BC8610, register_nInf_75)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 75 from `pInf_75`.
   */
  void register_nInf_75()
  {
    RegisterNegativeInfinity<75>();
  }

  /**
   * Address: 0x00BC8630 (FUN_00BC8630, register_NaN_75)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 75.
   */
  void register_NaN_75()
  {
    RegisterQuietNaN<75>();
  }

  /**
   * Address: 0x00BC8750 (FUN_00BC8750, register_pInf_76)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 76.
   */
  void register_pInf_76()
  {
    RegisterPositiveInfinity<76>();
  }

  /**
   * Address: 0x00BC8770 (FUN_00BC8770, register_nInf_76)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 76 from `pInf_76`.
   */
  void register_nInf_76()
  {
    RegisterNegativeInfinity<76>();
  }

  /**
   * Address: 0x00BC8790 (FUN_00BC8790, register_NaN_76)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 76.
   */
  void register_NaN_76()
  {
    RegisterQuietNaN<76>();
  }

  /**
   * Address: 0x00BC88B0 (FUN_00BC88B0, register_pInf_77)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 77.
   */
  void register_pInf_77()
  {
    RegisterPositiveInfinity<77>();
  }

  /**
   * Address: 0x00BC88D0 (FUN_00BC88D0, register_nInf_77)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 77 from `pInf_77`.
   */
  void register_nInf_77()
  {
    RegisterNegativeInfinity<77>();
  }

  /**
   * Address: 0x00BC88F0 (FUN_00BC88F0, register_NaN_77)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 77.
   */
  void register_NaN_77()
  {
    RegisterQuietNaN<77>();
  }

  /**
   * Address: 0x00BC8D60 (FUN_00BC8D60, register_pInf_78)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 78.
   */
  void register_pInf_78()
  {
    RegisterPositiveInfinity<78>();
  }

  /**
   * Address: 0x00BC8D80 (FUN_00BC8D80, register_nInf_78)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 78 from `pInf_78`.
   */
  void register_nInf_78()
  {
    RegisterNegativeInfinity<78>();
  }

  /**
   * Address: 0x00BC8DA0 (FUN_00BC8DA0, register_NaN_78)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 78.
   */
  void register_NaN_78()
  {
    RegisterQuietNaN<78>();
  }

  /**
   * Address: 0x00BC8F90 (FUN_00BC8F90, register_pInf_79)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 79.
   */
  void register_pInf_79()
  {
    RegisterPositiveInfinity<79>();
  }

  /**
   * Address: 0x00BC8FB0 (FUN_00BC8FB0, register_nInf_79)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 79 from `pInf_79`.
   */
  void register_nInf_79()
  {
    RegisterNegativeInfinity<79>();
  }

  /**
   * Address: 0x00BC8FD0 (FUN_00BC8FD0, register_NaN_79)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 79.
   */
  void register_NaN_79()
  {
    RegisterQuietNaN<79>();
  }

  /**
   * Address: 0x00BC8FF0 (FUN_00BC8FF0, register_pInf_80)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 80.
   */
  void register_pInf_80()
  {
    RegisterPositiveInfinity<80>();
  }

  /**
   * Address: 0x00BC9010 (FUN_00BC9010, register_nInf_80)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 80 from `pInf_80`.
   */
  void register_nInf_80()
  {
    RegisterNegativeInfinity<80>();
  }

  /**
   * Address: 0x00BC9030 (FUN_00BC9030, register_NaN_80)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 80.
   */
  void register_NaN_80()
  {
    RegisterQuietNaN<80>();
  }

  /**
   * Address: 0x00BC92B0 (FUN_00BC92B0, register_pInf_81)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 81.
   */
  void register_pInf_81()
  {
    RegisterPositiveInfinity<81>();
  }

  /**
   * Address: 0x00BC92D0 (FUN_00BC92D0, register_nInf_81)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 81 from `pInf_81`.
   */
  void register_nInf_81()
  {
    RegisterNegativeInfinity<81>();
  }

  /**
   * Address: 0x00BC92F0 (FUN_00BC92F0, register_NaN_81)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 81.
   */
  void register_NaN_81()
  {
    RegisterQuietNaN<81>();
  }

  /**
   * Address: 0x00BC9320 (FUN_00BC9320, register_pInf_82)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 82.
   */
  void register_pInf_82()
  {
    RegisterPositiveInfinity<82>();
  }

  /**
   * Address: 0x00BC9340 (FUN_00BC9340, register_nInf_82)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 82 from `pInf_82`.
   */
  void register_nInf_82()
  {
    RegisterNegativeInfinity<82>();
  }

  /**
   * Address: 0x00BC9360 (FUN_00BC9360, register_NaN_82)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 82.
   */
  void register_NaN_82()
  {
    RegisterQuietNaN<82>();
  }

  /**
   * Address: 0x00BC93D0 (FUN_00BC93D0, register_pInf_83)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 83.
   */
  void register_pInf_83()
  {
    RegisterPositiveInfinity<83>();
  }

  /**
   * Address: 0x00BC93F0 (FUN_00BC93F0, register_nInf_83)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 83 from `pInf_83`.
   */
  void register_nInf_83()
  {
    RegisterNegativeInfinity<83>();
  }

  /**
   * Address: 0x00BC9410 (FUN_00BC9410, register_NaN_83)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 83.
   */
  void register_NaN_83()
  {
    RegisterQuietNaN<83>();
  }

  /**
   * Address: 0x00BC9590 (FUN_00BC9590, register_pInf_84)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 84.
   */
  void register_pInf_84()
  {
    RegisterPositiveInfinity<84>();
  }

  /**
   * Address: 0x00BC95B0 (FUN_00BC95B0, register_nInf_84)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 84 from `pInf_84`.
   */
  void register_nInf_84()
  {
    RegisterNegativeInfinity<84>();
  }

  /**
   * Address: 0x00BC95D0 (FUN_00BC95D0, register_NaN_84)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 84.
   */
  void register_NaN_84()
  {
    RegisterQuietNaN<84>();
  }

  /**
   * Address: 0x00BC9820 (FUN_00BC9820, register_pInf_85)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 85.
   */
  void register_pInf_85()
  {
    RegisterPositiveInfinity<85>();
  }

  /**
   * Address: 0x00BC9840 (FUN_00BC9840, register_nInf_85)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 85 from `pInf_85`.
   */
  void register_nInf_85()
  {
    RegisterNegativeInfinity<85>();
  }

  /**
   * Address: 0x00BC9860 (FUN_00BC9860, register_NaN_85)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 85.
   */
  void register_NaN_85()
  {
    RegisterQuietNaN<85>();
  }

  /**
   * Address: 0x00BC9A30 (FUN_00BC9A30, register_pInf_86)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 86.
   */
  void register_pInf_86()
  {
    RegisterPositiveInfinity<86>();
  }

  /**
   * Address: 0x00BC9A50 (FUN_00BC9A50, register_nInf_86)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 86 from `pInf_86`.
   */
  void register_nInf_86()
  {
    RegisterNegativeInfinity<86>();
  }

  /**
   * Address: 0x00BC9A70 (FUN_00BC9A70, register_NaN_86)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 86.
   */
  void register_NaN_86()
  {
    RegisterQuietNaN<86>();
  }

  /**
   * Address: 0x00BC9BB0 (FUN_00BC9BB0, register_pInf_87)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 87.
   */
  void register_pInf_87()
  {
    RegisterPositiveInfinity<87>();
  }

  /**
   * Address: 0x00BC9BD0 (FUN_00BC9BD0, register_nInf_87)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 87 from `pInf_87`.
   */
  void register_nInf_87()
  {
    RegisterNegativeInfinity<87>();
  }

  /**
   * Address: 0x00BC9BF0 (FUN_00BC9BF0, register_NaN_87)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 87.
   */
  void register_NaN_87()
  {
    RegisterQuietNaN<87>();
  }

  /**
   * Address: 0x00BC9D80 (FUN_00BC9D80, register_pInf_88)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 88.
   */
  void register_pInf_88()
  {
    RegisterPositiveInfinity<88>();
  }

  /**
   * Address: 0x00BC9DA0 (FUN_00BC9DA0, register_nInf_88)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 88 from `pInf_88`.
   */
  void register_nInf_88()
  {
    RegisterNegativeInfinity<88>();
  }

  /**
   * Address: 0x00BC9DC0 (FUN_00BC9DC0, register_NaN_88)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 88.
   */
  void register_NaN_88()
  {
    RegisterQuietNaN<88>();
  }

  /**
   * Address: 0x00BC9E00 (FUN_00BC9E00, register_pInf_89)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 89.
   */
  void register_pInf_89()
  {
    RegisterPositiveInfinity<89>();
  }

  /**
   * Address: 0x00BC9E20 (FUN_00BC9E20, register_nInf_89)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 89 from `pInf_89`.
   */
  void register_nInf_89()
  {
    RegisterNegativeInfinity<89>();
  }

  /**
   * Address: 0x00BC9E40 (FUN_00BC9E40, register_NaN_89)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 89.
   */
  void register_NaN_89()
  {
    RegisterQuietNaN<89>();
  }

  /**
   * Address: 0x00BC9EF0 (FUN_00BC9EF0, register_pInf_90)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 90.
   */
  void register_pInf_90()
  {
    RegisterPositiveInfinity<90>();
  }

  /**
   * Address: 0x00BC9F10 (FUN_00BC9F10, register_nInf_90)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 90 from `pInf_90`.
   */
  void register_nInf_90()
  {
    RegisterNegativeInfinity<90>();
  }

  /**
   * Address: 0x00BC9F30 (FUN_00BC9F30, register_NaN_90)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 90.
   */
  void register_NaN_90()
  {
    RegisterQuietNaN<90>();
  }

  /**
   * Address: 0x00BCA160 (FUN_00BCA160, register_pInf_91)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 91.
   */
  void register_pInf_91()
  {
    RegisterPositiveInfinity<91>();
  }

  /**
   * Address: 0x00BCA180 (FUN_00BCA180, register_nInf_91)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 91 from `pInf_91`.
   */
  void register_nInf_91()
  {
    RegisterNegativeInfinity<91>();
  }

  /**
   * Address: 0x00BCA1A0 (FUN_00BCA1A0, register_NaN_91)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 91.
   */
  void register_NaN_91()
  {
    RegisterQuietNaN<91>();
  }

  /**
   * Address: 0x00BCA1C0 (FUN_00BCA1C0, register_pInf_92)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 92.
   */
  void register_pInf_92()
  {
    RegisterPositiveInfinity<92>();
  }

  /**
   * Address: 0x00BCA1E0 (FUN_00BCA1E0, register_nInf_92)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 92 from `pInf_92`.
   */
  void register_nInf_92()
  {
    RegisterNegativeInfinity<92>();
  }

  /**
   * Address: 0x00BCA200 (FUN_00BCA200, register_NaN_92)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 92.
   */
  void register_NaN_92()
  {
    RegisterQuietNaN<92>();
  }

  /**
   * Address: 0x00BCA220 (FUN_00BCA220, register_pInf_93)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 93.
   */
  void register_pInf_93()
  {
    RegisterPositiveInfinity<93>();
  }

  /**
   * Address: 0x00BCA240 (FUN_00BCA240, register_nInf_93)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 93 from `pInf_93`.
   */
  void register_nInf_93()
  {
    RegisterNegativeInfinity<93>();
  }

  /**
   * Address: 0x00BCA260 (FUN_00BCA260, register_NaN_93)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 93.
   */
  void register_NaN_93()
  {
    RegisterQuietNaN<93>();
  }

  /**
   * Address: 0x00BCA350 (FUN_00BCA350, register_pInf_94)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 94.
   */
  void register_pInf_94()
  {
    RegisterPositiveInfinity<94>();
  }

  /**
   * Address: 0x00BCA370 (FUN_00BCA370, register_nInf_94)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 94 from `pInf_94`.
   */
  void register_nInf_94()
  {
    RegisterNegativeInfinity<94>();
  }

  /**
   * Address: 0x00BCA390 (FUN_00BCA390, register_NaN_94)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 94.
   */
  void register_NaN_94()
  {
    RegisterQuietNaN<94>();
  }

  /**
   * Address: 0x00BCA3D0 (FUN_00BCA3D0, register_pInf_95)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 95.
   */
  void register_pInf_95()
  {
    RegisterPositiveInfinity<95>();
  }

  /**
   * Address: 0x00BCA3F0 (FUN_00BCA3F0, register_nInf_95)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 95 from `pInf_95`.
   */
  void register_nInf_95()
  {
    RegisterNegativeInfinity<95>();
  }

  /**
   * Address: 0x00BCA410 (FUN_00BCA410, register_NaN_95)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 95.
   */
  void register_NaN_95()
  {
    RegisterQuietNaN<95>();
  }

  /**
   * Address: 0x00BCA720 (FUN_00BCA720, register_pInf_96)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 96.
   */
  void register_pInf_96()
  {
    RegisterPositiveInfinity<96>();
  }

  /**
   * Address: 0x00BCA740 (FUN_00BCA740, register_nInf_96)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 96 from `pInf_96`.
   */
  void register_nInf_96()
  {
    RegisterNegativeInfinity<96>();
  }

  /**
   * Address: 0x00BCA760 (FUN_00BCA760, register_NaN_96)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 96.
   */
  void register_NaN_96()
  {
    RegisterQuietNaN<96>();
  }

  /**
   * Address: 0x00BCA790 (FUN_00BCA790, register_pInf_97)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 97.
   */
  void register_pInf_97()
  {
    RegisterPositiveInfinity<97>();
  }

  /**
   * Address: 0x00BCA7B0 (FUN_00BCA7B0, register_nInf_97)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 97 from `pInf_97`.
   */
  void register_nInf_97()
  {
    RegisterNegativeInfinity<97>();
  }

  /**
   * Address: 0x00BCA7D0 (FUN_00BCA7D0, register_NaN_97)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 97.
   */
  void register_NaN_97()
  {
    RegisterQuietNaN<97>();
  }

  /**
   * Address: 0x00BCA930 (FUN_00BCA930, register_pInf_98)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 98.
   */
  void register_pInf_98()
  {
    RegisterPositiveInfinity<98>();
  }

  /**
   * Address: 0x00BCA950 (FUN_00BCA950, register_nInf_98)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 98 from `pInf_98`.
   */
  void register_nInf_98()
  {
    RegisterNegativeInfinity<98>();
  }

  /**
   * Address: 0x00BCA970 (FUN_00BCA970, register_NaN_98)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 98.
   */
  void register_NaN_98()
  {
    RegisterQuietNaN<98>();
  }

  /**
   * Address: 0x00BCA9B0 (FUN_00BCA9B0, register_pInf_99)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 99.
   */
  void register_pInf_99()
  {
    RegisterPositiveInfinity<99>();
  }

  /**
   * Address: 0x00BCA9D0 (FUN_00BCA9D0, register_nInf_99)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 99 from `pInf_99`.
   */
  void register_nInf_99()
  {
    RegisterNegativeInfinity<99>();
  }

  /**
   * Address: 0x00BCA9F0 (FUN_00BCA9F0, register_NaN_99)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 99.
   */
  void register_NaN_99()
  {
    RegisterQuietNaN<99>();
  }

  /**
   * Address: 0x00BCAA20 (FUN_00BCAA20, register_pInf_100)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 100.
   */
  void register_pInf_100()
  {
    RegisterPositiveInfinity<100>();
  }

  /**
   * Address: 0x00BCAA40 (FUN_00BCAA40, register_nInf_100)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 100 from `pInf_100`.
   */
  void register_nInf_100()
  {
    RegisterNegativeInfinity<100>();
  }

  /**
   * Address: 0x00BCAA60 (FUN_00BCAA60, register_NaN_100)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 100.
   */
  void register_NaN_100()
  {
    RegisterQuietNaN<100>();
  }

  /**
   * Address: 0x00BCAD70 (FUN_00BCAD70, register_pInf_101)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 101.
   */
  void register_pInf_101()
  {
    RegisterPositiveInfinity<101>();
  }

  /**
   * Address: 0x00BCAD90 (FUN_00BCAD90, register_nInf_101)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 101 from `pInf_101`.
   */
  void register_nInf_101()
  {
    RegisterNegativeInfinity<101>();
  }

  /**
   * Address: 0x00BCADB0 (FUN_00BCADB0, register_NaN_101)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 101.
   */
  void register_NaN_101()
  {
    RegisterQuietNaN<101>();
  }

  /**
   * Address: 0x00BCADE0 (FUN_00BCADE0, register_pInf_102)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 102.
   */
  void register_pInf_102()
  {
    RegisterPositiveInfinity<102>();
  }

  /**
   * Address: 0x00BCAE00 (FUN_00BCAE00, register_nInf_102)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 102 from `pInf_102`.
   */
  void register_nInf_102()
  {
    RegisterNegativeInfinity<102>();
  }

  /**
   * Address: 0x00BCAE20 (FUN_00BCAE20, register_NaN_102)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 102.
   */
  void register_NaN_102()
  {
    RegisterQuietNaN<102>();
  }

  /**
   * Address: 0x00BCAE70 (FUN_00BCAE70, register_pInf_103)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 103.
   */
  void register_pInf_103()
  {
    RegisterPositiveInfinity<103>();
  }

  /**
   * Address: 0x00BCAE90 (FUN_00BCAE90, register_nInf_103)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 103 from `pInf_103`.
   */
  void register_nInf_103()
  {
    RegisterNegativeInfinity<103>();
  }

  /**
   * Address: 0x00BCAEB0 (FUN_00BCAEB0, register_NaN_103)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 103.
   */
  void register_NaN_103()
  {
    RegisterQuietNaN<103>();
  }

  /**
   * Address: 0x00BCB4E0 (FUN_00BCB4E0, register_pInf_104)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 104.
   */
  void register_pInf_104()
  {
    RegisterPositiveInfinity<104>();
  }

  /**
   * Address: 0x00BCB500 (FUN_00BCB500, register_nInf_104)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 104 from `pInf_104`.
   */
  void register_nInf_104()
  {
    RegisterNegativeInfinity<104>();
  }

  /**
   * Address: 0x00BCB520 (FUN_00BCB520, register_NaN_104)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 104.
   */
  void register_NaN_104()
  {
    RegisterQuietNaN<104>();
  }

  /**
   * Address: 0x00BCBB70 (FUN_00BCBB70, register_pInf_105)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 105.
   */
  void register_pInf_105()
  {
    RegisterPositiveInfinity<105>();
  }

  /**
   * Address: 0x00BCBB90 (FUN_00BCBB90, register_nInf_105)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 105 from `pInf_105`.
   */
  void register_nInf_105()
  {
    RegisterNegativeInfinity<105>();
  }

  /**
   * Address: 0x00BCBBB0 (FUN_00BCBBB0, register_NaN_105)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 105.
   */
  void register_NaN_105()
  {
    RegisterQuietNaN<105>();
  }

  /**
   * Address: 0x00BCBE20 (FUN_00BCBE20, register_pInf_106)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 106.
   */
  void register_pInf_106()
  {
    RegisterPositiveInfinity<106>();
  }

  /**
   * Address: 0x00BCBE40 (FUN_00BCBE40, register_nInf_106)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 106 from `pInf_106`.
   */
  void register_nInf_106()
  {
    RegisterNegativeInfinity<106>();
  }

  /**
   * Address: 0x00BCBE60 (FUN_00BCBE60, register_NaN_106)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 106.
   */
  void register_NaN_106()
  {
    RegisterQuietNaN<106>();
  }

  /**
   * Address: 0x00BCBF50 (FUN_00BCBF50, register_pInf_107)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 107.
   */
  void register_pInf_107()
  {
    RegisterPositiveInfinity<107>();
  }

  /**
   * Address: 0x00BCBF70 (FUN_00BCBF70, register_nInf_107)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 107 from `pInf_107`.
   */
  void register_nInf_107()
  {
    RegisterNegativeInfinity<107>();
  }

  /**
   * Address: 0x00BCBF90 (FUN_00BCBF90, register_NaN_107)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 107.
   */
  void register_NaN_107()
  {
    RegisterQuietNaN<107>();
  }

  /**
   * Address: 0x00BCC240 (FUN_00BCC240, register_pInf_108)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 108.
   */
  void register_pInf_108()
  {
    RegisterPositiveInfinity<108>();
  }

  /**
   * Address: 0x00BCC260 (FUN_00BCC260, register_nInf_108)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 108 from `pInf_108`.
   */
  void register_nInf_108()
  {
    RegisterNegativeInfinity<108>();
  }

  /**
   * Address: 0x00BCC280 (FUN_00BCC280, register_NaN_108)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 108.
   */
  void register_NaN_108()
  {
    RegisterQuietNaN<108>();
  }

  /**
   * Address: 0x00BCC390 (FUN_00BCC390, register_pInf_109)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 109.
   */
  void register_pInf_109()
  {
    RegisterPositiveInfinity<109>();
  }

  /**
   * Address: 0x00BCC3B0 (FUN_00BCC3B0, register_nInf_109)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 109 from `pInf_109`.
   */
  void register_nInf_109()
  {
    RegisterNegativeInfinity<109>();
  }

  /**
   * Address: 0x00BCC3D0 (FUN_00BCC3D0, register_NaN_109)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 109.
   */
  void register_NaN_109()
  {
    RegisterQuietNaN<109>();
  }

  /**
   * Address: 0x00BCC400 (FUN_00BCC400, register_pInf_110)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 110.
   */
  void register_pInf_110()
  {
    RegisterPositiveInfinity<110>();
  }

  /**
   * Address: 0x00BCC420 (FUN_00BCC420, register_nInf_110)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 110 from `pInf_110`.
   */
  void register_nInf_110()
  {
    RegisterNegativeInfinity<110>();
  }

  /**
   * Address: 0x00BCC440 (FUN_00BCC440, register_NaN_110)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 110.
   */
  void register_NaN_110()
  {
    RegisterQuietNaN<110>();
  }

  /**
   * Address: 0x00BCCA00 (FUN_00BCCA00, register_pInf_111)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 111.
   */
  void register_pInf_111()
  {
    RegisterPositiveInfinity<111>();
  }

  /**
   * Address: 0x00BCCA20 (FUN_00BCCA20, register_nInf_111)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 111 from `pInf_111`.
   */
  void register_nInf_111()
  {
    RegisterNegativeInfinity<111>();
  }

  /**
   * Address: 0x00BCCA40 (FUN_00BCCA40, register_NaN_111)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 111.
   */
  void register_NaN_111()
  {
    RegisterQuietNaN<111>();
  }

  /**
   * Address: 0x00BCCDE0 (FUN_00BCCDE0, register_pInf_112)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 112.
   */
  void register_pInf_112()
  {
    RegisterPositiveInfinity<112>();
  }

  /**
   * Address: 0x00BCCE00 (FUN_00BCCE00, register_nInf_112)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 112 from `pInf_112`.
   */
  void register_nInf_112()
  {
    RegisterNegativeInfinity<112>();
  }

  /**
   * Address: 0x00BCCE20 (FUN_00BCCE20, register_NaN_112)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 112.
   */
  void register_NaN_112()
  {
    RegisterQuietNaN<112>();
  }

  /**
   * Address: 0x00BCD090 (FUN_00BCD090, register_pInf_113)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 113.
   */
  void register_pInf_113()
  {
    RegisterPositiveInfinity<113>();
  }

  /**
   * Address: 0x00BCD0B0 (FUN_00BCD0B0, register_nInf_113)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 113 from `pInf_113`.
   */
  void register_nInf_113()
  {
    RegisterNegativeInfinity<113>();
  }

  /**
   * Address: 0x00BCD0D0 (FUN_00BCD0D0, register_NaN_113)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 113.
   */
  void register_NaN_113()
  {
    RegisterQuietNaN<113>();
  }

  /**
   * Address: 0x00BCD3C0 (FUN_00BCD3C0, register_pInf_114)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 114.
   */
  void register_pInf_114()
  {
    RegisterPositiveInfinity<114>();
  }

  /**
   * Address: 0x00BCD3E0 (FUN_00BCD3E0, register_nInf_114)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 114 from `pInf_114`.
   */
  void register_nInf_114()
  {
    RegisterNegativeInfinity<114>();
  }

  /**
   * Address: 0x00BCD400 (FUN_00BCD400, register_NaN_114)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 114.
   */
  void register_NaN_114()
  {
    RegisterQuietNaN<114>();
  }

  /**
   * Address: 0x00BCD6D0 (FUN_00BCD6D0, register_pInf_115)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 115.
   */
  void register_pInf_115()
  {
    RegisterPositiveInfinity<115>();
  }

  /**
   * Address: 0x00BCD6F0 (FUN_00BCD6F0, register_nInf_115)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 115 from `pInf_115`.
   */
  void register_nInf_115()
  {
    RegisterNegativeInfinity<115>();
  }

  /**
   * Address: 0x00BCD710 (FUN_00BCD710, register_NaN_115)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 115.
   */
  void register_NaN_115()
  {
    RegisterQuietNaN<115>();
  }

  /**
   * Address: 0x00BCD990 (FUN_00BCD990, register_pInf_116)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 116.
   */
  void register_pInf_116()
  {
    RegisterPositiveInfinity<116>();
  }

  /**
   * Address: 0x00BCD9B0 (FUN_00BCD9B0, register_nInf_116)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 116 from `pInf_116`.
   */
  void register_nInf_116()
  {
    RegisterNegativeInfinity<116>();
  }

  /**
   * Address: 0x00BCD9D0 (FUN_00BCD9D0, register_NaN_116)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 116.
   */
  void register_NaN_116()
  {
    RegisterQuietNaN<116>();
  }

  /**
   * Address: 0x00BCDFB0 (FUN_00BCDFB0, register_pInf_117)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 117.
   */
  void register_pInf_117()
  {
    RegisterPositiveInfinity<117>();
  }

  /**
   * Address: 0x00BCDFD0 (FUN_00BCDFD0, register_nInf_117)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 117 from `pInf_117`.
   */
  void register_nInf_117()
  {
    RegisterNegativeInfinity<117>();
  }

  /**
   * Address: 0x00BCDFF0 (FUN_00BCDFF0, register_NaN_117)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 117.
   */
  void register_NaN_117()
  {
    RegisterQuietNaN<117>();
  }

  /**
   * Address: 0x00BCE1C0 (FUN_00BCE1C0, register_pInf_118)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 118.
   */
  void register_pInf_118()
  {
    RegisterPositiveInfinity<118>();
  }

  /**
   * Address: 0x00BCE1E0 (FUN_00BCE1E0, register_nInf_118)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 118 from `pInf_118`.
   */
  void register_nInf_118()
  {
    RegisterNegativeInfinity<118>();
  }

  /**
   * Address: 0x00BCE200 (FUN_00BCE200, register_NaN_118)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 118.
   */
  void register_NaN_118()
  {
    RegisterQuietNaN<118>();
  }

  /**
   * Address: 0x00BCE4F0 (FUN_00BCE4F0, register_pInf_119)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 119.
   */
  void register_pInf_119()
  {
    RegisterPositiveInfinity<119>();
  }

  /**
   * Address: 0x00BCE510 (FUN_00BCE510, register_nInf_119)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 119 from `pInf_119`.
   */
  void register_nInf_119()
  {
    RegisterNegativeInfinity<119>();
  }

  /**
   * Address: 0x00BCE530 (FUN_00BCE530, register_NaN_119)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 119.
   */
  void register_NaN_119()
  {
    RegisterQuietNaN<119>();
  }

  /**
   * Address: 0x00BCEB70 (FUN_00BCEB70, register_pInf_120)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 120.
   */
  void register_pInf_120()
  {
    RegisterPositiveInfinity<120>();
  }

  /**
   * Address: 0x00BCEB90 (FUN_00BCEB90, register_nInf_120)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 120 from `pInf_120`.
   */
  void register_nInf_120()
  {
    RegisterNegativeInfinity<120>();
  }

  /**
   * Address: 0x00BCEBB0 (FUN_00BCEBB0, register_NaN_120)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 120.
   */
  void register_NaN_120()
  {
    RegisterQuietNaN<120>();
  }

  /**
   * Address: 0x00BCECB0 (FUN_00BCECB0, register_pInf_121)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 121.
   */
  void register_pInf_121()
  {
    RegisterPositiveInfinity<121>();
  }

  /**
   * Address: 0x00BCECD0 (FUN_00BCECD0, register_nInf_121)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 121 from `pInf_121`.
   */
  void register_nInf_121()
  {
    RegisterNegativeInfinity<121>();
  }

  /**
   * Address: 0x00BCECF0 (FUN_00BCECF0, register_NaN_121)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 121.
   */
  void register_NaN_121()
  {
    RegisterQuietNaN<121>();
  }

  /**
   * Address: 0x00BCF060 (FUN_00BCF060, register_pInf_122)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 122.
   */
  void register_pInf_122()
  {
    RegisterPositiveInfinity<122>();
  }

  /**
   * Address: 0x00BCF080 (FUN_00BCF080, register_nInf_122)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 122 from `pInf_122`.
   */
  void register_nInf_122()
  {
    RegisterNegativeInfinity<122>();
  }

  /**
   * Address: 0x00BCF0A0 (FUN_00BCF0A0, register_NaN_122)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 122.
   */
  void register_NaN_122()
  {
    RegisterQuietNaN<122>();
  }

  /**
   * Address: 0x00BCF2B0 (FUN_00BCF2B0, register_pInf_123)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 123.
   */
  void register_pInf_123()
  {
    RegisterPositiveInfinity<123>();
  }

  /**
   * Address: 0x00BCF2D0 (FUN_00BCF2D0, register_nInf_123)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 123 from `pInf_123`.
   */
  void register_nInf_123()
  {
    RegisterNegativeInfinity<123>();
  }

  /**
   * Address: 0x00BCF2F0 (FUN_00BCF2F0, register_NaN_123)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 123.
   */
  void register_NaN_123()
  {
    RegisterQuietNaN<123>();
  }

  /**
   * Address: 0x00BCF530 (FUN_00BCF530, register_pInf_124)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 124.
   */
  void register_pInf_124()
  {
    RegisterPositiveInfinity<124>();
  }

  /**
   * Address: 0x00BCF550 (FUN_00BCF550, register_nInf_124)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 124 from `pInf_124`.
   */
  void register_nInf_124()
  {
    RegisterNegativeInfinity<124>();
  }

  /**
   * Address: 0x00BCF570 (FUN_00BCF570, register_NaN_124)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 124.
   */
  void register_NaN_124()
  {
    RegisterQuietNaN<124>();
  }

  /**
   * Address: 0x00BCFA50 (FUN_00BCFA50, register_pInf_125)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 125.
   */
  void register_pInf_125()
  {
    RegisterPositiveInfinity<125>();
  }

  /**
   * Address: 0x00BCFA70 (FUN_00BCFA70, register_nInf_125)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 125 from `pInf_125`.
   */
  void register_nInf_125()
  {
    RegisterNegativeInfinity<125>();
  }

  /**
   * Address: 0x00BCFA90 (FUN_00BCFA90, register_NaN_125)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 125.
   */
  void register_NaN_125()
  {
    RegisterQuietNaN<125>();
  }

  /**
   * Address: 0x00BCFDC0 (FUN_00BCFDC0, register_pInf_126)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 126.
   */
  void register_pInf_126()
  {
    RegisterPositiveInfinity<126>();
  }

  /**
   * Address: 0x00BCFDE0 (FUN_00BCFDE0, register_nInf_126)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 126 from `pInf_126`.
   */
  void register_nInf_126()
  {
    RegisterNegativeInfinity<126>();
  }

  /**
   * Address: 0x00BCFE00 (FUN_00BCFE00, register_NaN_126)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 126.
   */
  void register_NaN_126()
  {
    RegisterQuietNaN<126>();
  }

  /**
   * Address: 0x00BD0010 (FUN_00BD0010, register_pInf_127)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 127.
   */
  void register_pInf_127()
  {
    RegisterPositiveInfinity<127>();
  }

  /**
   * Address: 0x00BD0030 (FUN_00BD0030, register_nInf_127)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 127 from `pInf_127`.
   */
  void register_nInf_127()
  {
    RegisterNegativeInfinity<127>();
  }

  /**
   * Address: 0x00BD0050 (FUN_00BD0050, register_NaN_127)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 127.
   */
  void register_NaN_127()
  {
    RegisterQuietNaN<127>();
  }

  /**
   * Address: 0x00BD0320 (FUN_00BD0320, register_pInf_128)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 128.
   */
  void register_pInf_128()
  {
    RegisterPositiveInfinity<128>();
  }

  /**
   * Address: 0x00BD0340 (FUN_00BD0340, register_nInf_128)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 128 from `pInf_128`.
   */
  void register_nInf_128()
  {
    RegisterNegativeInfinity<128>();
  }

  /**
   * Address: 0x00BD0360 (FUN_00BD0360, register_NaN_128)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 128.
   */
  void register_NaN_128()
  {
    RegisterQuietNaN<128>();
  }

  /**
   * Address: 0x00BD06F0 (FUN_00BD06F0, register_pInf_129)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 129.
   */
  void register_pInf_129()
  {
    RegisterPositiveInfinity<129>();
  }

  /**
   * Address: 0x00BD0710 (FUN_00BD0710, register_nInf_129)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 129 from `pInf_129`.
   */
  void register_nInf_129()
  {
    RegisterNegativeInfinity<129>();
  }

  /**
   * Address: 0x00BD0730 (FUN_00BD0730, register_NaN_129)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 129.
   */
  void register_NaN_129()
  {
    RegisterQuietNaN<129>();
  }

  /**
   * Address: 0x00BD09A0 (FUN_00BD09A0, register_pInf_130)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 130.
   */
  void register_pInf_130()
  {
    RegisterPositiveInfinity<130>();
  }

  /**
   * Address: 0x00BD09C0 (FUN_00BD09C0, register_nInf_130)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 130 from `pInf_130`.
   */
  void register_nInf_130()
  {
    RegisterNegativeInfinity<130>();
  }

  /**
   * Address: 0x00BD09E0 (FUN_00BD09E0, register_NaN_130)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 130.
   */
  void register_NaN_130()
  {
    RegisterQuietNaN<130>();
  }

  /**
   * Address: 0x00BD0BF0 (FUN_00BD0BF0, register_pInf_131)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 131.
   */
  void register_pInf_131()
  {
    RegisterPositiveInfinity<131>();
  }

  /**
   * Address: 0x00BD0C10 (FUN_00BD0C10, register_nInf_131)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 131 from `pInf_131`.
   */
  void register_nInf_131()
  {
    RegisterNegativeInfinity<131>();
  }

  /**
   * Address: 0x00BD0C30 (FUN_00BD0C30, register_NaN_131)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 131.
   */
  void register_NaN_131()
  {
    RegisterQuietNaN<131>();
  }

  /**
   * Address: 0x00BD0E40 (FUN_00BD0E40, register_pInf_132)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 132.
   */
  void register_pInf_132()
  {
    RegisterPositiveInfinity<132>();
  }

  /**
   * Address: 0x00BD0E60 (FUN_00BD0E60, register_nInf_132)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 132 from `pInf_132`.
   */
  void register_nInf_132()
  {
    RegisterNegativeInfinity<132>();
  }

  /**
   * Address: 0x00BD0E80 (FUN_00BD0E80, register_NaN_132)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 132.
   */
  void register_NaN_132()
  {
    RegisterQuietNaN<132>();
  }

  /**
   * Address: 0x00BD10F0 (FUN_00BD10F0, register_pInf_133)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 133.
   */
  void register_pInf_133()
  {
    RegisterPositiveInfinity<133>();
  }

  /**
   * Address: 0x00BD1110 (FUN_00BD1110, register_nInf_133)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 133 from `pInf_133`.
   */
  void register_nInf_133()
  {
    RegisterNegativeInfinity<133>();
  }

  /**
   * Address: 0x00BD1130 (FUN_00BD1130, register_NaN_133)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 133.
   */
  void register_NaN_133()
  {
    RegisterQuietNaN<133>();
  }

  /**
   * Address: 0x00BD1390 (FUN_00BD1390, register_pInf_134)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 134.
   */
  void register_pInf_134()
  {
    RegisterPositiveInfinity<134>();
  }

  /**
   * Address: 0x00BD13B0 (FUN_00BD13B0, register_nInf_134)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 134 from `pInf_134`.
   */
  void register_nInf_134()
  {
    RegisterNegativeInfinity<134>();
  }

  /**
   * Address: 0x00BD13D0 (FUN_00BD13D0, register_NaN_134)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 134.
   */
  void register_NaN_134()
  {
    RegisterQuietNaN<134>();
  }

  /**
   * Address: 0x00BD15D0 (FUN_00BD15D0, register_pInf_135)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 135.
   */
  void register_pInf_135()
  {
    RegisterPositiveInfinity<135>();
  }

  /**
   * Address: 0x00BD15F0 (FUN_00BD15F0, register_nInf_135)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 135 from `pInf_135`.
   */
  void register_nInf_135()
  {
    RegisterNegativeInfinity<135>();
  }

  /**
   * Address: 0x00BD1610 (FUN_00BD1610, register_NaN_135)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 135.
   */
  void register_NaN_135()
  {
    RegisterQuietNaN<135>();
  }

  /**
   * Address: 0x00BD1820 (FUN_00BD1820, register_pInf_136)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 136.
   */
  void register_pInf_136()
  {
    RegisterPositiveInfinity<136>();
  }

  /**
   * Address: 0x00BD1840 (FUN_00BD1840, register_nInf_136)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 136 from `pInf_136`.
   */
  void register_nInf_136()
  {
    RegisterNegativeInfinity<136>();
  }

  /**
   * Address: 0x00BD1860 (FUN_00BD1860, register_NaN_136)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 136.
   */
  void register_NaN_136()
  {
    RegisterQuietNaN<136>();
  }

  /**
   * Address: 0x00BD18F0 (FUN_00BD18F0, register_pInf_137)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 137.
   */
  void register_pInf_137()
  {
    RegisterPositiveInfinity<137>();
  }

  /**
   * Address: 0x00BD1910 (FUN_00BD1910, register_nInf_137)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 137 from `pInf_137`.
   */
  void register_nInf_137()
  {
    RegisterNegativeInfinity<137>();
  }

  /**
   * Address: 0x00BD1930 (FUN_00BD1930, register_NaN_137)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 137.
   */
  void register_NaN_137()
  {
    RegisterQuietNaN<137>();
  }

  /**
   * Address: 0x00BD1A40 (FUN_00BD1A40, register_pInf_138)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 138.
   */
  void register_pInf_138()
  {
    RegisterPositiveInfinity<138>();
  }

  /**
   * Address: 0x00BD1A60 (FUN_00BD1A60, register_nInf_138)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 138 from `pInf_138`.
   */
  void register_nInf_138()
  {
    RegisterNegativeInfinity<138>();
  }

  /**
   * Address: 0x00BD1A80 (FUN_00BD1A80, register_NaN_138)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 138.
   */
  void register_NaN_138()
  {
    RegisterQuietNaN<138>();
  }

  /**
   * Address: 0x00BD1D70 (FUN_00BD1D70, register_pInf_139)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 139.
   */
  void register_pInf_139()
  {
    RegisterPositiveInfinity<139>();
  }

  /**
   * Address: 0x00BD1D90 (FUN_00BD1D90, register_nInf_139)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 139 from `pInf_139`.
   */
  void register_nInf_139()
  {
    RegisterNegativeInfinity<139>();
  }

  /**
   * Address: 0x00BD1DB0 (FUN_00BD1DB0, register_NaN_139)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 139.
   */
  void register_NaN_139()
  {
    RegisterQuietNaN<139>();
  }

  /**
   * Address: 0x00BD2060 (FUN_00BD2060, register_pInf_140)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 140.
   */
  void register_pInf_140()
  {
    RegisterPositiveInfinity<140>();
  }

  /**
   * Address: 0x00BD2080 (FUN_00BD2080, register_nInf_140)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 140 from `pInf_140`.
   */
  void register_nInf_140()
  {
    RegisterNegativeInfinity<140>();
  }

  /**
   * Address: 0x00BD20A0 (FUN_00BD20A0, register_NaN_140)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 140.
   */
  void register_NaN_140()
  {
    RegisterQuietNaN<140>();
  }

  /**
   * Address: 0x00BD2190 (FUN_00BD2190, register_pInf_141)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 141.
   */
  void register_pInf_141()
  {
    RegisterPositiveInfinity<141>();
  }

  /**
   * Address: 0x00BD21B0 (FUN_00BD21B0, register_nInf_141)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 141 from `pInf_141`.
   */
  void register_nInf_141()
  {
    RegisterNegativeInfinity<141>();
  }

  /**
   * Address: 0x00BD21D0 (FUN_00BD21D0, register_NaN_141)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 141.
   */
  void register_NaN_141()
  {
    RegisterQuietNaN<141>();
  }

  /**
   * Address: 0x00BD2390 (FUN_00BD2390, register_pInf_142)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 142.
   */
  void register_pInf_142()
  {
    RegisterPositiveInfinity<142>();
  }

  /**
   * Address: 0x00BD23B0 (FUN_00BD23B0, register_nInf_142)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 142 from `pInf_142`.
   */
  void register_nInf_142()
  {
    RegisterNegativeInfinity<142>();
  }

  /**
   * Address: 0x00BD23D0 (FUN_00BD23D0, register_NaN_142)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 142.
   */
  void register_NaN_142()
  {
    RegisterQuietNaN<142>();
  }

  /**
   * Address: 0x00BD24E0 (FUN_00BD24E0, register_pInf_143)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 143.
   */
  void register_pInf_143()
  {
    RegisterPositiveInfinity<143>();
  }

  /**
   * Address: 0x00BD2500 (FUN_00BD2500, register_nInf_143)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 143 from `pInf_143`.
   */
  void register_nInf_143()
  {
    RegisterNegativeInfinity<143>();
  }

  /**
   * Address: 0x00BD2520 (FUN_00BD2520, register_NaN_143)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 143.
   */
  void register_NaN_143()
  {
    RegisterQuietNaN<143>();
  }

  /**
   * Address: 0x00BD2650 (FUN_00BD2650, register_pInf_144)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 144.
   */
  void register_pInf_144()
  {
    RegisterPositiveInfinity<144>();
  }

  /**
   * Address: 0x00BD2670 (FUN_00BD2670, register_nInf_144)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 144 from `pInf_144`.
   */
  void register_nInf_144()
  {
    RegisterNegativeInfinity<144>();
  }

  /**
   * Address: 0x00BD2690 (FUN_00BD2690, register_NaN_144)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 144.
   */
  void register_NaN_144()
  {
    RegisterQuietNaN<144>();
  }

  /**
   * Address: 0x00BD27D0 (FUN_00BD27D0, register_pInf_145)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 145.
   */
  void register_pInf_145()
  {
    RegisterPositiveInfinity<145>();
  }

  /**
   * Address: 0x00BD27F0 (FUN_00BD27F0, register_nInf_145)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 145 from `pInf_145`.
   */
  void register_nInf_145()
  {
    RegisterNegativeInfinity<145>();
  }

  /**
   * Address: 0x00BD2810 (FUN_00BD2810, register_NaN_145)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 145.
   */
  void register_NaN_145()
  {
    RegisterQuietNaN<145>();
  }

  /**
   * Address: 0x00BD2A90 (FUN_00BD2A90, register_pInf_146)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 146.
   */
  void register_pInf_146()
  {
    RegisterPositiveInfinity<146>();
  }

  /**
   * Address: 0x00BD2AB0 (FUN_00BD2AB0, register_nInf_146)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 146 from `pInf_146`.
   */
  void register_nInf_146()
  {
    RegisterNegativeInfinity<146>();
  }

  /**
   * Address: 0x00BD2AD0 (FUN_00BD2AD0, register_NaN_146)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 146.
   */
  void register_NaN_146()
  {
    RegisterQuietNaN<146>();
  }

  /**
   * Address: 0x00BD2CE0 (FUN_00BD2CE0, register_pInf_147)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 147.
   */
  void register_pInf_147()
  {
    RegisterPositiveInfinity<147>();
  }

  /**
   * Address: 0x00BD2D00 (FUN_00BD2D00, register_nInf_147)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 147 from `pInf_147`.
   */
  void register_nInf_147()
  {
    RegisterNegativeInfinity<147>();
  }

  /**
   * Address: 0x00BD2D20 (FUN_00BD2D20, register_NaN_147)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 147.
   */
  void register_NaN_147()
  {
    RegisterQuietNaN<147>();
  }

  /**
   * Address: 0x00BD2F40 (FUN_00BD2F40, register_pInf_148)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 148.
   */
  void register_pInf_148()
  {
    RegisterPositiveInfinity<148>();
  }

  /**
   * Address: 0x00BD2F60 (FUN_00BD2F60, register_nInf_148)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 148 from `pInf_148`.
   */
  void register_nInf_148()
  {
    RegisterNegativeInfinity<148>();
  }

  /**
   * Address: 0x00BD2F80 (FUN_00BD2F80, register_NaN_148)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 148.
   */
  void register_NaN_148()
  {
    RegisterQuietNaN<148>();
  }

  /**
   * Address: 0x00BD3120 (FUN_00BD3120, register_pInf_149)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 149.
   */
  void register_pInf_149()
  {
    RegisterPositiveInfinity<149>();
  }

  /**
   * Address: 0x00BD3140 (FUN_00BD3140, register_nInf_149)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 149 from `pInf_149`.
   */
  void register_nInf_149()
  {
    RegisterNegativeInfinity<149>();
  }

  /**
   * Address: 0x00BD3160 (FUN_00BD3160, register_NaN_149)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 149.
   */
  void register_NaN_149()
  {
    RegisterQuietNaN<149>();
  }

  /**
   * Address: 0x00BD3270 (FUN_00BD3270, register_pInf_150)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 150.
   */
  void register_pInf_150()
  {
    RegisterPositiveInfinity<150>();
  }

  /**
   * Address: 0x00BD3290 (FUN_00BD3290, register_nInf_150)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 150 from `pInf_150`.
   */
  void register_nInf_150()
  {
    RegisterNegativeInfinity<150>();
  }

  /**
   * Address: 0x00BD32B0 (FUN_00BD32B0, register_NaN_150)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 150.
   */
  void register_NaN_150()
  {
    RegisterQuietNaN<150>();
  }

  /**
   * Address: 0x00BD3590 (FUN_00BD3590, register_pInf_151)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 151.
   */
  void register_pInf_151()
  {
    RegisterPositiveInfinity<151>();
  }

  /**
   * Address: 0x00BD35B0 (FUN_00BD35B0, register_nInf_151)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 151 from `pInf_151`.
   */
  void register_nInf_151()
  {
    RegisterNegativeInfinity<151>();
  }

  /**
   * Address: 0x00BD35D0 (FUN_00BD35D0, register_NaN_151)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 151.
   */
  void register_NaN_151()
  {
    RegisterQuietNaN<151>();
  }

  /**
   * Address: 0x00BD36D0 (FUN_00BD36D0, register_pInf_152)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 152.
   */
  void register_pInf_152()
  {
    RegisterPositiveInfinity<152>();
  }

  /**
   * Address: 0x00BD36F0 (FUN_00BD36F0, register_nInf_152)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 152 from `pInf_152`.
   */
  void register_nInf_152()
  {
    RegisterNegativeInfinity<152>();
  }

  /**
   * Address: 0x00BD3710 (FUN_00BD3710, register_NaN_152)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 152.
   */
  void register_NaN_152()
  {
    RegisterQuietNaN<152>();
  }

  /**
   * Address: 0x00BD3830 (FUN_00BD3830, register_pInf_153)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 153.
   */
  void register_pInf_153()
  {
    RegisterPositiveInfinity<153>();
  }

  /**
   * Address: 0x00BD3850 (FUN_00BD3850, register_nInf_153)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 153 from `pInf_153`.
   */
  void register_nInf_153()
  {
    RegisterNegativeInfinity<153>();
  }

  /**
   * Address: 0x00BD3870 (FUN_00BD3870, register_NaN_153)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 153.
   */
  void register_NaN_153()
  {
    RegisterQuietNaN<153>();
  }

  /**
   * Address: 0x00BD3AD0 (FUN_00BD3AD0, register_pInf_154)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 154.
   */
  void register_pInf_154()
  {
    RegisterPositiveInfinity<154>();
  }

  /**
   * Address: 0x00BD3AF0 (FUN_00BD3AF0, register_nInf_154)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 154 from `pInf_154`.
   */
  void register_nInf_154()
  {
    RegisterNegativeInfinity<154>();
  }

  /**
   * Address: 0x00BD3B10 (FUN_00BD3B10, register_NaN_154)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 154.
   */
  void register_NaN_154()
  {
    RegisterQuietNaN<154>();
  }

  /**
   * Address: 0x00BD3B50 (FUN_00BD3B50, register_pInf_155)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 155.
   */
  void register_pInf_155()
  {
    RegisterPositiveInfinity<155>();
  }

  /**
   * Address: 0x00BD3B70 (FUN_00BD3B70, register_nInf_155)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 155 from `pInf_155`.
   */
  void register_nInf_155()
  {
    RegisterNegativeInfinity<155>();
  }

  /**
   * Address: 0x00BD3B90 (FUN_00BD3B90, register_NaN_155)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 155.
   */
  void register_NaN_155()
  {
    RegisterQuietNaN<155>();
  }

  /**
   * Address: 0x00BD3C10 (FUN_00BD3C10, register_pInf_156)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 156.
   */
  void register_pInf_156()
  {
    RegisterPositiveInfinity<156>();
  }

  /**
   * Address: 0x00BD3C30 (FUN_00BD3C30, register_nInf_156)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 156 from `pInf_156`.
   */
  void register_nInf_156()
  {
    RegisterNegativeInfinity<156>();
  }

  /**
   * Address: 0x00BD3C50 (FUN_00BD3C50, register_NaN_156)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 156.
   */
  void register_NaN_156()
  {
    RegisterQuietNaN<156>();
  }

  /**
   * Address: 0x00BD3CD0 (FUN_00BD3CD0, register_pInf_157)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 157.
   */
  void register_pInf_157()
  {
    RegisterPositiveInfinity<157>();
  }

  /**
   * Address: 0x00BD3CF0 (FUN_00BD3CF0, register_nInf_157)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 157 from `pInf_157`.
   */
  void register_nInf_157()
  {
    RegisterNegativeInfinity<157>();
  }

  /**
   * Address: 0x00BD3D10 (FUN_00BD3D10, register_NaN_157)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 157.
   */
  void register_NaN_157()
  {
    RegisterQuietNaN<157>();
  }

  /**
   * Address: 0x00BD3E00 (FUN_00BD3E00, register_pInf_158)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 158.
   */
  void register_pInf_158()
  {
    RegisterPositiveInfinity<158>();
  }

  /**
   * Address: 0x00BD3E20 (FUN_00BD3E20, register_nInf_158)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 158 from `pInf_158`.
   */
  void register_nInf_158()
  {
    RegisterNegativeInfinity<158>();
  }

  /**
   * Address: 0x00BD3E40 (FUN_00BD3E40, register_NaN_158)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 158.
   */
  void register_NaN_158()
  {
    RegisterQuietNaN<158>();
  }

  /**
   * Address: 0x00BD3E80 (FUN_00BD3E80, register_pInf_159)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 159.
   */
  void register_pInf_159()
  {
    RegisterPositiveInfinity<159>();
  }

  /**
   * Address: 0x00BD3EA0 (FUN_00BD3EA0, register_nInf_159)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 159 from `pInf_159`.
   */
  void register_nInf_159()
  {
    RegisterNegativeInfinity<159>();
  }

  /**
   * Address: 0x00BD3EC0 (FUN_00BD3EC0, register_NaN_159)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 159.
   */
  void register_NaN_159()
  {
    RegisterQuietNaN<159>();
  }

  /**
   * Address: 0x00BD4050 (FUN_00BD4050, register_pInf_160)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 160.
   */
  void register_pInf_160()
  {
    RegisterPositiveInfinity<160>();
  }

  /**
   * Address: 0x00BD4070 (FUN_00BD4070, register_nInf_160)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 160 from `pInf_160`.
   */
  void register_nInf_160()
  {
    RegisterNegativeInfinity<160>();
  }

  /**
   * Address: 0x00BD4090 (FUN_00BD4090, register_NaN_160)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 160.
   */
  void register_NaN_160()
  {
    RegisterQuietNaN<160>();
  }

  /**
   * Address: 0x00BD41B0 (FUN_00BD41B0, register_pInf_161)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 161.
   */
  void register_pInf_161()
  {
    RegisterPositiveInfinity<161>();
  }

  /**
   * Address: 0x00BD41D0 (FUN_00BD41D0, register_nInf_161)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 161 from `pInf_161`.
   */
  void register_nInf_161()
  {
    RegisterNegativeInfinity<161>();
  }

  /**
   * Address: 0x00BD41F0 (FUN_00BD41F0, register_NaN_161)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 161.
   */
  void register_NaN_161()
  {
    RegisterQuietNaN<161>();
  }

  /**
   * Address: 0x00BD4460 (FUN_00BD4460, register_pInf_162)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 162.
   */
  void register_pInf_162()
  {
    RegisterPositiveInfinity<162>();
  }

  /**
   * Address: 0x00BD4480 (FUN_00BD4480, register_nInf_162)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 162 from `pInf_162`.
   */
  void register_nInf_162()
  {
    RegisterNegativeInfinity<162>();
  }

  /**
   * Address: 0x00BD44A0 (FUN_00BD44A0, register_NaN_162)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 162.
   */
  void register_NaN_162()
  {
    RegisterQuietNaN<162>();
  }

  /**
   * Address: 0x00BD4510 (FUN_00BD4510, register_pInf_163)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 163.
   */
  void register_pInf_163()
  {
    RegisterPositiveInfinity<163>();
  }

  /**
   * Address: 0x00BD4530 (FUN_00BD4530, register_nInf_163)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 163 from `pInf_163`.
   */
  void register_nInf_163()
  {
    RegisterNegativeInfinity<163>();
  }

  /**
   * Address: 0x00BD4550 (FUN_00BD4550, register_NaN_163)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 163.
   */
  void register_NaN_163()
  {
    RegisterQuietNaN<163>();
  }

  /**
   * Address: 0x00BD46C0 (FUN_00BD46C0, register_pInf_164)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 164.
   */
  void register_pInf_164()
  {
    RegisterPositiveInfinity<164>();
  }

  /**
   * Address: 0x00BD46E0 (FUN_00BD46E0, register_nInf_164)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 164 from `pInf_164`.
   */
  void register_nInf_164()
  {
    RegisterNegativeInfinity<164>();
  }

  /**
   * Address: 0x00BD4700 (FUN_00BD4700, register_NaN_164)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 164.
   */
  void register_NaN_164()
  {
    RegisterQuietNaN<164>();
  }

  /**
   * Address: 0x00BD48B0 (FUN_00BD48B0, register_pInf_165)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 165.
   */
  void register_pInf_165()
  {
    RegisterPositiveInfinity<165>();
  }

  /**
   * Address: 0x00BD48D0 (FUN_00BD48D0, register_nInf_165)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 165 from `pInf_165`.
   */
  void register_nInf_165()
  {
    RegisterNegativeInfinity<165>();
  }

  /**
   * Address: 0x00BD48F0 (FUN_00BD48F0, register_NaN_165)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 165.
   */
  void register_NaN_165()
  {
    RegisterQuietNaN<165>();
  }

  /**
   * Address: 0x00BD49C0 (FUN_00BD49C0, register_pInf_166)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 166.
   */
  void register_pInf_166()
  {
    RegisterPositiveInfinity<166>();
  }

  /**
   * Address: 0x00BD49E0 (FUN_00BD49E0, register_nInf_166)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 166 from `pInf_166`.
   */
  void register_nInf_166()
  {
    RegisterNegativeInfinity<166>();
  }

  /**
   * Address: 0x00BD4A00 (FUN_00BD4A00, register_NaN_166)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 166.
   */
  void register_NaN_166()
  {
    RegisterQuietNaN<166>();
  }

  /**
   * Address: 0x00BD4E20 (FUN_00BD4E20, register_pInf_167)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 167.
   */
  void register_pInf_167()
  {
    RegisterPositiveInfinity<167>();
  }

  /**
   * Address: 0x00BD4E40 (FUN_00BD4E40, register_nInf_167)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 167 from `pInf_167`.
   */
  void register_nInf_167()
  {
    RegisterNegativeInfinity<167>();
  }

  /**
   * Address: 0x00BD4E60 (FUN_00BD4E60, register_NaN_167)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 167.
   */
  void register_NaN_167()
  {
    RegisterQuietNaN<167>();
  }

  /**
   * Address: 0x00BD5110 (FUN_00BD5110, register_pInf_168)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 168.
   */
  void register_pInf_168()
  {
    RegisterPositiveInfinity<168>();
  }

  /**
   * Address: 0x00BD5130 (FUN_00BD5130, register_nInf_168)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 168 from `pInf_168`.
   */
  void register_nInf_168()
  {
    RegisterNegativeInfinity<168>();
  }

  /**
   * Address: 0x00BD5150 (FUN_00BD5150, register_NaN_168)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 168.
   */
  void register_NaN_168()
  {
    RegisterQuietNaN<168>();
  }

  /**
   * Address: 0x00BD52A0 (FUN_00BD52A0, register_pInf_169)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 169.
   */
  void register_pInf_169()
  {
    RegisterPositiveInfinity<169>();
  }

  /**
   * Address: 0x00BD52C0 (FUN_00BD52C0, register_nInf_169)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 169 from `pInf_169`.
   */
  void register_nInf_169()
  {
    RegisterNegativeInfinity<169>();
  }

  /**
   * Address: 0x00BD52E0 (FUN_00BD52E0, register_NaN_169)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 169.
   */
  void register_NaN_169()
  {
    RegisterQuietNaN<169>();
  }

  /**
   * Address: 0x00BD5700 (FUN_00BD5700, register_pInf_170)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 170.
   */
  void register_pInf_170()
  {
    RegisterPositiveInfinity<170>();
  }

  /**
   * Address: 0x00BD5720 (FUN_00BD5720, register_nInf_170)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 170 from `pInf_170`.
   */
  void register_nInf_170()
  {
    RegisterNegativeInfinity<170>();
  }

  /**
   * Address: 0x00BD5740 (FUN_00BD5740, register_NaN_170)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 170.
   */
  void register_NaN_170()
  {
    RegisterQuietNaN<170>();
  }

  /**
   * Address: 0x00BD58B0 (FUN_00BD58B0, register_pInf_171)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 171.
   */
  void register_pInf_171()
  {
    RegisterPositiveInfinity<171>();
  }

  /**
   * Address: 0x00BD58D0 (FUN_00BD58D0, register_nInf_171)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 171 from `pInf_171`.
   */
  void register_nInf_171()
  {
    RegisterNegativeInfinity<171>();
  }

  /**
   * Address: 0x00BD58F0 (FUN_00BD58F0, register_NaN_171)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 171.
   */
  void register_NaN_171()
  {
    RegisterQuietNaN<171>();
  }

  /**
   * Address: 0x00BD5970 (FUN_00BD5970, register_pInf_172)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 172.
   */
  void register_pInf_172()
  {
    RegisterPositiveInfinity<172>();
  }

  /**
   * Address: 0x00BD5990 (FUN_00BD5990, register_nInf_172)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 172 from `pInf_172`.
   */
  void register_nInf_172()
  {
    RegisterNegativeInfinity<172>();
  }

  /**
   * Address: 0x00BD59B0 (FUN_00BD59B0, register_NaN_172)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 172.
   */
  void register_NaN_172()
  {
    RegisterQuietNaN<172>();
  }

  /**
   * Address: 0x00BD5CE0 (FUN_00BD5CE0, register_pInf_173)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 173.
   */
  void register_pInf_173()
  {
    RegisterPositiveInfinity<173>();
  }

  /**
   * Address: 0x00BD5D00 (FUN_00BD5D00, register_nInf_173)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 173 from `pInf_173`.
   */
  void register_nInf_173()
  {
    RegisterNegativeInfinity<173>();
  }

  /**
   * Address: 0x00BD5D20 (FUN_00BD5D20, register_NaN_173)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 173.
   */
  void register_NaN_173()
  {
    RegisterQuietNaN<173>();
  }

  /**
   * Address: 0x00BD5E20 (FUN_00BD5E20, register_pInf_174)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 174.
   */
  void register_pInf_174()
  {
    RegisterPositiveInfinity<174>();
  }

  /**
   * Address: 0x00BD5E40 (FUN_00BD5E40, register_nInf_174)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 174 from `pInf_174`.
   */
  void register_nInf_174()
  {
    RegisterNegativeInfinity<174>();
  }

  /**
   * Address: 0x00BD5E60 (FUN_00BD5E60, register_NaN_174)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 174.
   */
  void register_NaN_174()
  {
    RegisterQuietNaN<174>();
  }

  /**
   * Address: 0x00BD5F60 (FUN_00BD5F60, register_pInf_175)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 175.
   */
  void register_pInf_175()
  {
    RegisterPositiveInfinity<175>();
  }

  /**
   * Address: 0x00BD5F80 (FUN_00BD5F80, register_nInf_175)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 175 from `pInf_175`.
   */
  void register_nInf_175()
  {
    RegisterNegativeInfinity<175>();
  }

  /**
   * Address: 0x00BD5FA0 (FUN_00BD5FA0, register_NaN_175)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 175.
   */
  void register_NaN_175()
  {
    RegisterQuietNaN<175>();
  }

  /**
   * Address: 0x00BD5FD0 (FUN_00BD5FD0, register_pInf_176)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 176.
   */
  void register_pInf_176()
  {
    RegisterPositiveInfinity<176>();
  }

  /**
   * Address: 0x00BD5FF0 (FUN_00BD5FF0, register_nInf_176)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 176 from `pInf_176`.
   */
  void register_nInf_176()
  {
    RegisterNegativeInfinity<176>();
  }

  /**
   * Address: 0x00BD6010 (FUN_00BD6010, register_NaN_176)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 176.
   */
  void register_NaN_176()
  {
    RegisterQuietNaN<176>();
  }

  /**
   * Address: 0x00BD6110 (FUN_00BD6110, register_pInf_177)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 177.
   */
  void register_pInf_177()
  {
    RegisterPositiveInfinity<177>();
  }

  /**
   * Address: 0x00BD6130 (FUN_00BD6130, register_nInf_177)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 177 from `pInf_177`.
   */
  void register_nInf_177()
  {
    RegisterNegativeInfinity<177>();
  }

  /**
   * Address: 0x00BD6150 (FUN_00BD6150, register_NaN_177)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 177.
   */
  void register_NaN_177()
  {
    RegisterQuietNaN<177>();
  }

  /**
   * Address: 0x00BD6510 (FUN_00BD6510, register_pInf_178)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 178.
   */
  void register_pInf_178()
  {
    RegisterPositiveInfinity<178>();
  }

  /**
   * Address: 0x00BD6530 (FUN_00BD6530, register_nInf_178)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 178 from `pInf_178`.
   */
  void register_nInf_178()
  {
    RegisterNegativeInfinity<178>();
  }

  /**
   * Address: 0x00BD6550 (FUN_00BD6550, register_NaN_178)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 178.
   */
  void register_NaN_178()
  {
    RegisterQuietNaN<178>();
  }

  /**
   * Address: 0x00BD6570 (FUN_00BD6570, register_pInf_179)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 179.
   */
  void register_pInf_179()
  {
    RegisterPositiveInfinity<179>();
  }

  /**
   * Address: 0x00BD6590 (FUN_00BD6590, register_nInf_179)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 179 from `pInf_179`.
   */
  void register_nInf_179()
  {
    RegisterNegativeInfinity<179>();
  }

  /**
   * Address: 0x00BD65B0 (FUN_00BD65B0, register_NaN_179)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 179.
   */
  void register_NaN_179()
  {
    RegisterQuietNaN<179>();
  }

  /**
   * Address: 0x00BD6810 (FUN_00BD6810, register_pInf_180)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 180.
   */
  void register_pInf_180()
  {
    RegisterPositiveInfinity<180>();
  }

  /**
   * Address: 0x00BD6830 (FUN_00BD6830, register_nInf_180)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 180 from `pInf_180`.
   */
  void register_nInf_180()
  {
    RegisterNegativeInfinity<180>();
  }

  /**
   * Address: 0x00BD6850 (FUN_00BD6850, register_NaN_180)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 180.
   */
  void register_NaN_180()
  {
    RegisterQuietNaN<180>();
  }

  /**
   * Address: 0x00BC3B40 (FUN_00BC3B40, register_pInf_20)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 20.
   */
  void register_pInf_20()
  {
    RegisterPositiveInfinity<20>();
  }

  /**
   * Address: 0x00BC3B60 (FUN_00BC3B60, register_nInf_20)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 20 from `pInf_20`.
   */
  void register_nInf_20()
  {
    RegisterNegativeInfinity<20>();
  }

  /**
   * Address: 0x00BC3B80 (FUN_00BC3B80, register_NaN_20)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 20.
   */
  void register_NaN_20()
  {
    RegisterQuietNaN<20>();
  }

  /**
   * Address: 0x00BC3BE0 (FUN_00BC3BE0, register_pInf_21)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 21.
   */
  void register_pInf_21()
  {
    RegisterPositiveInfinity<21>();
  }

  /**
   * Address: 0x00BC3C00 (FUN_00BC3C00, register_nInf_21)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 21 from `pInf_21`.
   */
  void register_nInf_21()
  {
    RegisterNegativeInfinity<21>();
  }

  /**
   * Address: 0x00BC3C20 (FUN_00BC3C20, register_NaN_21)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 21.
   */
  void register_NaN_21()
  {
    RegisterQuietNaN<21>();
  }

  /**
   * Address: 0x00BC3CA0 (FUN_00BC3CA0, register_pInf_22)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 22.
   */
  void register_pInf_22()
  {
    RegisterPositiveInfinity<22>();
  }

  /**
   * Address: 0x00BC3CC0 (FUN_00BC3CC0, register_nInf_22)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 22 from `pInf_22`.
   */
  void register_nInf_22()
  {
    RegisterNegativeInfinity<22>();
  }

  /**
   * Address: 0x00BC3CE0 (FUN_00BC3CE0, register_NaN_22)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 22.
   */
  void register_NaN_22()
  {
    RegisterQuietNaN<22>();
  }

  /**
   * Address: 0x00BC3F80 (FUN_00BC3F80, register_pInf_23)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 23.
   */
  void register_pInf_23()
  {
    RegisterPositiveInfinity<23>();
  }

  /**
   * Address: 0x00BC3FA0 (FUN_00BC3FA0, register_nInf_23)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 23 from `pInf_23`.
   */
  void register_nInf_23()
  {
    RegisterNegativeInfinity<23>();
  }

  /**
   * Address: 0x00BC3FC0 (FUN_00BC3FC0, register_NaN_23)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 23.
   */
  void register_NaN_23()
  {
    RegisterQuietNaN<23>();
  }

  /**
   * Address: 0x00BC4060 (FUN_00BC4060, register_pInf_24)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 24.
   */
  void register_pInf_24()
  {
    RegisterPositiveInfinity<24>();
  }

  /**
   * Address: 0x00BC4080 (FUN_00BC4080, register_nInf_24)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 24 from `pInf_24`.
   */
  void register_nInf_24()
  {
    RegisterNegativeInfinity<24>();
  }

  /**
   * Address: 0x00BC40A0 (FUN_00BC40A0, register_NaN_24)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 24.
   */
  void register_NaN_24()
  {
    RegisterQuietNaN<24>();
  }

  /**
   * Address: 0x00BC40F0 (FUN_00BC40F0, register_pInf_25)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 25.
   */
  void register_pInf_25()
  {
    RegisterPositiveInfinity<25>();
  }

  /**
   * Address: 0x00BC4110 (FUN_00BC4110, register_nInf_25)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 25 from `pInf_25`.
   */
  void register_nInf_25()
  {
    RegisterNegativeInfinity<25>();
  }

  /**
   * Address: 0x00BC4130 (FUN_00BC4130, register_NaN_25)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 25.
   */
  void register_NaN_25()
  {
    RegisterQuietNaN<25>();
  }

  /**
   * Address: 0x00BC4270 (FUN_00BC4270, register_pInf_26)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 26.
   */
  void register_pInf_26()
  {
    RegisterPositiveInfinity<26>();
  }

  /**
   * Address: 0x00BC4290 (FUN_00BC4290, register_nInf_26)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 26 from `pInf_26`.
   */
  void register_nInf_26()
  {
    RegisterNegativeInfinity<26>();
  }

  /**
   * Address: 0x00BC42B0 (FUN_00BC42B0, register_NaN_26)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 26.
   */
  void register_NaN_26()
  {
    RegisterQuietNaN<26>();
  }

  /**
   * Address: 0x00BC42E0 (FUN_00BC42E0, register_pInf_27)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 27.
   */
  void register_pInf_27()
  {
    RegisterPositiveInfinity<27>();
  }

  /**
   * Address: 0x00BC4300 (FUN_00BC4300, register_nInf_27)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 27 from `pInf_27`.
   */
  void register_nInf_27()
  {
    RegisterNegativeInfinity<27>();
  }

  /**
   * Address: 0x00BC4320 (FUN_00BC4320, register_NaN_27)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 27.
   */
  void register_NaN_27()
  {
    RegisterQuietNaN<27>();
  }

  /**
   * Address: 0x00BD6C20 (FUN_00BD6C20, register_pInf_181)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 181.
   */
  void register_pInf_181()
  {
    RegisterPositiveInfinity<181>();
  }

  /**
   * Address: 0x00BD6C40 (FUN_00BD6C40, register_nInf_181)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 181 from `pInf_181`.
   */
  void register_nInf_181()
  {
    RegisterNegativeInfinity<181>();
  }

  /**
   * Address: 0x00BD6C60 (FUN_00BD6C60, register_NaN_181)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 181.
   */
  void register_NaN_181()
  {
    RegisterQuietNaN<181>();
  }

  /**
   * Address: 0x00BD6D80 (FUN_00BD6D80, register_pInf_182)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 182.
   */
  void register_pInf_182()
  {
    RegisterPositiveInfinity<182>();
  }

  /**
   * Address: 0x00BD6DA0 (FUN_00BD6DA0, register_nInf_182)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 182 from `pInf_182`.
   */
  void register_nInf_182()
  {
    RegisterNegativeInfinity<182>();
  }

  /**
   * Address: 0x00BD6DC0 (FUN_00BD6DC0, register_NaN_182)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 182.
   */
  void register_NaN_182()
  {
    RegisterQuietNaN<182>();
  }

  /**
   * Address: 0x00BD72D0 (FUN_00BD72D0, register_pInf_183)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 183.
   */
  void register_pInf_183()
  {
    RegisterPositiveInfinity<183>();
  }

  /**
   * Address: 0x00BD72F0 (FUN_00BD72F0, register_nInf_183)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 183 from `pInf_183`.
   */
  void register_nInf_183()
  {
    RegisterNegativeInfinity<183>();
  }

  /**
   * Address: 0x00BD7310 (FUN_00BD7310, register_NaN_183)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 183.
   */
  void register_NaN_183()
  {
    RegisterQuietNaN<183>();
  }

  /**
   * Address: 0x00BD7540 (FUN_00BD7540, register_pInf_184)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 184.
   */
  void register_pInf_184()
  {
    RegisterPositiveInfinity<184>();
  }

  /**
   * Address: 0x00BD7560 (FUN_00BD7560, register_nInf_184)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 184 from `pInf_184`.
   */
  void register_nInf_184()
  {
    RegisterNegativeInfinity<184>();
  }

  /**
   * Address: 0x00BD7580 (FUN_00BD7580, register_NaN_184)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 184.
   */
  void register_NaN_184()
  {
    RegisterQuietNaN<184>();
  }

  /**
   * Address: 0x00BD7720 (FUN_00BD7720, register_pInf_185)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 185.
   */
  void register_pInf_185()
  {
    RegisterPositiveInfinity<185>();
  }

  /**
   * Address: 0x00BD7740 (FUN_00BD7740, register_nInf_185)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 185 from `pInf_185`.
   */
  void register_nInf_185()
  {
    RegisterNegativeInfinity<185>();
  }

  /**
   * Address: 0x00BD7760 (FUN_00BD7760, register_NaN_185)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 185.
   */
  void register_NaN_185()
  {
    RegisterQuietNaN<185>();
  }

  /**
   * Address: 0x00BD83F0 (FUN_00BD83F0, register_pInf_186)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 186.
   */
  void register_pInf_186()
  {
    RegisterPositiveInfinity<186>();
  }

  /**
   * Address: 0x00BD8410 (FUN_00BD8410, register_nInf_186)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 186 from `pInf_186`.
   */
  void register_nInf_186()
  {
    RegisterNegativeInfinity<186>();
  }

  /**
   * Address: 0x00BD8430 (FUN_00BD8430, register_NaN_186)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 186.
   */
  void register_NaN_186()
  {
    RegisterQuietNaN<186>();
  }

  /**
   * Address: 0x00BD8530 (FUN_00BD8530, register_pInf_187)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 187.
   */
  void register_pInf_187()
  {
    RegisterPositiveInfinity<187>();
  }

  /**
   * Address: 0x00BD8550 (FUN_00BD8550, register_nInf_187)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 187 from `pInf_187`.
   */
  void register_nInf_187()
  {
    RegisterNegativeInfinity<187>();
  }

  /**
   * Address: 0x00BD8570 (FUN_00BD8570, register_NaN_187)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 187.
   */
  void register_NaN_187()
  {
    RegisterQuietNaN<187>();
  }

  /**
   * Address: 0x00BD8BD0 (FUN_00BD8BD0, register_pInf_188)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 188.
   */
  void register_pInf_188()
  {
    RegisterPositiveInfinity<188>();
  }

  /**
   * Address: 0x00BD8BF0 (FUN_00BD8BF0, register_nInf_188)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 188 from `pInf_188`.
   */
  void register_nInf_188()
  {
    RegisterNegativeInfinity<188>();
  }

  /**
   * Address: 0x00BD8C10 (FUN_00BD8C10, register_NaN_188)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 188.
   */
  void register_NaN_188()
  {
    RegisterQuietNaN<188>();
  }

  /**
   * Address: 0x00BD8D10 (FUN_00BD8D10, register_pInf_189)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 189.
   */
  void register_pInf_189()
  {
    RegisterPositiveInfinity<189>();
  }

  /**
   * Address: 0x00BD8D30 (FUN_00BD8D30, register_nInf_189)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 189 from `pInf_189`.
   */
  void register_nInf_189()
  {
    RegisterNegativeInfinity<189>();
  }

  /**
   * Address: 0x00BD8D50 (FUN_00BD8D50, register_NaN_189)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 189.
   */
  void register_NaN_189()
  {
    RegisterQuietNaN<189>();
  }

  /**
   * Address: 0x00BD8D80 (FUN_00BD8D80, register_pInf_190)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 190.
   */
  void register_pInf_190()
  {
    RegisterPositiveInfinity<190>();
  }

  /**
   * Address: 0x00BD8DA0 (FUN_00BD8DA0, register_nInf_190)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 190 from `pInf_190`.
   */
  void register_nInf_190()
  {
    RegisterNegativeInfinity<190>();
  }

  /**
   * Address: 0x00BD8DC0 (FUN_00BD8DC0, register_NaN_190)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 190.
   */
  void register_NaN_190()
  {
    RegisterQuietNaN<190>();
  }

  /**
   * Address: 0x00BD8DF0 (FUN_00BD8DF0, register_pInf_191)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 191.
   */
  void register_pInf_191()
  {
    RegisterPositiveInfinity<191>();
  }

  /**
   * Address: 0x00BD8E10 (FUN_00BD8E10, register_nInf_191)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 191 from `pInf_191`.
   */
  void register_nInf_191()
  {
    RegisterNegativeInfinity<191>();
  }

  /**
   * Address: 0x00BD8E30 (FUN_00BD8E30, register_NaN_191)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 191.
   */
  void register_NaN_191()
  {
    RegisterQuietNaN<191>();
  }

  /**
   * Address: 0x00BD8E70 (FUN_00BD8E70, register_pInf_192)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 192.
   */
  void register_pInf_192()
  {
    RegisterPositiveInfinity<192>();
  }

  /**
   * Address: 0x00BD8E90 (FUN_00BD8E90, register_nInf_192)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 192 from `pInf_192`.
   */
  void register_nInf_192()
  {
    RegisterNegativeInfinity<192>();
  }

  /**
   * Address: 0x00BD8EB0 (FUN_00BD8EB0, register_NaN_192)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 192.
   */
  void register_NaN_192()
  {
    RegisterQuietNaN<192>();
  }

  /**
   * Address: 0x00BD9080 (FUN_00BD9080, register_pInf_193)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 193.
   */
  void register_pInf_193()
  {
    RegisterPositiveInfinity<193>();
  }

  /**
   * Address: 0x00BD90A0 (FUN_00BD90A0, register_nInf_193)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 193 from `pInf_193`.
   */
  void register_nInf_193()
  {
    RegisterNegativeInfinity<193>();
  }

  /**
   * Address: 0x00BD90C0 (FUN_00BD90C0, register_NaN_193)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 193.
   */
  void register_NaN_193()
  {
    RegisterQuietNaN<193>();
  }

  /**
   * Address: 0x00BD9620 (FUN_00BD9620, register_pInf_194)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 194.
   */
  void register_pInf_194()
  {
    RegisterPositiveInfinity<194>();
  }

  /**
   * Address: 0x00BD9640 (FUN_00BD9640, register_nInf_194)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 194 from `pInf_194`.
   */
  void register_nInf_194()
  {
    RegisterNegativeInfinity<194>();
  }

  /**
   * Address: 0x00BD9660 (FUN_00BD9660, register_NaN_194)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 194.
   */
  void register_NaN_194()
  {
    RegisterQuietNaN<194>();
  }

  /**
   * Address: 0x00BD9960 (FUN_00BD9960, register_pInf_195)
   *
   * What it does:
   * Initializes the first recovered positive-infinity lane.
   */
  void register_pInf_195()
  {
    RegisterPositiveInfinity<195>();
  }

  /**
   * Address: 0x00BD9980 (FUN_00BD9980, register_nInf_195)
   *
   * What it does:
   * Initializes the first recovered negative-infinity lane from `pInf_195`.
   */
  void register_nInf_195()
  {
    RegisterNegativeInfinity<195>();
  }

  /**
   * Address: 0x00BD99A0 (FUN_00BD99A0, register_NaN_195)
   *
   * What it does:
   * Initializes the first recovered quiet-NaN lane.
   */
  void register_NaN_195()
  {
    RegisterQuietNaN<195>();
  }

  /**
   * Address: 0x00BD99D0 (FUN_00BD99D0, register_pInf_196)
   *
   * What it does:
   * Initializes the second recovered positive-infinity lane.
   */
  void register_pInf_196()
  {
    RegisterPositiveInfinity<196>();
  }

  /**
   * Address: 0x00BD99F0 (FUN_00BD99F0, register_nInf_196)
   *
   * What it does:
   * Initializes the second recovered negative-infinity lane from `pInf_196`.
   */
  void register_nInf_196()
  {
    RegisterNegativeInfinity<196>();
  }

  /**
   * Address: 0x00BD9A10 (FUN_00BD9A10, register_NaN_196)
   *
   * What it does:
   * Initializes the second recovered quiet-NaN lane.
   */
  void register_NaN_196()
  {
    RegisterQuietNaN<196>();
  }

  /**
   * Address: 0x00BD9AC0 (FUN_00BD9AC0, register_pInf_197)
   *
   * What it does:
   * Initializes the third recovered positive-infinity lane.
   */
  void register_pInf_197()
  {
    RegisterPositiveInfinity<197>();
  }

  /**
   * Address: 0x00BD9AE0 (FUN_00BD9AE0, register_nInf_197)
   *
   * What it does:
   * Initializes the third recovered negative-infinity lane from `pInf_197`.
   */
  void register_nInf_197()
  {
    RegisterNegativeInfinity<197>();
  }

  /**
   * Address: 0x00BD9B00 (FUN_00BD9B00, register_NaN_197)
   *
   * What it does:
   * Initializes the third recovered quiet-NaN lane.
   */
  void register_NaN_197()
  {
    RegisterQuietNaN<197>();
  }

  /**
   * Address: 0x00BD9C90 (FUN_00BD9C90, register_pInf_198)
   *
   * What it does:
   * Initializes the fourth recovered positive-infinity lane.
   */
  void register_pInf_198()
  {
    RegisterPositiveInfinity<198>();
  }

  /**
   * Address: 0x00BD9CB0 (FUN_00BD9CB0, register_nInf_198)
   *
   * What it does:
   * Initializes the fourth recovered negative-infinity lane from `pInf_198`.
   */
  void register_nInf_198()
  {
    RegisterNegativeInfinity<198>();
  }

  /**
   * Address: 0x00BD9CD0 (FUN_00BD9CD0, register_NaN_198)
   *
   * What it does:
   * Initializes the fourth recovered quiet-NaN lane.
   */
  void register_NaN_198()
  {
    RegisterQuietNaN<198>();
  }

  /**
   * Address: 0x00BD9F70 (FUN_00BD9F70, register_pInf_199)
   *
   * What it does:
   * Initializes the fifth recovered positive-infinity lane.
   */
  void register_pInf_199()
  {
    RegisterPositiveInfinity<199>();
  }

  /**
   * Address: 0x00BD9F90 (FUN_00BD9F90, register_nInf_199)
   *
   * What it does:
   * Initializes the fifth recovered negative-infinity lane from `pInf_199`.
   */
  void register_nInf_199()
  {
    RegisterNegativeInfinity<199>();
  }

  /**
   * Address: 0x00BD9FB0 (FUN_00BD9FB0, register_NaN_199)
   *
   * What it does:
   * Initializes the fifth recovered quiet-NaN lane.
   */
  void register_NaN_199()
  {
    RegisterQuietNaN<199>();
  }
} // namespace moho








namespace
{
  template <>
  struct SimFloatSlot<0>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<0>::pInf = 0.0f;
  float SimFloatSlot<0>::nInf = 0.0f;
  float SimFloatSlot<0>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<1>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<1>::pInf = 0.0f;
  float SimFloatSlot<1>::nInf = 0.0f;
  float SimFloatSlot<1>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<2>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<2>::pInf = 0.0f;
  float SimFloatSlot<2>::nInf = 0.0f;
  float SimFloatSlot<2>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<3>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<3>::pInf = 0.0f;
  float SimFloatSlot<3>::nInf = 0.0f;
  float SimFloatSlot<3>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<4>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<4>::pInf = 0.0f;
  float SimFloatSlot<4>::nInf = 0.0f;
  float SimFloatSlot<4>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<5>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<5>::pInf = 0.0f;
  float SimFloatSlot<5>::nInf = 0.0f;
  float SimFloatSlot<5>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<6>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<6>::pInf = 0.0f;
  float SimFloatSlot<6>::nInf = 0.0f;
  float SimFloatSlot<6>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<7>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<7>::pInf = 0.0f;
  float SimFloatSlot<7>::nInf = 0.0f;
  float SimFloatSlot<7>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<8>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<8>::pInf = 0.0f;
  float SimFloatSlot<8>::nInf = 0.0f;
  float SimFloatSlot<8>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<200>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<200>::pInf = 0.0f;
  float SimFloatSlot<200>::nInf = 0.0f;
  float SimFloatSlot<200>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<201>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<201>::pInf = 0.0f;
  float SimFloatSlot<201>::nInf = 0.0f;
  float SimFloatSlot<201>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<202>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<202>::pInf = 0.0f;
  float SimFloatSlot<202>::nInf = 0.0f;
  float SimFloatSlot<202>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<203>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<203>::pInf = 0.0f;
  float SimFloatSlot<203>::nInf = 0.0f;
  float SimFloatSlot<203>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<204>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<204>::pInf = 0.0f;
  float SimFloatSlot<204>::nInf = 0.0f;
  float SimFloatSlot<204>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<205>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<205>::pInf = 0.0f;
  float SimFloatSlot<205>::nInf = 0.0f;
  float SimFloatSlot<205>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<206>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<206>::pInf = 0.0f;
  float SimFloatSlot<206>::nInf = 0.0f;
  float SimFloatSlot<206>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<207>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<207>::pInf = 0.0f;
  float SimFloatSlot<207>::nInf = 0.0f;
  float SimFloatSlot<207>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<208>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<208>::pInf = 0.0f;
  float SimFloatSlot<208>::nInf = 0.0f;
  float SimFloatSlot<208>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<209>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<209>::pInf = 0.0f;
  float SimFloatSlot<209>::nInf = 0.0f;
  float SimFloatSlot<209>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<210>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<210>::pInf = 0.0f;
  float SimFloatSlot<210>::nInf = 0.0f;
  float SimFloatSlot<210>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<211>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<211>::pInf = 0.0f;
  float SimFloatSlot<211>::nInf = 0.0f;
  float SimFloatSlot<211>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<212>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<212>::pInf = 0.0f;
  float SimFloatSlot<212>::nInf = 0.0f;
  float SimFloatSlot<212>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<213>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<213>::pInf = 0.0f;
  float SimFloatSlot<213>::nInf = 0.0f;
  float SimFloatSlot<213>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<214>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<214>::pInf = 0.0f;
  float SimFloatSlot<214>::nInf = 0.0f;
  float SimFloatSlot<214>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<215>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<215>::pInf = 0.0f;
  float SimFloatSlot<215>::nInf = 0.0f;
  float SimFloatSlot<215>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<216>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<216>::pInf = 0.0f;
  float SimFloatSlot<216>::nInf = 0.0f;
  float SimFloatSlot<216>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<217>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<217>::pInf = 0.0f;
  float SimFloatSlot<217>::nInf = 0.0f;
  float SimFloatSlot<217>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<218>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<218>::pInf = 0.0f;
  float SimFloatSlot<218>::nInf = 0.0f;
  float SimFloatSlot<218>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<219>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<219>::pInf = 0.0f;
  float SimFloatSlot<219>::nInf = 0.0f;
  float SimFloatSlot<219>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<220>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<220>::pInf = 0.0f;
  float SimFloatSlot<220>::nInf = 0.0f;
  float SimFloatSlot<220>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<221>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<221>::pInf = 0.0f;
  float SimFloatSlot<221>::nInf = 0.0f;
  float SimFloatSlot<221>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<222>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<222>::pInf = 0.0f;
  float SimFloatSlot<222>::nInf = 0.0f;
  float SimFloatSlot<222>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<223>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<223>::pInf = 0.0f;
  float SimFloatSlot<223>::nInf = 0.0f;
  float SimFloatSlot<223>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<224>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<224>::pInf = 0.0f;
  float SimFloatSlot<224>::nInf = 0.0f;
  float SimFloatSlot<224>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<225>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<225>::pInf = 0.0f;
  float SimFloatSlot<225>::nInf = 0.0f;
  float SimFloatSlot<225>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<226>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<226>::pInf = 0.0f;
  float SimFloatSlot<226>::nInf = 0.0f;
  float SimFloatSlot<226>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<227>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<227>::pInf = 0.0f;
  float SimFloatSlot<227>::nInf = 0.0f;
  float SimFloatSlot<227>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<228>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<228>::pInf = 0.0f;
  float SimFloatSlot<228>::nInf = 0.0f;
  float SimFloatSlot<228>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<229>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<229>::pInf = 0.0f;
  float SimFloatSlot<229>::nInf = 0.0f;
  float SimFloatSlot<229>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<230>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<230>::pInf = 0.0f;
  float SimFloatSlot<230>::nInf = 0.0f;
  float SimFloatSlot<230>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<231>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<231>::pInf = 0.0f;
  float SimFloatSlot<231>::nInf = 0.0f;
  float SimFloatSlot<231>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<232>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<232>::pInf = 0.0f;
  float SimFloatSlot<232>::nInf = 0.0f;
  float SimFloatSlot<232>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<233>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<233>::pInf = 0.0f;
  float SimFloatSlot<233>::nInf = 0.0f;
  float SimFloatSlot<233>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<234>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<234>::pInf = 0.0f;
  float SimFloatSlot<234>::nInf = 0.0f;
  float SimFloatSlot<234>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<235>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<235>::pInf = 0.0f;
  float SimFloatSlot<235>::nInf = 0.0f;
  float SimFloatSlot<235>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<236>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<236>::pInf = 0.0f;
  float SimFloatSlot<236>::nInf = 0.0f;
  float SimFloatSlot<236>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<237>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<237>::pInf = 0.0f;
  float SimFloatSlot<237>::nInf = 0.0f;
  float SimFloatSlot<237>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<238>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<238>::pInf = 0.0f;
  float SimFloatSlot<238>::nInf = 0.0f;
  float SimFloatSlot<238>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<239>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<239>::pInf = 0.0f;
  float SimFloatSlot<239>::nInf = 0.0f;
  float SimFloatSlot<239>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<240>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<240>::pInf = 0.0f;
  float SimFloatSlot<240>::nInf = 0.0f;
  float SimFloatSlot<240>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<241>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<241>::pInf = 0.0f;
  float SimFloatSlot<241>::nInf = 0.0f;
  float SimFloatSlot<241>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<242>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<242>::pInf = 0.0f;
  float SimFloatSlot<242>::nInf = 0.0f;
  float SimFloatSlot<242>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<243>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<243>::pInf = 0.0f;
  float SimFloatSlot<243>::nInf = 0.0f;
  float SimFloatSlot<243>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<244>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<244>::pInf = 0.0f;
  float SimFloatSlot<244>::nInf = 0.0f;
  float SimFloatSlot<244>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<245>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<245>::pInf = 0.0f;
  float SimFloatSlot<245>::nInf = 0.0f;
  float SimFloatSlot<245>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<246>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<246>::pInf = 0.0f;
  float SimFloatSlot<246>::nInf = 0.0f;
  float SimFloatSlot<246>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<247>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<247>::pInf = 0.0f;
  float SimFloatSlot<247>::nInf = 0.0f;
  float SimFloatSlot<247>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<248>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<248>::pInf = 0.0f;
  float SimFloatSlot<248>::nInf = 0.0f;
  float SimFloatSlot<248>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<249>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<249>::pInf = 0.0f;
  float SimFloatSlot<249>::nInf = 0.0f;
  float SimFloatSlot<249>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<250>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<250>::pInf = 0.0f;
  float SimFloatSlot<250>::nInf = 0.0f;
  float SimFloatSlot<250>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<251>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<251>::pInf = 0.0f;
  float SimFloatSlot<251>::nInf = 0.0f;
  float SimFloatSlot<251>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<252>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<252>::pInf = 0.0f;
  float SimFloatSlot<252>::nInf = 0.0f;
  float SimFloatSlot<252>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<253>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<253>::pInf = 0.0f;
  float SimFloatSlot<253>::nInf = 0.0f;
  float SimFloatSlot<253>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<254>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<254>::pInf = 0.0f;
  float SimFloatSlot<254>::nInf = 0.0f;
  float SimFloatSlot<254>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<255>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<255>::pInf = 0.0f;
  float SimFloatSlot<255>::nInf = 0.0f;
  float SimFloatSlot<255>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<256>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<256>::pInf = 0.0f;
  float SimFloatSlot<256>::nInf = 0.0f;
  float SimFloatSlot<256>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<257>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<257>::pInf = 0.0f;
  float SimFloatSlot<257>::nInf = 0.0f;
  float SimFloatSlot<257>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<258>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<258>::pInf = 0.0f;
  float SimFloatSlot<258>::nInf = 0.0f;
  float SimFloatSlot<258>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<259>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<259>::pInf = 0.0f;
  float SimFloatSlot<259>::nInf = 0.0f;
  float SimFloatSlot<259>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<260>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<260>::pInf = 0.0f;
  float SimFloatSlot<260>::nInf = 0.0f;
  float SimFloatSlot<260>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<261>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<261>::pInf = 0.0f;
  float SimFloatSlot<261>::nInf = 0.0f;
  float SimFloatSlot<261>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<262>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<262>::pInf = 0.0f;
  float SimFloatSlot<262>::nInf = 0.0f;
  float SimFloatSlot<262>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<263>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<263>::pInf = 0.0f;
  float SimFloatSlot<263>::nInf = 0.0f;
  float SimFloatSlot<263>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<264>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<264>::pInf = 0.0f;
  float SimFloatSlot<264>::nInf = 0.0f;
  float SimFloatSlot<264>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<265>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<265>::pInf = 0.0f;
  float SimFloatSlot<265>::nInf = 0.0f;
  float SimFloatSlot<265>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<266>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<266>::pInf = 0.0f;
  float SimFloatSlot<266>::nInf = 0.0f;
  float SimFloatSlot<266>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<267>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<267>::pInf = 0.0f;
  float SimFloatSlot<267>::nInf = 0.0f;
  float SimFloatSlot<267>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<268>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<268>::pInf = 0.0f;
  float SimFloatSlot<268>::nInf = 0.0f;
  float SimFloatSlot<268>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<269>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<269>::pInf = 0.0f;
  float SimFloatSlot<269>::nInf = 0.0f;
  float SimFloatSlot<269>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<270>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<270>::pInf = 0.0f;
  float SimFloatSlot<270>::nInf = 0.0f;
  float SimFloatSlot<270>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<271>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<271>::pInf = 0.0f;
  float SimFloatSlot<271>::nInf = 0.0f;
  float SimFloatSlot<271>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<272>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<272>::pInf = 0.0f;
  float SimFloatSlot<272>::nInf = 0.0f;
  float SimFloatSlot<272>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<273>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<273>::pInf = 0.0f;
  float SimFloatSlot<273>::nInf = 0.0f;
  float SimFloatSlot<273>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<274>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<274>::pInf = 0.0f;
  float SimFloatSlot<274>::nInf = 0.0f;
  float SimFloatSlot<274>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<275>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<275>::pInf = 0.0f;
  float SimFloatSlot<275>::nInf = 0.0f;
  float SimFloatSlot<275>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<276>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<276>::pInf = 0.0f;
  float SimFloatSlot<276>::nInf = 0.0f;
  float SimFloatSlot<276>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<277>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<277>::pInf = 0.0f;
  float SimFloatSlot<277>::nInf = 0.0f;
  float SimFloatSlot<277>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<278>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<278>::pInf = 0.0f;
  float SimFloatSlot<278>::nInf = 0.0f;
  float SimFloatSlot<278>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<279>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<279>::pInf = 0.0f;
  float SimFloatSlot<279>::nInf = 0.0f;
  float SimFloatSlot<279>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<280>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<280>::pInf = 0.0f;
  float SimFloatSlot<280>::nInf = 0.0f;
  float SimFloatSlot<280>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<281>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<281>::pInf = 0.0f;
  float SimFloatSlot<281>::nInf = 0.0f;
  float SimFloatSlot<281>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<282>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<282>::pInf = 0.0f;
  float SimFloatSlot<282>::nInf = 0.0f;
  float SimFloatSlot<282>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<283>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<283>::pInf = 0.0f;
  float SimFloatSlot<283>::nInf = 0.0f;
  float SimFloatSlot<283>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<284>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<284>::pInf = 0.0f;
  float SimFloatSlot<284>::nInf = 0.0f;
  float SimFloatSlot<284>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<285>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<285>::pInf = 0.0f;
  float SimFloatSlot<285>::nInf = 0.0f;
  float SimFloatSlot<285>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<286>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<286>::pInf = 0.0f;
  float SimFloatSlot<286>::nInf = 0.0f;
  float SimFloatSlot<286>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<287>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<287>::pInf = 0.0f;
  float SimFloatSlot<287>::nInf = 0.0f;
  float SimFloatSlot<287>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<288>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<288>::pInf = 0.0f;
  float SimFloatSlot<288>::nInf = 0.0f;
  float SimFloatSlot<288>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<289>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<289>::pInf = 0.0f;
  float SimFloatSlot<289>::nInf = 0.0f;
  float SimFloatSlot<289>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<290>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<290>::pInf = 0.0f;
  float SimFloatSlot<290>::nInf = 0.0f;
  float SimFloatSlot<290>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<291>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<291>::pInf = 0.0f;
  float SimFloatSlot<291>::nInf = 0.0f;
  float SimFloatSlot<291>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<292>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<292>::pInf = 0.0f;
  float SimFloatSlot<292>::nInf = 0.0f;
  float SimFloatSlot<292>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<293>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<293>::pInf = 0.0f;
  float SimFloatSlot<293>::nInf = 0.0f;
  float SimFloatSlot<293>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<294>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<294>::pInf = 0.0f;
  float SimFloatSlot<294>::nInf = 0.0f;
  float SimFloatSlot<294>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<295>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<295>::pInf = 0.0f;
  float SimFloatSlot<295>::nInf = 0.0f;
  float SimFloatSlot<295>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<296>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<296>::pInf = 0.0f;
  float SimFloatSlot<296>::nInf = 0.0f;
  float SimFloatSlot<296>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<297>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<297>::pInf = 0.0f;
  float SimFloatSlot<297>::nInf = 0.0f;
  float SimFloatSlot<297>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<298>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<298>::pInf = 0.0f;
  float SimFloatSlot<298>::nInf = 0.0f;
  float SimFloatSlot<298>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<299>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<299>::pInf = 0.0f;
  float SimFloatSlot<299>::nInf = 0.0f;
  float SimFloatSlot<299>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<300>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<300>::pInf = 0.0f;
  float SimFloatSlot<300>::nInf = 0.0f;
  float SimFloatSlot<300>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<301>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<301>::pInf = 0.0f;
  float SimFloatSlot<301>::nInf = 0.0f;
  float SimFloatSlot<301>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<302>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<302>::pInf = 0.0f;
  float SimFloatSlot<302>::nInf = 0.0f;
  float SimFloatSlot<302>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<303>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<303>::pInf = 0.0f;
  float SimFloatSlot<303>::nInf = 0.0f;
  float SimFloatSlot<303>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<304>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<304>::pInf = 0.0f;
  float SimFloatSlot<304>::nInf = 0.0f;
  float SimFloatSlot<304>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<305>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<305>::pInf = 0.0f;
  float SimFloatSlot<305>::nInf = 0.0f;
  float SimFloatSlot<305>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<306>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<306>::pInf = 0.0f;
  float SimFloatSlot<306>::nInf = 0.0f;
  float SimFloatSlot<306>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<307>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<307>::pInf = 0.0f;
  float SimFloatSlot<307>::nInf = 0.0f;
  float SimFloatSlot<307>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<308>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<308>::pInf = 0.0f;
  float SimFloatSlot<308>::nInf = 0.0f;
  float SimFloatSlot<308>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<309>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<309>::pInf = 0.0f;
  float SimFloatSlot<309>::nInf = 0.0f;
  float SimFloatSlot<309>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<310>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<310>::pInf = 0.0f;
  float SimFloatSlot<310>::nInf = 0.0f;
  float SimFloatSlot<310>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<311>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<311>::pInf = 0.0f;
  float SimFloatSlot<311>::nInf = 0.0f;
  float SimFloatSlot<311>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<312>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<312>::pInf = 0.0f;
  float SimFloatSlot<312>::nInf = 0.0f;
  float SimFloatSlot<312>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<313>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<313>::pInf = 0.0f;
  float SimFloatSlot<313>::nInf = 0.0f;
  float SimFloatSlot<313>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<314>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<314>::pInf = 0.0f;
  float SimFloatSlot<314>::nInf = 0.0f;
  float SimFloatSlot<314>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<315>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<315>::pInf = 0.0f;
  float SimFloatSlot<315>::nInf = 0.0f;
  float SimFloatSlot<315>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<316>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<316>::pInf = 0.0f;
  float SimFloatSlot<316>::nInf = 0.0f;
  float SimFloatSlot<316>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<317>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<317>::pInf = 0.0f;
  float SimFloatSlot<317>::nInf = 0.0f;
  float SimFloatSlot<317>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<318>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<318>::pInf = 0.0f;
  float SimFloatSlot<318>::nInf = 0.0f;
  float SimFloatSlot<318>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<319>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<319>::pInf = 0.0f;
  float SimFloatSlot<319>::nInf = 0.0f;
  float SimFloatSlot<319>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<320>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<320>::pInf = 0.0f;
  float SimFloatSlot<320>::nInf = 0.0f;
  float SimFloatSlot<320>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<321>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<321>::pInf = 0.0f;
  float SimFloatSlot<321>::nInf = 0.0f;
  float SimFloatSlot<321>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<322>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<322>::pInf = 0.0f;
  float SimFloatSlot<322>::nInf = 0.0f;
  float SimFloatSlot<322>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<323>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<323>::pInf = 0.0f;
  float SimFloatSlot<323>::nInf = 0.0f;
  float SimFloatSlot<323>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<324>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<324>::pInf = 0.0f;
  float SimFloatSlot<324>::nInf = 0.0f;
  float SimFloatSlot<324>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<325>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<325>::pInf = 0.0f;
  float SimFloatSlot<325>::nInf = 0.0f;
  float SimFloatSlot<325>::qNaN = 0.0f;

  template <>
  struct SimFloatSlot<326>
  {
    static float pInf;
    static float nInf;
    static float qNaN;
  };
  float SimFloatSlot<326>::pInf = 0.0f;
  float SimFloatSlot<326>::nInf = 0.0f;
  float SimFloatSlot<326>::qNaN = 0.0f;

} // namespace

namespace moho
{
  /**
   * Address: 0x00BE9780 (FUN_00BE9780, register_pInf_0)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 0.
   */
  void register_pInf_0()
  {
    RegisterPositiveInfinity<0>();
  }

  /**
   * Address: 0x00BE97A0 (FUN_00BE97A0, register_nInf_0)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 0 from `pInf_0`.
   */
  void register_nInf_0()
  {
    RegisterNegativeInfinity<0>();
  }

  /**
   * Address: 0x00BE97C0 (FUN_00BE97C0, register_NaN_0)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 0.
   */
  void register_NaN_0()
  {
    RegisterQuietNaN<0>();
  }

  /**
   * Address: 0x00BE99C0 (FUN_00BE99C0, register_pInf_1)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 1.
   */
  void register_pInf_1()
  {
    RegisterPositiveInfinity<1>();
  }

  /**
   * Address: 0x00BE99E0 (FUN_00BE99E0, register_nInf_1)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 1 from `pInf_1`.
   */
  void register_nInf_1()
  {
    RegisterNegativeInfinity<1>();
  }

  /**
   * Address: 0x00BE9A00 (FUN_00BE9A00, register_NaN_1)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 1.
   */
  void register_NaN_1()
  {
    RegisterQuietNaN<1>();
  }

  /**
   * Address: 0x00BE9A30 (FUN_00BE9A30, register_pInf_2)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 2.
   */
  void register_pInf_2()
  {
    RegisterPositiveInfinity<2>();
  }

  /**
   * Address: 0x00BE9A50 (FUN_00BE9A50, register_nInf_2)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 2 from `pInf_2`.
   */
  void register_nInf_2()
  {
    RegisterNegativeInfinity<2>();
  }

  /**
   * Address: 0x00BE9A70 (FUN_00BE9A70, register_NaN_2)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 2.
   */
  void register_NaN_2()
  {
    RegisterQuietNaN<2>();
  }

  /**
   * Address: 0x00BE9A90 (FUN_00BE9A90, register_pInf_3)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 3.
   */
  void register_pInf_3()
  {
    RegisterPositiveInfinity<3>();
  }

  /**
   * Address: 0x00BE9AB0 (FUN_00BE9AB0, register_nInf_3)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 3 from `pInf_3`.
   */
  void register_nInf_3()
  {
    RegisterNegativeInfinity<3>();
  }

  /**
   * Address: 0x00BE9AD0 (FUN_00BE9AD0, register_NaN_3)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 3.
   */
  void register_NaN_3()
  {
    RegisterQuietNaN<3>();
  }

  /**
   * Address: 0x00BE9D50 (FUN_00BE9D50, register_pInf_4)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 4.
   */
  void register_pInf_4()
  {
    RegisterPositiveInfinity<4>();
  }

  /**
   * Address: 0x00BE9D70 (FUN_00BE9D70, register_nInf_4)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 4 from `pInf_4`.
   */
  void register_nInf_4()
  {
    RegisterNegativeInfinity<4>();
  }

  /**
   * Address: 0x00BE9D90 (FUN_00BE9D90, register_NaN_4)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 4.
   */
  void register_NaN_4()
  {
    RegisterQuietNaN<4>();
  }

  /**
   * Address: 0x00BEA910 (FUN_00BEA910, register_pInf_5)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 5.
   */
  void register_pInf_5()
  {
    RegisterPositiveInfinity<5>();
  }

  /**
   * Address: 0x00BEA930 (FUN_00BEA930, register_nInf_5)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 5 from `pInf_5`.
   */
  void register_nInf_5()
  {
    RegisterNegativeInfinity<5>();
  }

  /**
   * Address: 0x00BEA950 (FUN_00BEA950, register_NaN_5)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 5.
   */
  void register_NaN_5()
  {
    RegisterQuietNaN<5>();
  }

  /**
   * Address: 0x00BEA970 (FUN_00BEA970, register_pInf_6)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 6.
   */
  void register_pInf_6()
  {
    RegisterPositiveInfinity<6>();
  }

  /**
   * Address: 0x00BEA990 (FUN_00BEA990, register_nInf_6)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 6 from `pInf_6`.
   */
  void register_nInf_6()
  {
    RegisterNegativeInfinity<6>();
  }

  /**
   * Address: 0x00BEA9B0 (FUN_00BEA9B0, register_NaN_6)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 6.
   */
  void register_NaN_6()
  {
    RegisterQuietNaN<6>();
  }

  /**
   * Address: 0x00BEAAD0 (FUN_00BEAAD0, register_pInf_7)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 7.
   */
  void register_pInf_7()
  {
    RegisterPositiveInfinity<7>();
  }

  /**
   * Address: 0x00BEAAF0 (FUN_00BEAAF0, register_nInf_7)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 7 from `pInf_7`.
   */
  void register_nInf_7()
  {
    RegisterNegativeInfinity<7>();
  }

  /**
   * Address: 0x00BEAB10 (FUN_00BEAB10, register_NaN_7)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 7.
   */
  void register_NaN_7()
  {
    RegisterQuietNaN<7>();
  }

  /**
   * Address: 0x00BEAB30 (FUN_00BEAB30, register_pInf_8)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 8.
   */
  void register_pInf_8()
  {
    RegisterPositiveInfinity<8>();
  }

  /**
   * Address: 0x00BEAB50 (FUN_00BEAB50, register_nInf_8)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 8 from `pInf_8`.
   */
  void register_nInf_8()
  {
    RegisterNegativeInfinity<8>();
  }

  /**
   * Address: 0x00BEAB70 (FUN_00BEAB70, register_NaN_8)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 8.
   */
  void register_NaN_8()
  {
    RegisterQuietNaN<8>();
  }

  /**
   * Address: 0x00BDA310 (FUN_00BDA310, register_pInf_200)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 200.
   */
  void register_pInf_200()
  {
    RegisterPositiveInfinity<200>();
  }

  /**
   * Address: 0x00BDA330 (FUN_00BDA330, register_nInf_200)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 200 from `pInf_200`.
   */
  void register_nInf_200()
  {
    RegisterNegativeInfinity<200>();
  }

  /**
   * Address: 0x00BDA350 (FUN_00BDA350, register_NaN_200)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 200.
   */
  void register_NaN_200()
  {
    RegisterQuietNaN<200>();
  }

  /**
   * Address: 0x00BDA8B0 (FUN_00BDA8B0, register_pInf_201)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 201.
   */
  void register_pInf_201()
  {
    RegisterPositiveInfinity<201>();
  }

  /**
   * Address: 0x00BDA8D0 (FUN_00BDA8D0, register_nInf_201)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 201 from `pInf_201`.
   */
  void register_nInf_201()
  {
    RegisterNegativeInfinity<201>();
  }

  /**
   * Address: 0x00BDA8F0 (FUN_00BDA8F0, register_NaN_201)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 201.
   */
  void register_NaN_201()
  {
    RegisterQuietNaN<201>();
  }

  /**
   * Address: 0x00BDAB00 (FUN_00BDAB00, register_pInf_202)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 202.
   */
  void register_pInf_202()
  {
    RegisterPositiveInfinity<202>();
  }

  /**
   * Address: 0x00BDAB20 (FUN_00BDAB20, register_nInf_202)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 202 from `pInf_202`.
   */
  void register_nInf_202()
  {
    RegisterNegativeInfinity<202>();
  }

  /**
   * Address: 0x00BDAB40 (FUN_00BDAB40, register_NaN_202)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 202.
   */
  void register_NaN_202()
  {
    RegisterQuietNaN<202>();
  }

  /**
   * Address: 0x00BDAD30 (FUN_00BDAD30, register_pInf_203)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 203.
   */
  void register_pInf_203()
  {
    RegisterPositiveInfinity<203>();
  }

  /**
   * Address: 0x00BDAD50 (FUN_00BDAD50, register_nInf_203)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 203 from `pInf_203`.
   */
  void register_nInf_203()
  {
    RegisterNegativeInfinity<203>();
  }

  /**
   * Address: 0x00BDAD70 (FUN_00BDAD70, register_NaN_203)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 203.
   */
  void register_NaN_203()
  {
    RegisterQuietNaN<203>();
  }

  /**
   * Address: 0x00BDB0C0 (FUN_00BDB0C0, register_pInf_204)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 204.
   */
  void register_pInf_204()
  {
    RegisterPositiveInfinity<204>();
  }

  /**
   * Address: 0x00BDB0E0 (FUN_00BDB0E0, register_nInf_204)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 204 from `pInf_204`.
   */
  void register_nInf_204()
  {
    RegisterNegativeInfinity<204>();
  }

  /**
   * Address: 0x00BDB100 (FUN_00BDB100, register_NaN_204)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 204.
   */
  void register_NaN_204()
  {
    RegisterQuietNaN<204>();
  }

  /**
   * Address: 0x00BDB650 (FUN_00BDB650, register_pInf_205)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 205.
   */
  void register_pInf_205()
  {
    RegisterPositiveInfinity<205>();
  }

  /**
   * Address: 0x00BDB670 (FUN_00BDB670, register_nInf_205)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 205 from `pInf_205`.
   */
  void register_nInf_205()
  {
    RegisterNegativeInfinity<205>();
  }

  /**
   * Address: 0x00BDB690 (FUN_00BDB690, register_NaN_205)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 205.
   */
  void register_NaN_205()
  {
    RegisterQuietNaN<205>();
  }

  /**
   * Address: 0x00BDB7F0 (FUN_00BDB7F0, register_pInf_206)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 206.
   */
  void register_pInf_206()
  {
    RegisterPositiveInfinity<206>();
  }

  /**
   * Address: 0x00BDB810 (FUN_00BDB810, register_nInf_206)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 206 from `pInf_206`.
   */
  void register_nInf_206()
  {
    RegisterNegativeInfinity<206>();
  }

  /**
   * Address: 0x00BDB830 (FUN_00BDB830, register_NaN_206)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 206.
   */
  void register_NaN_206()
  {
    RegisterQuietNaN<206>();
  }

  /**
   * Address: 0x00BDB970 (FUN_00BDB970, register_pInf_207)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 207.
   */
  void register_pInf_207()
  {
    RegisterPositiveInfinity<207>();
  }

  /**
   * Address: 0x00BDB990 (FUN_00BDB990, register_nInf_207)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 207 from `pInf_207`.
   */
  void register_nInf_207()
  {
    RegisterNegativeInfinity<207>();
  }

  /**
   * Address: 0x00BDB9B0 (FUN_00BDB9B0, register_NaN_207)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 207.
   */
  void register_NaN_207()
  {
    RegisterQuietNaN<207>();
  }

  /**
   * Address: 0x00BDBE70 (FUN_00BDBE70, register_pInf_208)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 208.
   */
  void register_pInf_208()
  {
    RegisterPositiveInfinity<208>();
  }

  /**
   * Address: 0x00BDBE90 (FUN_00BDBE90, register_nInf_208)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 208 from `pInf_208`.
   */
  void register_nInf_208()
  {
    RegisterNegativeInfinity<208>();
  }

  /**
   * Address: 0x00BDBEB0 (FUN_00BDBEB0, register_NaN_208)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 208.
   */
  void register_NaN_208()
  {
    RegisterQuietNaN<208>();
  }

  /**
   * Address: 0x00BDC430 (FUN_00BDC430, register_pInf_209)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 209.
   */
  void register_pInf_209()
  {
    RegisterPositiveInfinity<209>();
  }

  /**
   * Address: 0x00BDC450 (FUN_00BDC450, register_nInf_209)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 209 from `pInf_209`.
   */
  void register_nInf_209()
  {
    RegisterNegativeInfinity<209>();
  }

  /**
   * Address: 0x00BDC470 (FUN_00BDC470, register_NaN_209)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 209.
   */
  void register_NaN_209()
  {
    RegisterQuietNaN<209>();
  }

  /**
   * Address: 0x00BDC740 (FUN_00BDC740, register_pInf_210)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 210.
   */
  void register_pInf_210()
  {
    RegisterPositiveInfinity<210>();
  }

  /**
   * Address: 0x00BDC760 (FUN_00BDC760, register_nInf_210)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 210 from `pInf_210`.
   */
  void register_nInf_210()
  {
    RegisterNegativeInfinity<210>();
  }

  /**
   * Address: 0x00BDC780 (FUN_00BDC780, register_NaN_210)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 210.
   */
  void register_NaN_210()
  {
    RegisterQuietNaN<210>();
  }

  /**
   * Address: 0x00BDC890 (FUN_00BDC890, register_pInf_211)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 211.
   */
  void register_pInf_211()
  {
    RegisterPositiveInfinity<211>();
  }

  /**
   * Address: 0x00BDC8B0 (FUN_00BDC8B0, register_nInf_211)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 211 from `pInf_211`.
   */
  void register_nInf_211()
  {
    RegisterNegativeInfinity<211>();
  }

  /**
   * Address: 0x00BDC8D0 (FUN_00BDC8D0, register_NaN_211)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 211.
   */
  void register_NaN_211()
  {
    RegisterQuietNaN<211>();
  }

  /**
   * Address: 0x00BDC9E0 (FUN_00BDC9E0, register_pInf_212)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 212.
   */
  void register_pInf_212()
  {
    RegisterPositiveInfinity<212>();
  }

  /**
   * Address: 0x00BDCA00 (FUN_00BDCA00, register_nInf_212)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 212 from `pInf_212`.
   */
  void register_nInf_212()
  {
    RegisterNegativeInfinity<212>();
  }

  /**
   * Address: 0x00BDCA20 (FUN_00BDCA20, register_NaN_212)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 212.
   */
  void register_NaN_212()
  {
    RegisterQuietNaN<212>();
  }

  /**
   * Address: 0x00BDCA70 (FUN_00BDCA70, register_pInf_213)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 213.
   */
  void register_pInf_213()
  {
    RegisterPositiveInfinity<213>();
  }

  /**
   * Address: 0x00BDCA90 (FUN_00BDCA90, register_nInf_213)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 213 from `pInf_213`.
   */
  void register_nInf_213()
  {
    RegisterNegativeInfinity<213>();
  }

  /**
   * Address: 0x00BDCAB0 (FUN_00BDCAB0, register_NaN_213)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 213.
   */
  void register_NaN_213()
  {
    RegisterQuietNaN<213>();
  }

  /**
   * Address: 0x00BDCB60 (FUN_00BDCB60, register_pInf_214)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 214.
   */
  void register_pInf_214()
  {
    RegisterPositiveInfinity<214>();
  }

  /**
   * Address: 0x00BDCB80 (FUN_00BDCB80, register_nInf_214)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 214 from `pInf_214`.
   */
  void register_nInf_214()
  {
    RegisterNegativeInfinity<214>();
  }

  /**
   * Address: 0x00BDCBA0 (FUN_00BDCBA0, register_NaN_214)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 214.
   */
  void register_NaN_214()
  {
    RegisterQuietNaN<214>();
  }

  /**
   * Address: 0x00BDCC20 (FUN_00BDCC20, register_pInf_215)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 215.
   */
  void register_pInf_215()
  {
    RegisterPositiveInfinity<215>();
  }

  /**
   * Address: 0x00BDCC40 (FUN_00BDCC40, register_nInf_215)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 215 from `pInf_215`.
   */
  void register_nInf_215()
  {
    RegisterNegativeInfinity<215>();
  }

  /**
   * Address: 0x00BDCC60 (FUN_00BDCC60, register_NaN_215)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 215.
   */
  void register_NaN_215()
  {
    RegisterQuietNaN<215>();
  }

  /**
   * Address: 0x00BDCDE0 (FUN_00BDCDE0, register_pInf_216)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 216.
   */
  void register_pInf_216()
  {
    RegisterPositiveInfinity<216>();
  }

  /**
   * Address: 0x00BDCE00 (FUN_00BDCE00, register_nInf_216)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 216 from `pInf_216`.
   */
  void register_nInf_216()
  {
    RegisterNegativeInfinity<216>();
  }

  /**
   * Address: 0x00BDCE20 (FUN_00BDCE20, register_NaN_216)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 216.
   */
  void register_NaN_216()
  {
    RegisterQuietNaN<216>();
  }

  /**
   * Address: 0x00BDCF40 (FUN_00BDCF40, register_pInf_217)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 217.
   */
  void register_pInf_217()
  {
    RegisterPositiveInfinity<217>();
  }

  /**
   * Address: 0x00BDCF60 (FUN_00BDCF60, register_nInf_217)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 217 from `pInf_217`.
   */
  void register_nInf_217()
  {
    RegisterNegativeInfinity<217>();
  }

  /**
   * Address: 0x00BDCF80 (FUN_00BDCF80, register_NaN_217)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 217.
   */
  void register_NaN_217()
  {
    RegisterQuietNaN<217>();
  }

  /**
   * Address: 0x00BDD2A0 (FUN_00BDD2A0, register_pInf_218)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 218.
   */
  void register_pInf_218()
  {
    RegisterPositiveInfinity<218>();
  }

  /**
   * Address: 0x00BDD2C0 (FUN_00BDD2C0, register_nInf_218)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 218 from `pInf_218`.
   */
  void register_nInf_218()
  {
    RegisterNegativeInfinity<218>();
  }

  /**
   * Address: 0x00BDD2E0 (FUN_00BDD2E0, register_NaN_218)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 218.
   */
  void register_NaN_218()
  {
    RegisterQuietNaN<218>();
  }

  /**
   * Address: 0x00BDD460 (FUN_00BDD460, register_pInf_219)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 219.
   */
  void register_pInf_219()
  {
    RegisterPositiveInfinity<219>();
  }

  /**
   * Address: 0x00BDD480 (FUN_00BDD480, register_nInf_219)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 219 from `pInf_219`.
   */
  void register_nInf_219()
  {
    RegisterNegativeInfinity<219>();
  }

  /**
   * Address: 0x00BDD4A0 (FUN_00BDD4A0, register_NaN_219)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 219.
   */
  void register_NaN_219()
  {
    RegisterQuietNaN<219>();
  }

  /**
   * Address: 0x00BDD610 (FUN_00BDD610, register_pInf_220)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 220.
   */
  void register_pInf_220()
  {
    RegisterPositiveInfinity<220>();
  }

  /**
   * Address: 0x00BDD630 (FUN_00BDD630, register_nInf_220)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 220 from `pInf_220`.
   */
  void register_nInf_220()
  {
    RegisterNegativeInfinity<220>();
  }

  /**
   * Address: 0x00BDD650 (FUN_00BDD650, register_NaN_220)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 220.
   */
  void register_NaN_220()
  {
    RegisterQuietNaN<220>();
  }

  /**
   * Address: 0x00BDD7A0 (FUN_00BDD7A0, register_pInf_221)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 221.
   */
  void register_pInf_221()
  {
    RegisterPositiveInfinity<221>();
  }

  /**
   * Address: 0x00BDD7C0 (FUN_00BDD7C0, register_nInf_221)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 221 from `pInf_221`.
   */
  void register_nInf_221()
  {
    RegisterNegativeInfinity<221>();
  }

  /**
   * Address: 0x00BDD7E0 (FUN_00BDD7E0, register_NaN_221)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 221.
   */
  void register_NaN_221()
  {
    RegisterQuietNaN<221>();
  }

  /**
   * Address: 0x00BDD970 (FUN_00BDD970, register_pInf_222)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 222.
   */
  void register_pInf_222()
  {
    RegisterPositiveInfinity<222>();
  }

  /**
   * Address: 0x00BDD990 (FUN_00BDD990, register_nInf_222)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 222 from `pInf_222`.
   */
  void register_nInf_222()
  {
    RegisterNegativeInfinity<222>();
  }

  /**
   * Address: 0x00BDD9B0 (FUN_00BDD9B0, register_NaN_222)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 222.
   */
  void register_NaN_222()
  {
    RegisterQuietNaN<222>();
  }

  /**
   * Address: 0x00BDDBC0 (FUN_00BDDBC0, register_pInf_223)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 223.
   */
  void register_pInf_223()
  {
    RegisterPositiveInfinity<223>();
  }

  /**
   * Address: 0x00BDDBE0 (FUN_00BDDBE0, register_nInf_223)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 223 from `pInf_223`.
   */
  void register_nInf_223()
  {
    RegisterNegativeInfinity<223>();
  }

  /**
   * Address: 0x00BDDC00 (FUN_00BDDC00, register_NaN_223)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 223.
   */
  void register_NaN_223()
  {
    RegisterQuietNaN<223>();
  }

  /**
   * Address: 0x00BDDCD0 (FUN_00BDDCD0, register_pInf_224)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 224.
   */
  void register_pInf_224()
  {
    RegisterPositiveInfinity<224>();
  }

  /**
   * Address: 0x00BDDCF0 (FUN_00BDDCF0, register_nInf_224)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 224 from `pInf_224`.
   */
  void register_nInf_224()
  {
    RegisterNegativeInfinity<224>();
  }

  /**
   * Address: 0x00BDDD10 (FUN_00BDDD10, register_NaN_224)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 224.
   */
  void register_NaN_224()
  {
    RegisterQuietNaN<224>();
  }

  /**
   * Address: 0x00BDDF50 (FUN_00BDDF50, register_pInf_225)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 225.
   */
  void register_pInf_225()
  {
    RegisterPositiveInfinity<225>();
  }

  /**
   * Address: 0x00BDDF70 (FUN_00BDDF70, register_nInf_225)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 225 from `pInf_225`.
   */
  void register_nInf_225()
  {
    RegisterNegativeInfinity<225>();
  }

  /**
   * Address: 0x00BDDF90 (FUN_00BDDF90, register_NaN_225)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 225.
   */
  void register_NaN_225()
  {
    RegisterQuietNaN<225>();
  }

  /**
   * Address: 0x00BDE0C0 (FUN_00BDE0C0, register_pInf_226)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 226.
   */
  void register_pInf_226()
  {
    RegisterPositiveInfinity<226>();
  }

  /**
   * Address: 0x00BDE0E0 (FUN_00BDE0E0, register_nInf_226)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 226 from `pInf_226`.
   */
  void register_nInf_226()
  {
    RegisterNegativeInfinity<226>();
  }

  /**
   * Address: 0x00BDE100 (FUN_00BDE100, register_NaN_226)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 226.
   */
  void register_NaN_226()
  {
    RegisterQuietNaN<226>();
  }

  /**
   * Address: 0x00BDE1C0 (FUN_00BDE1C0, register_pInf_227)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 227.
   */
  void register_pInf_227()
  {
    RegisterPositiveInfinity<227>();
  }

  /**
   * Address: 0x00BDE1E0 (FUN_00BDE1E0, register_nInf_227)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 227 from `pInf_227`.
   */
  void register_nInf_227()
  {
    RegisterNegativeInfinity<227>();
  }

  /**
   * Address: 0x00BDE200 (FUN_00BDE200, register_NaN_227)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 227.
   */
  void register_NaN_227()
  {
    RegisterQuietNaN<227>();
  }

  /**
   * Address: 0x00BDE4C0 (FUN_00BDE4C0, register_pInf_228)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 228.
   */
  void register_pInf_228()
  {
    RegisterPositiveInfinity<228>();
  }

  /**
   * Address: 0x00BDE4E0 (FUN_00BDE4E0, register_nInf_228)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 228 from `pInf_228`.
   */
  void register_nInf_228()
  {
    RegisterNegativeInfinity<228>();
  }

  /**
   * Address: 0x00BDE500 (FUN_00BDE500, register_NaN_228)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 228.
   */
  void register_NaN_228()
  {
    RegisterQuietNaN<228>();
  }

  /**
   * Address: 0x00BDE550 (FUN_00BDE550, register_pInf_229)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 229.
   */
  void register_pInf_229()
  {
    RegisterPositiveInfinity<229>();
  }

  /**
   * Address: 0x00BDE570 (FUN_00BDE570, register_nInf_229)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 229 from `pInf_229`.
   */
  void register_nInf_229()
  {
    RegisterNegativeInfinity<229>();
  }

  /**
   * Address: 0x00BDE590 (FUN_00BDE590, register_NaN_229)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 229.
   */
  void register_NaN_229()
  {
    RegisterQuietNaN<229>();
  }

  /**
   * Address: 0x00BDE680 (FUN_00BDE680, register_pInf_230)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 230.
   */
  void register_pInf_230()
  {
    RegisterPositiveInfinity<230>();
  }

  /**
   * Address: 0x00BDE6A0 (FUN_00BDE6A0, register_nInf_230)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 230 from `pInf_230`.
   */
  void register_nInf_230()
  {
    RegisterNegativeInfinity<230>();
  }

  /**
   * Address: 0x00BDE6C0 (FUN_00BDE6C0, register_NaN_230)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 230.
   */
  void register_NaN_230()
  {
    RegisterQuietNaN<230>();
  }

  /**
   * Address: 0x00BDE780 (FUN_00BDE780, register_pInf_231)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 231.
   */
  void register_pInf_231()
  {
    RegisterPositiveInfinity<231>();
  }

  /**
   * Address: 0x00BDE7A0 (FUN_00BDE7A0, register_nInf_231)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 231 from `pInf_231`.
   */
  void register_nInf_231()
  {
    RegisterNegativeInfinity<231>();
  }

  /**
   * Address: 0x00BDE7C0 (FUN_00BDE7C0, register_NaN_231)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 231.
   */
  void register_NaN_231()
  {
    RegisterQuietNaN<231>();
  }

  /**
   * Address: 0x00BDE8A0 (FUN_00BDE8A0, register_pInf_232)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 232.
   */
  void register_pInf_232()
  {
    RegisterPositiveInfinity<232>();
  }

  /**
   * Address: 0x00BDE8C0 (FUN_00BDE8C0, register_nInf_232)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 232 from `pInf_232`.
   */
  void register_nInf_232()
  {
    RegisterNegativeInfinity<232>();
  }

  /**
   * Address: 0x00BDE8E0 (FUN_00BDE8E0, register_NaN_232)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 232.
   */
  void register_NaN_232()
  {
    RegisterQuietNaN<232>();
  }

  /**
   * Address: 0x00BDEAE0 (FUN_00BDEAE0, register_pInf_233)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 233.
   */
  void register_pInf_233()
  {
    RegisterPositiveInfinity<233>();
  }

  /**
   * Address: 0x00BDEB00 (FUN_00BDEB00, register_nInf_233)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 233 from `pInf_233`.
   */
  void register_nInf_233()
  {
    RegisterNegativeInfinity<233>();
  }

  /**
   * Address: 0x00BDEB20 (FUN_00BDEB20, register_NaN_233)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 233.
   */
  void register_NaN_233()
  {
    RegisterQuietNaN<233>();
  }

  /**
   * Address: 0x00BDEBB0 (FUN_00BDEBB0, register_pInf_234)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 234.
   */
  void register_pInf_234()
  {
    RegisterPositiveInfinity<234>();
  }

  /**
   * Address: 0x00BDEBD0 (FUN_00BDEBD0, register_nInf_234)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 234 from `pInf_234`.
   */
  void register_nInf_234()
  {
    RegisterNegativeInfinity<234>();
  }

  /**
   * Address: 0x00BDEBF0 (FUN_00BDEBF0, register_NaN_234)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 234.
   */
  void register_NaN_234()
  {
    RegisterQuietNaN<234>();
  }

  /**
   * Address: 0x00BDECD0 (FUN_00BDECD0, register_pInf_235)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 235.
   */
  void register_pInf_235()
  {
    RegisterPositiveInfinity<235>();
  }

  /**
   * Address: 0x00BDECF0 (FUN_00BDECF0, register_nInf_235)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 235 from `pInf_235`.
   */
  void register_nInf_235()
  {
    RegisterNegativeInfinity<235>();
  }

  /**
   * Address: 0x00BDED10 (FUN_00BDED10, register_NaN_235)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 235.
   */
  void register_NaN_235()
  {
    RegisterQuietNaN<235>();
  }

  /**
   * Address: 0x00BDEE40 (FUN_00BDEE40, register_pInf_236)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 236.
   */
  void register_pInf_236()
  {
    RegisterPositiveInfinity<236>();
  }

  /**
   * Address: 0x00BDEE60 (FUN_00BDEE60, register_nInf_236)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 236 from `pInf_236`.
   */
  void register_nInf_236()
  {
    RegisterNegativeInfinity<236>();
  }

  /**
   * Address: 0x00BDEE80 (FUN_00BDEE80, register_NaN_236)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 236.
   */
  void register_NaN_236()
  {
    RegisterQuietNaN<236>();
  }

  /**
   * Address: 0x00BDEF80 (FUN_00BDEF80, register_pInf_237)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 237.
   */
  void register_pInf_237()
  {
    RegisterPositiveInfinity<237>();
  }

  /**
   * Address: 0x00BDEFA0 (FUN_00BDEFA0, register_nInf_237)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 237 from `pInf_237`.
   */
  void register_nInf_237()
  {
    RegisterNegativeInfinity<237>();
  }

  /**
   * Address: 0x00BDEFC0 (FUN_00BDEFC0, register_NaN_237)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 237.
   */
  void register_NaN_237()
  {
    RegisterQuietNaN<237>();
  }

  /**
   * Address: 0x00BDF110 (FUN_00BDF110, register_pInf_238)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 238.
   */
  void register_pInf_238()
  {
    RegisterPositiveInfinity<238>();
  }

  /**
   * Address: 0x00BDF130 (FUN_00BDF130, register_nInf_238)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 238 from `pInf_238`.
   */
  void register_nInf_238()
  {
    RegisterNegativeInfinity<238>();
  }

  /**
   * Address: 0x00BDF150 (FUN_00BDF150, register_NaN_238)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 238.
   */
  void register_NaN_238()
  {
    RegisterQuietNaN<238>();
  }

  /**
   * Address: 0x00BDF1D0 (FUN_00BDF1D0, register_pInf_239)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 239.
   */
  void register_pInf_239()
  {
    RegisterPositiveInfinity<239>();
  }

  /**
   * Address: 0x00BDF1F0 (FUN_00BDF1F0, register_nInf_239)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 239 from `pInf_239`.
   */
  void register_nInf_239()
  {
    RegisterNegativeInfinity<239>();
  }

  /**
   * Address: 0x00BDF210 (FUN_00BDF210, register_NaN_239)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 239.
   */
  void register_NaN_239()
  {
    RegisterQuietNaN<239>();
  }

  /**
   * Address: 0x00BDF860 (FUN_00BDF860, register_pInf_240)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 240.
   */
  void register_pInf_240()
  {
    RegisterPositiveInfinity<240>();
  }

  /**
   * Address: 0x00BDF880 (FUN_00BDF880, register_nInf_240)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 240 from `pInf_240`.
   */
  void register_nInf_240()
  {
    RegisterNegativeInfinity<240>();
  }

  /**
   * Address: 0x00BDF8A0 (FUN_00BDF8A0, register_NaN_240)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 240.
   */
  void register_NaN_240()
  {
    RegisterQuietNaN<240>();
  }

  /**
   * Address: 0x00BDF920 (FUN_00BDF920, register_pInf_241)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 241.
   */
  void register_pInf_241()
  {
    RegisterPositiveInfinity<241>();
  }

  /**
   * Address: 0x00BDF940 (FUN_00BDF940, register_nInf_241)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 241 from `pInf_241`.
   */
  void register_nInf_241()
  {
    RegisterNegativeInfinity<241>();
  }

  /**
   * Address: 0x00BDF960 (FUN_00BDF960, register_NaN_241)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 241.
   */
  void register_NaN_241()
  {
    RegisterQuietNaN<241>();
  }

  /**
   * Address: 0x00BDFA10 (FUN_00BDFA10, register_pInf_242)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 242.
   */
  void register_pInf_242()
  {
    RegisterPositiveInfinity<242>();
  }

  /**
   * Address: 0x00BDFA30 (FUN_00BDFA30, register_nInf_242)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 242 from `pInf_242`.
   */
  void register_nInf_242()
  {
    RegisterNegativeInfinity<242>();
  }

  /**
   * Address: 0x00BDFA50 (FUN_00BDFA50, register_NaN_242)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 242.
   */
  void register_NaN_242()
  {
    RegisterQuietNaN<242>();
  }

  /**
   * Address: 0x00BDFAC0 (FUN_00BDFAC0, register_pInf_243)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 243.
   */
  void register_pInf_243()
  {
    RegisterPositiveInfinity<243>();
  }

  /**
   * Address: 0x00BDFAE0 (FUN_00BDFAE0, register_nInf_243)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 243 from `pInf_243`.
   */
  void register_nInf_243()
  {
    RegisterNegativeInfinity<243>();
  }

  /**
   * Address: 0x00BDFB00 (FUN_00BDFB00, register_NaN_243)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 243.
   */
  void register_NaN_243()
  {
    RegisterQuietNaN<243>();
  }

  /**
   * Address: 0x00BDFC00 (FUN_00BDFC00, register_pInf_244)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 244.
   */
  void register_pInf_244()
  {
    RegisterPositiveInfinity<244>();
  }

  /**
   * Address: 0x00BDFC20 (FUN_00BDFC20, register_nInf_244)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 244 from `pInf_244`.
   */
  void register_nInf_244()
  {
    RegisterNegativeInfinity<244>();
  }

  /**
   * Address: 0x00BDFC40 (FUN_00BDFC40, register_NaN_244)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 244.
   */
  void register_NaN_244()
  {
    RegisterQuietNaN<244>();
  }

  /**
   * Address: 0x00BDFCD0 (FUN_00BDFCD0, register_pInf_245)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 245.
   */
  void register_pInf_245()
  {
    RegisterPositiveInfinity<245>();
  }

  /**
   * Address: 0x00BDFCF0 (FUN_00BDFCF0, register_nInf_245)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 245 from `pInf_245`.
   */
  void register_nInf_245()
  {
    RegisterNegativeInfinity<245>();
  }

  /**
   * Address: 0x00BDFD10 (FUN_00BDFD10, register_NaN_245)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 245.
   */
  void register_NaN_245()
  {
    RegisterQuietNaN<245>();
  }

  /**
   * Address: 0x00BDFFE0 (FUN_00BDFFE0, register_pInf_246)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 246.
   */
  void register_pInf_246()
  {
    RegisterPositiveInfinity<246>();
  }

  /**
   * Address: 0x00BE0000 (FUN_00BE0000, register_nInf_246)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 246 from `pInf_246`.
   */
  void register_nInf_246()
  {
    RegisterNegativeInfinity<246>();
  }

  /**
   * Address: 0x00BE0020 (FUN_00BE0020, register_NaN_246)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 246.
   */
  void register_NaN_246()
  {
    RegisterQuietNaN<246>();
  }

  /**
   * Address: 0x00BE0050 (FUN_00BE0050, register_pInf_247)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 247.
   */
  void register_pInf_247()
  {
    RegisterPositiveInfinity<247>();
  }

  /**
   * Address: 0x00BE0070 (FUN_00BE0070, register_nInf_247)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 247 from `pInf_247`.
   */
  void register_nInf_247()
  {
    RegisterNegativeInfinity<247>();
  }

  /**
   * Address: 0x00BE0090 (FUN_00BE0090, register_NaN_247)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 247.
   */
  void register_NaN_247()
  {
    RegisterQuietNaN<247>();
  }

  /**
   * Address: 0x00BE00C0 (FUN_00BE00C0, register_pInf_248)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 248.
   */
  void register_pInf_248()
  {
    RegisterPositiveInfinity<248>();
  }

  /**
   * Address: 0x00BE00E0 (FUN_00BE00E0, register_nInf_248)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 248 from `pInf_248`.
   */
  void register_nInf_248()
  {
    RegisterNegativeInfinity<248>();
  }

  /**
   * Address: 0x00BE0100 (FUN_00BE0100, register_NaN_248)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 248.
   */
  void register_NaN_248()
  {
    RegisterQuietNaN<248>();
  }

  /**
   * Address: 0x00BE0130 (FUN_00BE0130, register_pInf_249)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 249.
   */
  void register_pInf_249()
  {
    RegisterPositiveInfinity<249>();
  }

  /**
   * Address: 0x00BE0150 (FUN_00BE0150, register_nInf_249)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 249 from `pInf_249`.
   */
  void register_nInf_249()
  {
    RegisterNegativeInfinity<249>();
  }

  /**
   * Address: 0x00BE0170 (FUN_00BE0170, register_NaN_249)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 249.
   */
  void register_NaN_249()
  {
    RegisterQuietNaN<249>();
  }

  /**
   * Address: 0x00BE01A0 (FUN_00BE01A0, register_pInf_250)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 250.
   */
  void register_pInf_250()
  {
    RegisterPositiveInfinity<250>();
  }

  /**
   * Address: 0x00BE01C0 (FUN_00BE01C0, register_nInf_250)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 250 from `pInf_250`.
   */
  void register_nInf_250()
  {
    RegisterNegativeInfinity<250>();
  }

  /**
   * Address: 0x00BE01E0 (FUN_00BE01E0, register_NaN_250)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 250.
   */
  void register_NaN_250()
  {
    RegisterQuietNaN<250>();
  }

  /**
   * Address: 0x00BE0240 (FUN_00BE0240, register_pInf_251)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 251.
   */
  void register_pInf_251()
  {
    RegisterPositiveInfinity<251>();
  }

  /**
   * Address: 0x00BE0260 (FUN_00BE0260, register_nInf_251)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 251 from `pInf_251`.
   */
  void register_nInf_251()
  {
    RegisterNegativeInfinity<251>();
  }

  /**
   * Address: 0x00BE0280 (FUN_00BE0280, register_NaN_251)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 251.
   */
  void register_NaN_251()
  {
    RegisterQuietNaN<251>();
  }

  /**
   * Address: 0x00BE02B0 (FUN_00BE02B0, register_pInf_252)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 252.
   */
  void register_pInf_252()
  {
    RegisterPositiveInfinity<252>();
  }

  /**
   * Address: 0x00BE02D0 (FUN_00BE02D0, register_nInf_252)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 252 from `pInf_252`.
   */
  void register_nInf_252()
  {
    RegisterNegativeInfinity<252>();
  }

  /**
   * Address: 0x00BE02F0 (FUN_00BE02F0, register_NaN_252)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 252.
   */
  void register_NaN_252()
  {
    RegisterQuietNaN<252>();
  }

  /**
   * Address: 0x00BE0450 (FUN_00BE0450, register_pInf_253)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 253.
   */
  void register_pInf_253()
  {
    RegisterPositiveInfinity<253>();
  }

  /**
   * Address: 0x00BE0470 (FUN_00BE0470, register_nInf_253)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 253 from `pInf_253`.
   */
  void register_nInf_253()
  {
    RegisterNegativeInfinity<253>();
  }

  /**
   * Address: 0x00BE0490 (FUN_00BE0490, register_NaN_253)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 253.
   */
  void register_NaN_253()
  {
    RegisterQuietNaN<253>();
  }

  /**
   * Address: 0x00BE04C0 (FUN_00BE04C0, register_pInf_254)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 254.
   */
  void register_pInf_254()
  {
    RegisterPositiveInfinity<254>();
  }

  /**
   * Address: 0x00BE04E0 (FUN_00BE04E0, register_nInf_254)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 254 from `pInf_254`.
   */
  void register_nInf_254()
  {
    RegisterNegativeInfinity<254>();
  }

  /**
   * Address: 0x00BE0500 (FUN_00BE0500, register_NaN_254)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 254.
   */
  void register_NaN_254()
  {
    RegisterQuietNaN<254>();
  }

  /**
   * Address: 0x00BE0950 (FUN_00BE0950, register_pInf_255)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 255.
   */
  void register_pInf_255()
  {
    RegisterPositiveInfinity<255>();
  }

  /**
   * Address: 0x00BE0970 (FUN_00BE0970, register_nInf_255)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 255 from `pInf_255`.
   */
  void register_nInf_255()
  {
    RegisterNegativeInfinity<255>();
  }

  /**
   * Address: 0x00BE0990 (FUN_00BE0990, register_NaN_255)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 255.
   */
  void register_NaN_255()
  {
    RegisterQuietNaN<255>();
  }

  /**
   * Address: 0x00BE09B0 (FUN_00BE09B0, register_pInf_256)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 256.
   */
  void register_pInf_256()
  {
    RegisterPositiveInfinity<256>();
  }

  /**
   * Address: 0x00BE09D0 (FUN_00BE09D0, register_nInf_256)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 256 from `pInf_256`.
   */
  void register_nInf_256()
  {
    RegisterNegativeInfinity<256>();
  }

  /**
   * Address: 0x00BE09F0 (FUN_00BE09F0, register_NaN_256)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 256.
   */
  void register_NaN_256()
  {
    RegisterQuietNaN<256>();
  }

  /**
   * Address: 0x00BE0A70 (FUN_00BE0A70, register_pInf_257)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 257.
   */
  void register_pInf_257()
  {
    RegisterPositiveInfinity<257>();
  }

  /**
   * Address: 0x00BE0A90 (FUN_00BE0A90, register_nInf_257)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 257 from `pInf_257`.
   */
  void register_nInf_257()
  {
    RegisterNegativeInfinity<257>();
  }

  /**
   * Address: 0x00BE0AB0 (FUN_00BE0AB0, register_NaN_257)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 257.
   */
  void register_NaN_257()
  {
    RegisterQuietNaN<257>();
  }

  /**
   * Address: 0x00BE0C90 (FUN_00BE0C90, register_pInf_258)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 258.
   */
  void register_pInf_258()
  {
    RegisterPositiveInfinity<258>();
  }

  /**
   * Address: 0x00BE0CB0 (FUN_00BE0CB0, register_nInf_258)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 258 from `pInf_258`.
   */
  void register_nInf_258()
  {
    RegisterNegativeInfinity<258>();
  }

  /**
   * Address: 0x00BE0CD0 (FUN_00BE0CD0, register_NaN_258)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 258.
   */
  void register_NaN_258()
  {
    RegisterQuietNaN<258>();
  }

  /**
   * Address: 0x00BE0DA0 (FUN_00BE0DA0, register_pInf_259)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 259.
   */
  void register_pInf_259()
  {
    RegisterPositiveInfinity<259>();
  }

  /**
   * Address: 0x00BE0DC0 (FUN_00BE0DC0, register_nInf_259)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 259 from `pInf_259`.
   */
  void register_nInf_259()
  {
    RegisterNegativeInfinity<259>();
  }

  /**
   * Address: 0x00BE0DE0 (FUN_00BE0DE0, register_NaN_259)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 259.
   */
  void register_NaN_259()
  {
    RegisterQuietNaN<259>();
  }

  /**
   * Address: 0x00BE0E50 (FUN_00BE0E50, register_pInf_260)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 260.
   */
  void register_pInf_260()
  {
    RegisterPositiveInfinity<260>();
  }

  /**
   * Address: 0x00BE0E70 (FUN_00BE0E70, register_nInf_260)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 260 from `pInf_260`.
   */
  void register_nInf_260()
  {
    RegisterNegativeInfinity<260>();
  }

  /**
   * Address: 0x00BE0E90 (FUN_00BE0E90, register_NaN_260)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 260.
   */
  void register_NaN_260()
  {
    RegisterQuietNaN<260>();
  }

  /**
   * Address: 0x00BE0FE0 (FUN_00BE0FE0, register_pInf_261)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 261.
   */
  void register_pInf_261()
  {
    RegisterPositiveInfinity<261>();
  }

  /**
   * Address: 0x00BE1000 (FUN_00BE1000, register_nInf_261)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 261 from `pInf_261`.
   */
  void register_nInf_261()
  {
    RegisterNegativeInfinity<261>();
  }

  /**
   * Address: 0x00BE1020 (FUN_00BE1020, register_NaN_261)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 261.
   */
  void register_NaN_261()
  {
    RegisterQuietNaN<261>();
  }

  /**
   * Address: 0x00BE1330 (FUN_00BE1330, register_pInf_262)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 262.
   */
  void register_pInf_262()
  {
    RegisterPositiveInfinity<262>();
  }

  /**
   * Address: 0x00BE1350 (FUN_00BE1350, register_nInf_262)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 262 from `pInf_262`.
   */
  void register_nInf_262()
  {
    RegisterNegativeInfinity<262>();
  }

  /**
   * Address: 0x00BE1370 (FUN_00BE1370, register_NaN_262)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 262.
   */
  void register_NaN_262()
  {
    RegisterQuietNaN<262>();
  }

  /**
   * Address: 0x00BE1C50 (FUN_00BE1C50, register_pInf_263)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 263.
   */
  void register_pInf_263()
  {
    RegisterPositiveInfinity<263>();
  }

  /**
   * Address: 0x00BE1C70 (FUN_00BE1C70, register_nInf_263)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 263 from `pInf_263`.
   */
  void register_nInf_263()
  {
    RegisterNegativeInfinity<263>();
  }

  /**
   * Address: 0x00BE1C90 (FUN_00BE1C90, register_NaN_263)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 263.
   */
  void register_NaN_263()
  {
    RegisterQuietNaN<263>();
  }

  /**
   * Address: 0x00BE1EF0 (FUN_00BE1EF0, register_pInf_264)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 264.
   */
  void register_pInf_264()
  {
    RegisterPositiveInfinity<264>();
  }

  /**
   * Address: 0x00BE1F10 (FUN_00BE1F10, register_nInf_264)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 264 from `pInf_264`.
   */
  void register_nInf_264()
  {
    RegisterNegativeInfinity<264>();
  }

  /**
   * Address: 0x00BE1F30 (FUN_00BE1F30, register_NaN_264)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 264.
   */
  void register_NaN_264()
  {
    RegisterQuietNaN<264>();
  }

  /**
   * Address: 0x00BE2070 (FUN_00BE2070, register_pInf_265)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 265.
   */
  void register_pInf_265()
  {
    RegisterPositiveInfinity<265>();
  }

  /**
   * Address: 0x00BE2090 (FUN_00BE2090, register_nInf_265)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 265 from `pInf_265`.
   */
  void register_nInf_265()
  {
    RegisterNegativeInfinity<265>();
  }

  /**
   * Address: 0x00BE20B0 (FUN_00BE20B0, register_NaN_265)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 265.
   */
  void register_NaN_265()
  {
    RegisterQuietNaN<265>();
  }

  /**
   * Address: 0x00BE30A0 (FUN_00BE30A0, register_pInf_266)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 266.
   */
  void register_pInf_266()
  {
    RegisterPositiveInfinity<266>();
  }

  /**
   * Address: 0x00BE30C0 (FUN_00BE30C0, register_nInf_266)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 266 from `pInf_266`.
   */
  void register_nInf_266()
  {
    RegisterNegativeInfinity<266>();
  }

  /**
   * Address: 0x00BE30E0 (FUN_00BE30E0, register_NaN_266)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 266.
   */
  void register_NaN_266()
  {
    RegisterQuietNaN<266>();
  }

  /**
   * Address: 0x00BE32A0 (FUN_00BE32A0, register_pInf_267)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 267.
   */
  void register_pInf_267()
  {
    RegisterPositiveInfinity<267>();
  }

  /**
   * Address: 0x00BE32C0 (FUN_00BE32C0, register_nInf_267)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 267 from `pInf_267`.
   */
  void register_nInf_267()
  {
    RegisterNegativeInfinity<267>();
  }

  /**
   * Address: 0x00BE32E0 (FUN_00BE32E0, register_NaN_267)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 267.
   */
  void register_NaN_267()
  {
    RegisterQuietNaN<267>();
  }

  /**
   * Address: 0x00BE3750 (FUN_00BE3750, register_pInf_268)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 268.
   */
  void register_pInf_268()
  {
    RegisterPositiveInfinity<268>();
  }

  /**
   * Address: 0x00BE3770 (FUN_00BE3770, register_nInf_268)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 268 from `pInf_268`.
   */
  void register_nInf_268()
  {
    RegisterNegativeInfinity<268>();
  }

  /**
   * Address: 0x00BE3790 (FUN_00BE3790, register_NaN_268)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 268.
   */
  void register_NaN_268()
  {
    RegisterQuietNaN<268>();
  }

  /**
   * Address: 0x00BE38A0 (FUN_00BE38A0, register_pInf_269)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 269.
   */
  void register_pInf_269()
  {
    RegisterPositiveInfinity<269>();
  }

  /**
   * Address: 0x00BE38C0 (FUN_00BE38C0, register_nInf_269)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 269 from `pInf_269`.
   */
  void register_nInf_269()
  {
    RegisterNegativeInfinity<269>();
  }

  /**
   * Address: 0x00BE38E0 (FUN_00BE38E0, register_NaN_269)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 269.
   */
  void register_NaN_269()
  {
    RegisterQuietNaN<269>();
  }

  /**
   * Address: 0x00BE3910 (FUN_00BE3910, register_pInf_270)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 270.
   */
  void register_pInf_270()
  {
    RegisterPositiveInfinity<270>();
  }

  /**
   * Address: 0x00BE3930 (FUN_00BE3930, register_nInf_270)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 270 from `pInf_270`.
   */
  void register_nInf_270()
  {
    RegisterNegativeInfinity<270>();
  }

  /**
   * Address: 0x00BE3950 (FUN_00BE3950, register_NaN_270)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 270.
   */
  void register_NaN_270()
  {
    RegisterQuietNaN<270>();
  }

  /**
   * Address: 0x00BE3980 (FUN_00BE3980, register_pInf_271)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 271.
   */
  void register_pInf_271()
  {
    RegisterPositiveInfinity<271>();
  }

  /**
   * Address: 0x00BE39A0 (FUN_00BE39A0, register_nInf_271)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 271 from `pInf_271`.
   */
  void register_nInf_271()
  {
    RegisterNegativeInfinity<271>();
  }

  /**
   * Address: 0x00BE39C0 (FUN_00BE39C0, register_NaN_271)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 271.
   */
  void register_NaN_271()
  {
    RegisterQuietNaN<271>();
  }

  /**
   * Address: 0x00BE39E0 (FUN_00BE39E0, register_pInf_272)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 272.
   */
  void register_pInf_272()
  {
    RegisterPositiveInfinity<272>();
  }

  /**
   * Address: 0x00BE3A00 (FUN_00BE3A00, register_nInf_272)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 272 from `pInf_272`.
   */
  void register_nInf_272()
  {
    RegisterNegativeInfinity<272>();
  }

  /**
   * Address: 0x00BE3A20 (FUN_00BE3A20, register_NaN_272)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 272.
   */
  void register_NaN_272()
  {
    RegisterQuietNaN<272>();
  }

  /**
   * Address: 0x00BE3A70 (FUN_00BE3A70, register_pInf_273)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 273.
   */
  void register_pInf_273()
  {
    RegisterPositiveInfinity<273>();
  }

  /**
   * Address: 0x00BE3A90 (FUN_00BE3A90, register_nInf_273)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 273 from `pInf_273`.
   */
  void register_nInf_273()
  {
    RegisterNegativeInfinity<273>();
  }

  /**
   * Address: 0x00BE3AB0 (FUN_00BE3AB0, register_NaN_273)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 273.
   */
  void register_NaN_273()
  {
    RegisterQuietNaN<273>();
  }

  /**
   * Address: 0x00BE3AE0 (FUN_00BE3AE0, register_pInf_274)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 274.
   */
  void register_pInf_274()
  {
    RegisterPositiveInfinity<274>();
  }

  /**
   * Address: 0x00BE3B00 (FUN_00BE3B00, register_nInf_274)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 274 from `pInf_274`.
   */
  void register_nInf_274()
  {
    RegisterNegativeInfinity<274>();
  }

  /**
   * Address: 0x00BE3B20 (FUN_00BE3B20, register_NaN_274)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 274.
   */
  void register_NaN_274()
  {
    RegisterQuietNaN<274>();
  }

  /**
   * Address: 0x00BE3B50 (FUN_00BE3B50, register_pInf_275)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 275.
   */
  void register_pInf_275()
  {
    RegisterPositiveInfinity<275>();
  }

  /**
   * Address: 0x00BE3B70 (FUN_00BE3B70, register_nInf_275)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 275 from `pInf_275`.
   */
  void register_nInf_275()
  {
    RegisterNegativeInfinity<275>();
  }

  /**
   * Address: 0x00BE3B90 (FUN_00BE3B90, register_NaN_275)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 275.
   */
  void register_NaN_275()
  {
    RegisterQuietNaN<275>();
  }

  /**
   * Address: 0x00BE3E80 (FUN_00BE3E80, register_pInf_276)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 276.
   */
  void register_pInf_276()
  {
    RegisterPositiveInfinity<276>();
  }

  /**
   * Address: 0x00BE3EA0 (FUN_00BE3EA0, register_nInf_276)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 276 from `pInf_276`.
   */
  void register_nInf_276()
  {
    RegisterNegativeInfinity<276>();
  }

  /**
   * Address: 0x00BE3EC0 (FUN_00BE3EC0, register_NaN_276)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 276.
   */
  void register_NaN_276()
  {
    RegisterQuietNaN<276>();
  }

  /**
   * Address: 0x00BE45F0 (FUN_00BE45F0, register_pInf_277)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 277.
   */
  void register_pInf_277()
  {
    RegisterPositiveInfinity<277>();
  }

  /**
   * Address: 0x00BE4610 (FUN_00BE4610, register_nInf_277)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 277 from `pInf_277`.
   */
  void register_nInf_277()
  {
    RegisterNegativeInfinity<277>();
  }

  /**
   * Address: 0x00BE4630 (FUN_00BE4630, register_NaN_277)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 277.
   */
  void register_NaN_277()
  {
    RegisterQuietNaN<277>();
  }

  /**
   * Address: 0x00BE46D0 (FUN_00BE46D0, register_pInf_278)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 278.
   */
  void register_pInf_278()
  {
    RegisterPositiveInfinity<278>();
  }

  /**
   * Address: 0x00BE46F0 (FUN_00BE46F0, register_nInf_278)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 278 from `pInf_278`.
   */
  void register_nInf_278()
  {
    RegisterNegativeInfinity<278>();
  }

  /**
   * Address: 0x00BE4710 (FUN_00BE4710, register_NaN_278)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 278.
   */
  void register_NaN_278()
  {
    RegisterQuietNaN<278>();
  }

  /**
   * Address: 0x00BE4730 (FUN_00BE4730, register_pInf_279)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 279.
   */
  void register_pInf_279()
  {
    RegisterPositiveInfinity<279>();
  }

  /**
   * Address: 0x00BE4750 (FUN_00BE4750, register_nInf_279)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 279 from `pInf_279`.
   */
  void register_nInf_279()
  {
    RegisterNegativeInfinity<279>();
  }

  /**
   * Address: 0x00BE4770 (FUN_00BE4770, register_NaN_279)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 279.
   */
  void register_NaN_279()
  {
    RegisterQuietNaN<279>();
  }

  /**
   * Address: 0x00BE4990 (FUN_00BE4990, register_pInf_280)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 280.
   */
  void register_pInf_280()
  {
    RegisterPositiveInfinity<280>();
  }

  /**
   * Address: 0x00BE49B0 (FUN_00BE49B0, register_nInf_280)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 280 from `pInf_280`.
   */
  void register_nInf_280()
  {
    RegisterNegativeInfinity<280>();
  }

  /**
   * Address: 0x00BE49D0 (FUN_00BE49D0, register_NaN_280)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 280.
   */
  void register_NaN_280()
  {
    RegisterQuietNaN<280>();
  }

  /**
   * Address: 0x00BE4DA0 (FUN_00BE4DA0, register_pInf_281)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 281.
   */
  void register_pInf_281()
  {
    RegisterPositiveInfinity<281>();
  }

  /**
   * Address: 0x00BE4DC0 (FUN_00BE4DC0, register_nInf_281)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 281 from `pInf_281`.
   */
  void register_nInf_281()
  {
    RegisterNegativeInfinity<281>();
  }

  /**
   * Address: 0x00BE4DE0 (FUN_00BE4DE0, register_NaN_281)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 281.
   */
  void register_NaN_281()
  {
    RegisterQuietNaN<281>();
  }

  /**
   * Address: 0x00BE4E10 (FUN_00BE4E10, register_pInf_282)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 282.
   */
  void register_pInf_282()
  {
    RegisterPositiveInfinity<282>();
  }

  /**
   * Address: 0x00BE4E30 (FUN_00BE4E30, register_nInf_282)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 282 from `pInf_282`.
   */
  void register_nInf_282()
  {
    RegisterNegativeInfinity<282>();
  }

  /**
   * Address: 0x00BE4E50 (FUN_00BE4E50, register_NaN_282)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 282.
   */
  void register_NaN_282()
  {
    RegisterQuietNaN<282>();
  }

  /**
   * Address: 0x00BE4EE0 (FUN_00BE4EE0, register_pInf_283)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 283.
   */
  void register_pInf_283()
  {
    RegisterPositiveInfinity<283>();
  }

  /**
   * Address: 0x00BE4F00 (FUN_00BE4F00, register_nInf_283)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 283 from `pInf_283`.
   */
  void register_nInf_283()
  {
    RegisterNegativeInfinity<283>();
  }

  /**
   * Address: 0x00BE4F20 (FUN_00BE4F20, register_NaN_283)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 283.
   */
  void register_NaN_283()
  {
    RegisterQuietNaN<283>();
  }

  /**
   * Address: 0x00BE5010 (FUN_00BE5010, register_pInf_284)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 284.
   */
  void register_pInf_284()
  {
    RegisterPositiveInfinity<284>();
  }

  /**
   * Address: 0x00BE5030 (FUN_00BE5030, register_nInf_284)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 284 from `pInf_284`.
   */
  void register_nInf_284()
  {
    RegisterNegativeInfinity<284>();
  }

  /**
   * Address: 0x00BE5050 (FUN_00BE5050, register_NaN_284)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 284.
   */
  void register_NaN_284()
  {
    RegisterQuietNaN<284>();
  }

  /**
   * Address: 0x00BE5070 (FUN_00BE5070, register_pInf_285)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 285.
   */
  void register_pInf_285()
  {
    RegisterPositiveInfinity<285>();
  }

  /**
   * Address: 0x00BE5090 (FUN_00BE5090, register_nInf_285)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 285 from `pInf_285`.
   */
  void register_nInf_285()
  {
    RegisterNegativeInfinity<285>();
  }

  /**
   * Address: 0x00BE50B0 (FUN_00BE50B0, register_NaN_285)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 285.
   */
  void register_NaN_285()
  {
    RegisterQuietNaN<285>();
  }

  /**
   * Address: 0x00BE5120 (FUN_00BE5120, register_pInf_286)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 286.
   */
  void register_pInf_286()
  {
    RegisterPositiveInfinity<286>();
  }

  /**
   * Address: 0x00BE5140 (FUN_00BE5140, register_nInf_286)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 286 from `pInf_286`.
   */
  void register_nInf_286()
  {
    RegisterNegativeInfinity<286>();
  }

  /**
   * Address: 0x00BE5160 (FUN_00BE5160, register_NaN_286)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 286.
   */
  void register_NaN_286()
  {
    RegisterQuietNaN<286>();
  }

  /**
   * Address: 0x00BE51D0 (FUN_00BE51D0, register_pInf_287)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 287.
   */
  void register_pInf_287()
  {
    RegisterPositiveInfinity<287>();
  }

  /**
   * Address: 0x00BE51F0 (FUN_00BE51F0, register_nInf_287)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 287 from `pInf_287`.
   */
  void register_nInf_287()
  {
    RegisterNegativeInfinity<287>();
  }

  /**
   * Address: 0x00BE5210 (FUN_00BE5210, register_NaN_287)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 287.
   */
  void register_NaN_287()
  {
    RegisterQuietNaN<287>();
  }

  /**
   * Address: 0x00BE5290 (FUN_00BE5290, register_pInf_288)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 288.
   */
  void register_pInf_288()
  {
    RegisterPositiveInfinity<288>();
  }

  /**
   * Address: 0x00BE52B0 (FUN_00BE52B0, register_nInf_288)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 288 from `pInf_288`.
   */
  void register_nInf_288()
  {
    RegisterNegativeInfinity<288>();
  }

  /**
   * Address: 0x00BE52D0 (FUN_00BE52D0, register_NaN_288)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 288.
   */
  void register_NaN_288()
  {
    RegisterQuietNaN<288>();
  }

  /**
   * Address: 0x00BE5300 (FUN_00BE5300, register_pInf_289)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 289.
   */
  void register_pInf_289()
  {
    RegisterPositiveInfinity<289>();
  }

  /**
   * Address: 0x00BE5320 (FUN_00BE5320, register_nInf_289)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 289 from `pInf_289`.
   */
  void register_nInf_289()
  {
    RegisterNegativeInfinity<289>();
  }

  /**
   * Address: 0x00BE5340 (FUN_00BE5340, register_NaN_289)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 289.
   */
  void register_NaN_289()
  {
    RegisterQuietNaN<289>();
  }

  /**
   * Address: 0x00BE53C0 (FUN_00BE53C0, register_pInf_290)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 290.
   */
  void register_pInf_290()
  {
    RegisterPositiveInfinity<290>();
  }

  /**
   * Address: 0x00BE53E0 (FUN_00BE53E0, register_nInf_290)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 290 from `pInf_290`.
   */
  void register_nInf_290()
  {
    RegisterNegativeInfinity<290>();
  }

  /**
   * Address: 0x00BE5400 (FUN_00BE5400, register_NaN_290)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 290.
   */
  void register_NaN_290()
  {
    RegisterQuietNaN<290>();
  }

  /**
   * Address: 0x00BE5B90 (FUN_00BE5B90, register_pInf_291)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 291.
   */
  void register_pInf_291()
  {
    RegisterPositiveInfinity<291>();
  }

  /**
   * Address: 0x00BE5BB0 (FUN_00BE5BB0, register_nInf_291)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 291 from `pInf_291`.
   */
  void register_nInf_291()
  {
    RegisterNegativeInfinity<291>();
  }

  /**
   * Address: 0x00BE5BD0 (FUN_00BE5BD0, register_NaN_291)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 291.
   */
  void register_NaN_291()
  {
    RegisterQuietNaN<291>();
  }

  /**
   * Address: 0x00BE5D40 (FUN_00BE5D40, register_pInf_292)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 292.
   */
  void register_pInf_292()
  {
    RegisterPositiveInfinity<292>();
  }

  /**
   * Address: 0x00BE5D60 (FUN_00BE5D60, register_nInf_292)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 292 from `pInf_292`.
   */
  void register_nInf_292()
  {
    RegisterNegativeInfinity<292>();
  }

  /**
   * Address: 0x00BE5D80 (FUN_00BE5D80, register_NaN_292)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 292.
   */
  void register_NaN_292()
  {
    RegisterQuietNaN<292>();
  }

  /**
   * Address: 0x00BE5F70 (FUN_00BE5F70, register_pInf_293)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 293.
   */
  void register_pInf_293()
  {
    RegisterPositiveInfinity<293>();
  }

  /**
   * Address: 0x00BE5F90 (FUN_00BE5F90, register_nInf_293)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 293 from `pInf_293`.
   */
  void register_nInf_293()
  {
    RegisterNegativeInfinity<293>();
  }

  /**
   * Address: 0x00BE5FB0 (FUN_00BE5FB0, register_NaN_293)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 293.
   */
  void register_NaN_293()
  {
    RegisterQuietNaN<293>();
  }

  /**
   * Address: 0x00BE6080 (FUN_00BE6080, register_pInf_294)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 294.
   */
  void register_pInf_294()
  {
    RegisterPositiveInfinity<294>();
  }

  /**
   * Address: 0x00BE60A0 (FUN_00BE60A0, register_nInf_294)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 294 from `pInf_294`.
   */
  void register_nInf_294()
  {
    RegisterNegativeInfinity<294>();
  }

  /**
   * Address: 0x00BE60C0 (FUN_00BE60C0, register_NaN_294)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 294.
   */
  void register_NaN_294()
  {
    RegisterQuietNaN<294>();
  }

  /**
   * Address: 0x00BE6270 (FUN_00BE6270, register_pInf_295)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 295.
   */
  void register_pInf_295()
  {
    RegisterPositiveInfinity<295>();
  }

  /**
   * Address: 0x00BE6290 (FUN_00BE6290, register_nInf_295)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 295 from `pInf_295`.
   */
  void register_nInf_295()
  {
    RegisterNegativeInfinity<295>();
  }

  /**
   * Address: 0x00BE62B0 (FUN_00BE62B0, register_NaN_295)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 295.
   */
  void register_NaN_295()
  {
    RegisterQuietNaN<295>();
  }

  /**
   * Address: 0x00BE6370 (FUN_00BE6370, register_pInf_296)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 296.
   */
  void register_pInf_296()
  {
    RegisterPositiveInfinity<296>();
  }

  /**
   * Address: 0x00BE6390 (FUN_00BE6390, register_nInf_296)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 296 from `pInf_296`.
   */
  void register_nInf_296()
  {
    RegisterNegativeInfinity<296>();
  }

  /**
   * Address: 0x00BE63B0 (FUN_00BE63B0, register_NaN_296)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 296.
   */
  void register_NaN_296()
  {
    RegisterQuietNaN<296>();
  }

  /**
   * Address: 0x00BE6460 (FUN_00BE6460, register_pInf_297)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 297.
   */
  void register_pInf_297()
  {
    RegisterPositiveInfinity<297>();
  }

  /**
   * Address: 0x00BE6480 (FUN_00BE6480, register_nInf_297)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 297 from `pInf_297`.
   */
  void register_nInf_297()
  {
    RegisterNegativeInfinity<297>();
  }

  /**
   * Address: 0x00BE64A0 (FUN_00BE64A0, register_NaN_297)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 297.
   */
  void register_NaN_297()
  {
    RegisterQuietNaN<297>();
  }

  /**
   * Address: 0x00BE6630 (FUN_00BE6630, register_pInf_298)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 298.
   */
  void register_pInf_298()
  {
    RegisterPositiveInfinity<298>();
  }

  /**
   * Address: 0x00BE6650 (FUN_00BE6650, register_nInf_298)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 298 from `pInf_298`.
   */
  void register_nInf_298()
  {
    RegisterNegativeInfinity<298>();
  }

  /**
   * Address: 0x00BE6670 (FUN_00BE6670, register_NaN_298)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 298.
   */
  void register_NaN_298()
  {
    RegisterQuietNaN<298>();
  }

  /**
   * Address: 0x00BE6BD0 (FUN_00BE6BD0, register_pInf_299)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 299.
   */
  void register_pInf_299()
  {
    RegisterPositiveInfinity<299>();
  }

  /**
   * Address: 0x00BE6BF0 (FUN_00BE6BF0, register_nInf_299)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 299 from `pInf_299`.
   */
  void register_nInf_299()
  {
    RegisterNegativeInfinity<299>();
  }

  /**
   * Address: 0x00BE6C10 (FUN_00BE6C10, register_NaN_299)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 299.
   */
  void register_NaN_299()
  {
    RegisterQuietNaN<299>();
  }

  /**
   * Address: 0x00BE6CB0 (FUN_00BE6CB0, register_pInf_300)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 300.
   */
  void register_pInf_300()
  {
    RegisterPositiveInfinity<300>();
  }

  /**
   * Address: 0x00BE6CD0 (FUN_00BE6CD0, register_nInf_300)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 300 from `pInf_300`.
   */
  void register_nInf_300()
  {
    RegisterNegativeInfinity<300>();
  }

  /**
   * Address: 0x00BE6CF0 (FUN_00BE6CF0, register_NaN_300)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 300.
   */
  void register_NaN_300()
  {
    RegisterQuietNaN<300>();
  }

  /**
   * Address: 0x00BE6D40 (FUN_00BE6D40, register_pInf_301)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 301.
   */
  void register_pInf_301()
  {
    RegisterPositiveInfinity<301>();
  }

  /**
   * Address: 0x00BE6D60 (FUN_00BE6D60, register_nInf_301)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 301 from `pInf_301`.
   */
  void register_nInf_301()
  {
    RegisterNegativeInfinity<301>();
  }

  /**
   * Address: 0x00BE6D80 (FUN_00BE6D80, register_NaN_301)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 301.
   */
  void register_NaN_301()
  {
    RegisterQuietNaN<301>();
  }

  /**
   * Address: 0x00BE6DB0 (FUN_00BE6DB0, register_pInf_302)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 302.
   */
  void register_pInf_302()
  {
    RegisterPositiveInfinity<302>();
  }

  /**
   * Address: 0x00BE6DD0 (FUN_00BE6DD0, register_nInf_302)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 302 from `pInf_302`.
   */
  void register_nInf_302()
  {
    RegisterNegativeInfinity<302>();
  }

  /**
   * Address: 0x00BE6DF0 (FUN_00BE6DF0, register_NaN_302)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 302.
   */
  void register_NaN_302()
  {
    RegisterQuietNaN<302>();
  }

  /**
   * Address: 0x00BE6E30 (FUN_00BE6E30, register_pInf_303)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 303.
   */
  void register_pInf_303()
  {
    RegisterPositiveInfinity<303>();
  }

  /**
   * Address: 0x00BE6E50 (FUN_00BE6E50, register_nInf_303)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 303 from `pInf_303`.
   */
  void register_nInf_303()
  {
    RegisterNegativeInfinity<303>();
  }

  /**
   * Address: 0x00BE6E70 (FUN_00BE6E70, register_NaN_303)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 303.
   */
  void register_NaN_303()
  {
    RegisterQuietNaN<303>();
  }

  /**
   * Address: 0x00BE6F60 (FUN_00BE6F60, register_pInf_304)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 304.
   */
  void register_pInf_304()
  {
    RegisterPositiveInfinity<304>();
  }

  /**
   * Address: 0x00BE6F80 (FUN_00BE6F80, register_nInf_304)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 304 from `pInf_304`.
   */
  void register_nInf_304()
  {
    RegisterNegativeInfinity<304>();
  }

  /**
   * Address: 0x00BE6FA0 (FUN_00BE6FA0, register_NaN_304)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 304.
   */
  void register_NaN_304()
  {
    RegisterQuietNaN<304>();
  }

  /**
   * Address: 0x00BE70C0 (FUN_00BE70C0, register_pInf_305)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 305.
   */
  void register_pInf_305()
  {
    RegisterPositiveInfinity<305>();
  }

  /**
   * Address: 0x00BE70E0 (FUN_00BE70E0, register_nInf_305)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 305 from `pInf_305`.
   */
  void register_nInf_305()
  {
    RegisterNegativeInfinity<305>();
  }

  /**
   * Address: 0x00BE7100 (FUN_00BE7100, register_NaN_305)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 305.
   */
  void register_NaN_305()
  {
    RegisterQuietNaN<305>();
  }

  /**
   * Address: 0x00BE7150 (FUN_00BE7150, register_pInf_306)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 306.
   */
  void register_pInf_306()
  {
    RegisterPositiveInfinity<306>();
  }

  /**
   * Address: 0x00BE7170 (FUN_00BE7170, register_nInf_306)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 306 from `pInf_306`.
   */
  void register_nInf_306()
  {
    RegisterNegativeInfinity<306>();
  }

  /**
   * Address: 0x00BE7190 (FUN_00BE7190, register_NaN_306)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 306.
   */
  void register_NaN_306()
  {
    RegisterQuietNaN<306>();
  }

  /**
   * Address: 0x00BE7200 (FUN_00BE7200, register_pInf_307)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 307.
   */
  void register_pInf_307()
  {
    RegisterPositiveInfinity<307>();
  }

  /**
   * Address: 0x00BE7220 (FUN_00BE7220, register_nInf_307)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 307 from `pInf_307`.
   */
  void register_nInf_307()
  {
    RegisterNegativeInfinity<307>();
  }

  /**
   * Address: 0x00BE7240 (FUN_00BE7240, register_NaN_307)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 307.
   */
  void register_NaN_307()
  {
    RegisterQuietNaN<307>();
  }

  /**
   * Address: 0x00BE75A0 (FUN_00BE75A0, register_pInf_308)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 308.
   */
  void register_pInf_308()
  {
    RegisterPositiveInfinity<308>();
  }

  /**
   * Address: 0x00BE75C0 (FUN_00BE75C0, register_nInf_308)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 308 from `pInf_308`.
   */
  void register_nInf_308()
  {
    RegisterNegativeInfinity<308>();
  }

  /**
   * Address: 0x00BE75E0 (FUN_00BE75E0, register_NaN_308)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 308.
   */
  void register_NaN_308()
  {
    RegisterQuietNaN<308>();
  }

  /**
   * Address: 0x00BE7610 (FUN_00BE7610, register_pInf_309)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 309.
   */
  void register_pInf_309()
  {
    RegisterPositiveInfinity<309>();
  }

  /**
   * Address: 0x00BE7630 (FUN_00BE7630, register_nInf_309)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 309 from `pInf_309`.
   */
  void register_nInf_309()
  {
    RegisterNegativeInfinity<309>();
  }

  /**
   * Address: 0x00BE7650 (FUN_00BE7650, register_NaN_309)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 309.
   */
  void register_NaN_309()
  {
    RegisterQuietNaN<309>();
  }

  /**
   * Address: 0x00BE7690 (FUN_00BE7690, register_pInf_310)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 310.
   */
  void register_pInf_310()
  {
    RegisterPositiveInfinity<310>();
  }

  /**
   * Address: 0x00BE76B0 (FUN_00BE76B0, register_nInf_310)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 310 from `pInf_310`.
   */
  void register_nInf_310()
  {
    RegisterNegativeInfinity<310>();
  }

  /**
   * Address: 0x00BE76D0 (FUN_00BE76D0, register_NaN_310)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 310.
   */
  void register_NaN_310()
  {
    RegisterQuietNaN<310>();
  }

  /**
   * Address: 0x00BE7990 (FUN_00BE7990, register_pInf_311)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 311.
   */
  void register_pInf_311()
  {
    RegisterPositiveInfinity<311>();
  }

  /**
   * Address: 0x00BE79B0 (FUN_00BE79B0, register_nInf_311)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 311 from `pInf_311`.
   */
  void register_nInf_311()
  {
    RegisterNegativeInfinity<311>();
  }

  /**
   * Address: 0x00BE79D0 (FUN_00BE79D0, register_NaN_311)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 311.
   */
  void register_NaN_311()
  {
    RegisterQuietNaN<311>();
  }

  /**
   * Address: 0x00BE7D20 (FUN_00BE7D20, register_pInf_312)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 312.
   */
  void register_pInf_312()
  {
    RegisterPositiveInfinity<312>();
  }

  /**
   * Address: 0x00BE7D40 (FUN_00BE7D40, register_nInf_312)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 312 from `pInf_312`.
   */
  void register_nInf_312()
  {
    RegisterNegativeInfinity<312>();
  }

  /**
   * Address: 0x00BE7D60 (FUN_00BE7D60, register_NaN_312)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 312.
   */
  void register_NaN_312()
  {
    RegisterQuietNaN<312>();
  }

  /**
   * Address: 0x00BE7DD0 (FUN_00BE7DD0, register_pInf_313)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 313.
   */
  void register_pInf_313()
  {
    RegisterPositiveInfinity<313>();
  }

  /**
   * Address: 0x00BE7DF0 (FUN_00BE7DF0, register_nInf_313)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 313 from `pInf_313`.
   */
  void register_nInf_313()
  {
    RegisterNegativeInfinity<313>();
  }

  /**
   * Address: 0x00BE7E10 (FUN_00BE7E10, register_NaN_313)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 313.
   */
  void register_NaN_313()
  {
    RegisterQuietNaN<313>();
  }

  /**
   * Address: 0x00BE8040 (FUN_00BE8040, register_pInf_314)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 314.
   */
  void register_pInf_314()
  {
    RegisterPositiveInfinity<314>();
  }

  /**
   * Address: 0x00BE8060 (FUN_00BE8060, register_nInf_314)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 314 from `pInf_314`.
   */
  void register_nInf_314()
  {
    RegisterNegativeInfinity<314>();
  }

  /**
   * Address: 0x00BE8080 (FUN_00BE8080, register_NaN_314)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 314.
   */
  void register_NaN_314()
  {
    RegisterQuietNaN<314>();
  }

  /**
   * Address: 0x00BE80C0 (FUN_00BE80C0, register_pInf_315)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 315.
   */
  void register_pInf_315()
  {
    RegisterPositiveInfinity<315>();
  }

  /**
   * Address: 0x00BE80E0 (FUN_00BE80E0, register_nInf_315)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 315 from `pInf_315`.
   */
  void register_nInf_315()
  {
    RegisterNegativeInfinity<315>();
  }

  /**
   * Address: 0x00BE8100 (FUN_00BE8100, register_NaN_315)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 315.
   */
  void register_NaN_315()
  {
    RegisterQuietNaN<315>();
  }

  /**
   * Address: 0x00BE8160 (FUN_00BE8160, register_pInf_316)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 316.
   */
  void register_pInf_316()
  {
    RegisterPositiveInfinity<316>();
  }

  /**
   * Address: 0x00BE8180 (FUN_00BE8180, register_nInf_316)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 316 from `pInf_316`.
   */
  void register_nInf_316()
  {
    RegisterNegativeInfinity<316>();
  }

  /**
   * Address: 0x00BE81A0 (FUN_00BE81A0, register_NaN_316)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 316.
   */
  void register_NaN_316()
  {
    RegisterQuietNaN<316>();
  }

  /**
   * Address: 0x00BE81D0 (FUN_00BE81D0, register_pInf_317)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 317.
   */
  void register_pInf_317()
  {
    RegisterPositiveInfinity<317>();
  }

  /**
   * Address: 0x00BE81F0 (FUN_00BE81F0, register_nInf_317)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 317 from `pInf_317`.
   */
  void register_nInf_317()
  {
    RegisterNegativeInfinity<317>();
  }

  /**
   * Address: 0x00BE8210 (FUN_00BE8210, register_NaN_317)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 317.
   */
  void register_NaN_317()
  {
    RegisterQuietNaN<317>();
  }

  /**
   * Address: 0x00BE8240 (FUN_00BE8240, register_pInf_318)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 318.
   */
  void register_pInf_318()
  {
    RegisterPositiveInfinity<318>();
  }

  /**
   * Address: 0x00BE8260 (FUN_00BE8260, register_nInf_318)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 318 from `pInf_318`.
   */
  void register_nInf_318()
  {
    RegisterNegativeInfinity<318>();
  }

  /**
   * Address: 0x00BE8280 (FUN_00BE8280, register_NaN_318)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 318.
   */
  void register_NaN_318()
  {
    RegisterQuietNaN<318>();
  }

  /**
   * Address: 0x00BE82C0 (FUN_00BE82C0, register_pInf_319)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 319.
   */
  void register_pInf_319()
  {
    RegisterPositiveInfinity<319>();
  }

  /**
   * Address: 0x00BE82E0 (FUN_00BE82E0, register_nInf_319)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 319 from `pInf_319`.
   */
  void register_nInf_319()
  {
    RegisterNegativeInfinity<319>();
  }

  /**
   * Address: 0x00BE8300 (FUN_00BE8300, register_NaN_319)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 319.
   */
  void register_NaN_319()
  {
    RegisterQuietNaN<319>();
  }

  /**
   * Address: 0x00BE8320 (FUN_00BE8320, register_pInf_320)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 320.
   */
  void register_pInf_320()
  {
    RegisterPositiveInfinity<320>();
  }

  /**
   * Address: 0x00BE8340 (FUN_00BE8340, register_nInf_320)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 320 from `pInf_320`.
   */
  void register_nInf_320()
  {
    RegisterNegativeInfinity<320>();
  }

  /**
   * Address: 0x00BE8360 (FUN_00BE8360, register_NaN_320)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 320.
   */
  void register_NaN_320()
  {
    RegisterQuietNaN<320>();
  }

  /**
   * Address: 0x00BE8600 (FUN_00BE8600, register_pInf_321)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 321.
   */
  void register_pInf_321()
  {
    RegisterPositiveInfinity<321>();
  }

  /**
   * Address: 0x00BE8620 (FUN_00BE8620, register_nInf_321)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 321 from `pInf_321`.
   */
  void register_nInf_321()
  {
    RegisterNegativeInfinity<321>();
  }

  /**
   * Address: 0x00BE8640 (FUN_00BE8640, register_NaN_321)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 321.
   */
  void register_NaN_321()
  {
    RegisterQuietNaN<321>();
  }

  /**
   * Address: 0x00BE8670 (FUN_00BE8670, register_pInf_322)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 322.
   */
  void register_pInf_322()
  {
    RegisterPositiveInfinity<322>();
  }

  /**
   * Address: 0x00BE8690 (FUN_00BE8690, register_nInf_322)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 322 from `pInf_322`.
   */
  void register_nInf_322()
  {
    RegisterNegativeInfinity<322>();
  }

  /**
   * Address: 0x00BE86B0 (FUN_00BE86B0, register_NaN_322)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 322.
   */
  void register_NaN_322()
  {
    RegisterQuietNaN<322>();
  }

  /**
   * Address: 0x00BE89C0 (FUN_00BE89C0, register_pInf_323)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 323.
   */
  void register_pInf_323()
  {
    RegisterPositiveInfinity<323>();
  }

  /**
   * Address: 0x00BE89E0 (FUN_00BE89E0, register_nInf_323)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 323 from `pInf_323`.
   */
  void register_nInf_323()
  {
    RegisterNegativeInfinity<323>();
  }

  /**
   * Address: 0x00BE8A00 (FUN_00BE8A00, register_NaN_323)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 323.
   */
  void register_NaN_323()
  {
    RegisterQuietNaN<323>();
  }

  /**
   * Address: 0x00BE8A60 (FUN_00BE8A60, register_pInf_324)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 324.
   */
  void register_pInf_324()
  {
    RegisterPositiveInfinity<324>();
  }

  /**
   * Address: 0x00BE8A80 (FUN_00BE8A80, register_nInf_324)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 324 from `pInf_324`.
   */
  void register_nInf_324()
  {
    RegisterNegativeInfinity<324>();
  }

  /**
   * Address: 0x00BE8AA0 (FUN_00BE8AA0, register_NaN_324)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 324.
   */
  void register_NaN_324()
  {
    RegisterQuietNaN<324>();
  }

  /**
   * Address: 0x00BE8AD0 (FUN_00BE8AD0, register_pInf_325)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 325.
   */
  void register_pInf_325()
  {
    RegisterPositiveInfinity<325>();
  }

  /**
   * Address: 0x00BE8AF0 (FUN_00BE8AF0, register_nInf_325)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 325 from `pInf_325`.
   */
  void register_nInf_325()
  {
    RegisterNegativeInfinity<325>();
  }

  /**
   * Address: 0x00BE8B10 (FUN_00BE8B10, register_NaN_325)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 325.
   */
  void register_NaN_325()
  {
    RegisterQuietNaN<325>();
  }

  /**
   * Address: 0x00BE8D00 (FUN_00BE8D00, register_pInf_326)
   *
   * What it does:
   * Initializes the recovered positive-infinity lane for slot 326.
   */
  void register_pInf_326()
  {
    RegisterPositiveInfinity<326>();
  }

  /**
   * Address: 0x00BE8D20 (FUN_00BE8D20, register_nInf_326)
   *
   * What it does:
   * Initializes the recovered negative-infinity lane for slot 326 from `pInf_326`.
   */
  void register_nInf_326()
  {
    RegisterNegativeInfinity<326>();
  }

  /**
   * Address: 0x00BE8D40 (FUN_00BE8D40, register_NaN_326)
   *
   * What it does:
   * Initializes the recovered quiet-NaN lane for slot 326.
   */
  void register_NaN_326()
  {
    RegisterQuietNaN<326>();
  }

} // namespace moho

namespace
{
  struct SimFloatInitializersBootstrap2
  {
    SimFloatInitializersBootstrap2()
    {
      moho::register_pInf_0();
      moho::register_nInf_0();
      moho::register_NaN_0();
      moho::register_pInf_1();
      moho::register_nInf_1();
      moho::register_NaN_1();
      moho::register_pInf_2();
      moho::register_nInf_2();
      moho::register_NaN_2();
      moho::register_pInf_3();
      moho::register_nInf_3();
      moho::register_NaN_3();
      moho::register_pInf_4();
      moho::register_nInf_4();
      moho::register_NaN_4();
      moho::register_pInf_5();
      moho::register_nInf_5();
      moho::register_NaN_5();
      moho::register_pInf_6();
      moho::register_nInf_6();
      moho::register_NaN_6();
      moho::register_pInf_7();
      moho::register_nInf_7();
      moho::register_NaN_7();
      moho::register_pInf_8();
      moho::register_nInf_8();
      moho::register_NaN_8();
      moho::register_pInf_200();
      moho::register_nInf_200();
      moho::register_NaN_200();
      moho::register_pInf_201();
      moho::register_nInf_201();
      moho::register_NaN_201();
      moho::register_pInf_202();
      moho::register_nInf_202();
      moho::register_NaN_202();
      moho::register_pInf_203();
      moho::register_nInf_203();
      moho::register_NaN_203();
      moho::register_pInf_204();
      moho::register_nInf_204();
      moho::register_NaN_204();
      moho::register_pInf_205();
      moho::register_nInf_205();
      moho::register_NaN_205();
      moho::register_pInf_206();
      moho::register_nInf_206();
      moho::register_NaN_206();
      moho::register_pInf_207();
      moho::register_nInf_207();
      moho::register_NaN_207();
      moho::register_pInf_208();
      moho::register_nInf_208();
      moho::register_NaN_208();
      moho::register_pInf_209();
      moho::register_nInf_209();
      moho::register_NaN_209();
      moho::register_pInf_210();
      moho::register_nInf_210();
      moho::register_NaN_210();
      moho::register_pInf_211();
      moho::register_nInf_211();
      moho::register_NaN_211();
      moho::register_pInf_212();
      moho::register_nInf_212();
      moho::register_NaN_212();
      moho::register_pInf_213();
      moho::register_nInf_213();
      moho::register_NaN_213();
      moho::register_pInf_214();
      moho::register_nInf_214();
      moho::register_NaN_214();
      moho::register_pInf_215();
      moho::register_nInf_215();
      moho::register_NaN_215();
      moho::register_pInf_216();
      moho::register_nInf_216();
      moho::register_NaN_216();
      moho::register_pInf_217();
      moho::register_nInf_217();
      moho::register_NaN_217();
      moho::register_pInf_218();
      moho::register_nInf_218();
      moho::register_NaN_218();
      moho::register_pInf_219();
      moho::register_nInf_219();
      moho::register_NaN_219();
      moho::register_pInf_220();
      moho::register_nInf_220();
      moho::register_NaN_220();
      moho::register_pInf_221();
      moho::register_nInf_221();
      moho::register_NaN_221();
      moho::register_pInf_222();
      moho::register_nInf_222();
      moho::register_NaN_222();
      moho::register_pInf_223();
      moho::register_nInf_223();
      moho::register_NaN_223();
      moho::register_pInf_224();
      moho::register_nInf_224();
      moho::register_NaN_224();
      moho::register_pInf_225();
      moho::register_nInf_225();
      moho::register_NaN_225();
      moho::register_pInf_226();
      moho::register_nInf_226();
      moho::register_NaN_226();
      moho::register_pInf_227();
      moho::register_nInf_227();
      moho::register_NaN_227();
      moho::register_pInf_228();
      moho::register_nInf_228();
      moho::register_NaN_228();
      moho::register_pInf_229();
      moho::register_nInf_229();
      moho::register_NaN_229();
      moho::register_pInf_230();
      moho::register_nInf_230();
      moho::register_NaN_230();
      moho::register_pInf_231();
      moho::register_nInf_231();
      moho::register_NaN_231();
      moho::register_pInf_232();
      moho::register_nInf_232();
      moho::register_NaN_232();
      moho::register_pInf_233();
      moho::register_nInf_233();
      moho::register_NaN_233();
      moho::register_pInf_234();
      moho::register_nInf_234();
      moho::register_NaN_234();
      moho::register_pInf_235();
      moho::register_nInf_235();
      moho::register_NaN_235();
      moho::register_pInf_236();
      moho::register_nInf_236();
      moho::register_NaN_236();
      moho::register_pInf_237();
      moho::register_nInf_237();
      moho::register_NaN_237();
      moho::register_pInf_238();
      moho::register_nInf_238();
      moho::register_NaN_238();
      moho::register_pInf_239();
      moho::register_nInf_239();
      moho::register_NaN_239();
      moho::register_pInf_240();
      moho::register_nInf_240();
      moho::register_NaN_240();
      moho::register_pInf_241();
      moho::register_nInf_241();
      moho::register_NaN_241();
      moho::register_pInf_242();
      moho::register_nInf_242();
      moho::register_NaN_242();
      moho::register_pInf_243();
      moho::register_nInf_243();
      moho::register_NaN_243();
      moho::register_pInf_244();
      moho::register_nInf_244();
      moho::register_NaN_244();
      moho::register_pInf_245();
      moho::register_nInf_245();
      moho::register_NaN_245();
      moho::register_pInf_246();
      moho::register_nInf_246();
      moho::register_NaN_246();
      moho::register_pInf_247();
      moho::register_nInf_247();
      moho::register_NaN_247();
      moho::register_pInf_248();
      moho::register_nInf_248();
      moho::register_NaN_248();
      moho::register_pInf_249();
      moho::register_nInf_249();
      moho::register_NaN_249();
      moho::register_pInf_250();
      moho::register_nInf_250();
      moho::register_NaN_250();
      moho::register_pInf_251();
      moho::register_nInf_251();
      moho::register_NaN_251();
      moho::register_pInf_252();
      moho::register_nInf_252();
      moho::register_NaN_252();
      moho::register_pInf_253();
      moho::register_nInf_253();
      moho::register_NaN_253();
      moho::register_pInf_254();
      moho::register_nInf_254();
      moho::register_NaN_254();
      moho::register_pInf_255();
      moho::register_nInf_255();
      moho::register_NaN_255();
      moho::register_pInf_256();
      moho::register_nInf_256();
      moho::register_NaN_256();
      moho::register_pInf_257();
      moho::register_nInf_257();
      moho::register_NaN_257();
      moho::register_pInf_258();
      moho::register_nInf_258();
      moho::register_NaN_258();
      moho::register_pInf_259();
      moho::register_nInf_259();
      moho::register_NaN_259();
      moho::register_pInf_260();
      moho::register_nInf_260();
      moho::register_NaN_260();
      moho::register_pInf_261();
      moho::register_nInf_261();
      moho::register_NaN_261();
      moho::register_pInf_262();
      moho::register_nInf_262();
      moho::register_NaN_262();
      moho::register_pInf_263();
      moho::register_nInf_263();
      moho::register_NaN_263();
      moho::register_pInf_264();
      moho::register_nInf_264();
      moho::register_NaN_264();
      moho::register_pInf_265();
      moho::register_nInf_265();
      moho::register_NaN_265();
      moho::register_pInf_266();
      moho::register_nInf_266();
      moho::register_NaN_266();
      moho::register_pInf_267();
      moho::register_nInf_267();
      moho::register_NaN_267();
      moho::register_pInf_268();
      moho::register_nInf_268();
      moho::register_NaN_268();
      moho::register_pInf_269();
      moho::register_nInf_269();
      moho::register_NaN_269();
      moho::register_pInf_270();
      moho::register_nInf_270();
      moho::register_NaN_270();
      moho::register_pInf_271();
      moho::register_nInf_271();
      moho::register_NaN_271();
      moho::register_pInf_272();
      moho::register_nInf_272();
      moho::register_NaN_272();
      moho::register_pInf_273();
      moho::register_nInf_273();
      moho::register_NaN_273();
      moho::register_pInf_274();
      moho::register_nInf_274();
      moho::register_NaN_274();
      moho::register_pInf_275();
      moho::register_nInf_275();
      moho::register_NaN_275();
      moho::register_pInf_276();
      moho::register_nInf_276();
      moho::register_NaN_276();
      moho::register_pInf_277();
      moho::register_nInf_277();
      moho::register_NaN_277();
      moho::register_pInf_278();
      moho::register_nInf_278();
      moho::register_NaN_278();
      moho::register_pInf_279();
      moho::register_nInf_279();
      moho::register_NaN_279();
      moho::register_pInf_280();
      moho::register_nInf_280();
      moho::register_NaN_280();
      moho::register_pInf_281();
      moho::register_nInf_281();
      moho::register_NaN_281();
      moho::register_pInf_282();
      moho::register_nInf_282();
      moho::register_NaN_282();
      moho::register_pInf_283();
      moho::register_nInf_283();
      moho::register_NaN_283();
      moho::register_pInf_284();
      moho::register_nInf_284();
      moho::register_NaN_284();
      moho::register_pInf_285();
      moho::register_nInf_285();
      moho::register_NaN_285();
      moho::register_pInf_286();
      moho::register_nInf_286();
      moho::register_NaN_286();
      moho::register_pInf_287();
      moho::register_nInf_287();
      moho::register_NaN_287();
      moho::register_pInf_288();
      moho::register_nInf_288();
      moho::register_NaN_288();
      moho::register_pInf_289();
      moho::register_nInf_289();
      moho::register_NaN_289();
      moho::register_pInf_290();
      moho::register_nInf_290();
      moho::register_NaN_290();
      moho::register_pInf_291();
      moho::register_nInf_291();
      moho::register_NaN_291();
      moho::register_pInf_292();
      moho::register_nInf_292();
      moho::register_NaN_292();
      moho::register_pInf_293();
      moho::register_nInf_293();
      moho::register_NaN_293();
      moho::register_pInf_294();
      moho::register_nInf_294();
      moho::register_NaN_294();
      moho::register_pInf_295();
      moho::register_nInf_295();
      moho::register_NaN_295();
      moho::register_pInf_296();
      moho::register_nInf_296();
      moho::register_NaN_296();
      moho::register_pInf_297();
      moho::register_nInf_297();
      moho::register_NaN_297();
      moho::register_pInf_298();
      moho::register_nInf_298();
      moho::register_NaN_298();
      moho::register_pInf_299();
      moho::register_nInf_299();
      moho::register_NaN_299();
      moho::register_pInf_300();
      moho::register_nInf_300();
      moho::register_NaN_300();
      moho::register_pInf_301();
      moho::register_nInf_301();
      moho::register_NaN_301();
      moho::register_pInf_302();
      moho::register_nInf_302();
      moho::register_NaN_302();
      moho::register_pInf_303();
      moho::register_nInf_303();
      moho::register_NaN_303();
      moho::register_pInf_304();
      moho::register_nInf_304();
      moho::register_NaN_304();
      moho::register_pInf_305();
      moho::register_nInf_305();
      moho::register_NaN_305();
      moho::register_pInf_306();
      moho::register_nInf_306();
      moho::register_NaN_306();
      moho::register_pInf_307();
      moho::register_nInf_307();
      moho::register_NaN_307();
      moho::register_pInf_308();
      moho::register_nInf_308();
      moho::register_NaN_308();
      moho::register_pInf_309();
      moho::register_nInf_309();
      moho::register_NaN_309();
      moho::register_pInf_310();
      moho::register_nInf_310();
      moho::register_NaN_310();
      moho::register_pInf_311();
      moho::register_nInf_311();
      moho::register_NaN_311();
      moho::register_pInf_312();
      moho::register_nInf_312();
      moho::register_NaN_312();
      moho::register_pInf_313();
      moho::register_nInf_313();
      moho::register_NaN_313();
      moho::register_pInf_314();
      moho::register_nInf_314();
      moho::register_NaN_314();
      moho::register_pInf_315();
      moho::register_nInf_315();
      moho::register_NaN_315();
      moho::register_pInf_316();
      moho::register_nInf_316();
      moho::register_NaN_316();
      moho::register_pInf_317();
      moho::register_nInf_317();
      moho::register_NaN_317();
      moho::register_pInf_318();
      moho::register_nInf_318();
      moho::register_NaN_318();
      moho::register_pInf_319();
      moho::register_nInf_319();
      moho::register_NaN_319();
      moho::register_pInf_320();
      moho::register_nInf_320();
      moho::register_NaN_320();
      moho::register_pInf_321();
      moho::register_nInf_321();
      moho::register_NaN_321();
      moho::register_pInf_322();
      moho::register_nInf_322();
      moho::register_NaN_322();
      moho::register_pInf_323();
      moho::register_nInf_323();
      moho::register_NaN_323();
      moho::register_pInf_324();
      moho::register_nInf_324();
      moho::register_NaN_324();
      moho::register_pInf_325();
      moho::register_nInf_325();
      moho::register_NaN_325();
      moho::register_pInf_326();
      moho::register_nInf_326();
      moho::register_NaN_326();
    }
  };

  [[maybe_unused]] SimFloatInitializersBootstrap2 gSimFloatInitializersBootstrap2;
} // namespace
