#pragma once

#include <cstddef>
#include "gpg/core/reflection/Reflection.h"


  class voidTypeInfo final : public gpg::RType
  {
  public:
    /** Address: 0x008DF9E0 */
    voidTypeInfo();
    /** Address: 0x008DFA70 */
    ~voidTypeInfo() override;
    /** Address: 0x008DFA60 */
    [[nodiscard]] const char* GetName() const override;
    /** Address: 0x008DFA50 */
    void Init() override;
  };

  static_assert(sizeof(voidTypeInfo) == 0x64, "voidTypeInfo size must be 0x64");

  /** Address: 0x00BE97E0 */
  void register_voidTypeInfoStartup();

