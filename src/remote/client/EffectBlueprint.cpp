#include "gpg/core/containers/String.h"
#include "moho/resource/RResId.h"
#include "moho/sim/RRuleGameRules.h"
#include "remote/client/EffectLaneApplier.h"

// Engine addition, server mode (plan WP9.3): see `HasEffectBlueprint` in EffectLaneApplier.h.

namespace faf::remote::client
{
  bool HasEffectBlueprint(
    moho::RRuleGameRules& rules,
    const moho::EEffectOp op,
    const std::string& name
  )
  {
    switch (op) {
    case moho::EEffectOp::CreateTrail:
      return moho::RULE_FindTrailBlueprintByName(&rules, name.c_str()) != nullptr;
    case moho::EEffectOp::CreateBeam:
    case moho::EEffectOp::CreateBeamEntityToEntity:
    case moho::EEffectOp::AttachBeamEntityToEntity: {
      // As the beam bindings look a beam up (EffectLuaStartupRegistrations.cpp, `CreateBeamEmitter`).
      moho::RResId id{};
      gpg::STR_InitFilename(&id.name, name.c_str());
      return rules.GetBeamBlueprint(id) != nullptr;
    }
    default:
      return moho::RULE_FindEmitterBlueprintByName(&rules, name.c_str()) != nullptr;
    }
  }
} // namespace faf::remote::client
