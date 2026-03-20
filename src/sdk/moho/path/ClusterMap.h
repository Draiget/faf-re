#pragma once

#include "gpg/core/algorithms/Cluster.h"

namespace moho
{
  // Compatibility shim: path-layer names map directly to recovered HaStar types.
  using Cluster = gpg::HaStar::Cluster;
  using SubCluster = gpg::HaStar::Subcluster;
  using ClusterMap = gpg::HaStar::ClusterMap;
} // namespace moho
