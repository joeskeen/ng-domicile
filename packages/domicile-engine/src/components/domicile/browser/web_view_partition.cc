// Copyright 2026 Connor Prussin
// SPDX-License-Identifier: MIT

#include "components/domicile/browser/web_view_partition.h"

#include <string>

#include "base/containers/span.h"
#include "base/strings/strcat.h"
#include "base/strings/string_number_conversions.h"
#include "crypto/hash.h"

namespace domicile {
namespace {

constexpr char kPersistPrefix[] = "persist:";

}  // namespace

base::expected<std::optional<WebViewPartition>, std::string>
ParseWebViewPartition(std::string_view attribute) {
  if (attribute.empty()) {
    return std::nullopt;
  } else if (!attribute.starts_with(kPersistPrefix)) {
    return WebViewPartition{.name = std::string(attribute), .persist = false};
  } else if (attribute.size() == std::string_view(kPersistPrefix).size()) {
    return base::unexpected(
        "a partition of \"persist:\" names no partition to keep");
  } else {
    return WebViewPartition{
        .name = std::string(
            attribute.substr(std::string_view(kPersistPrefix).size())),
        .persist = true};
  }
}

std::string WebViewPartitionAttribute(const WebViewPartition& partition) {
  return partition.persist ? base::StrCat({kPersistPrefix, partition.name})
                           : partition.name;
}

base::FilePath WebViewPartitionPath(const base::FilePath& profile,
                                    const WebViewPartition& partition) {
  const auto hash = crypto::hash::Sha256(partition.name);
  return profile.Append("Storage")
      .Append("ext")
      .Append(kWebViewPartitionDomain)
      .AppendASCII(base::HexEncode(base::span(hash).first<6>()));
}

}  // namespace domicile
