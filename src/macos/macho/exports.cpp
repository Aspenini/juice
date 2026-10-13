#include "macos/macho/exports.hpp"

#include <cstring>

namespace juice::mac {

namespace {

bool uleb(std::span<const uint8_t> d, size_t& at, uint64_t& out) {
  out = 0;
  for (unsigned shift = 0; at < d.size() && shift < 64; shift += 7) {
    const uint8_t b = d[at++];
    out |= uint64_t{b & 0x7Fu} << shift;
    if (!(b & 0x80)) return true;
  }
  return false;
}

bool cstring(std::span<const uint8_t> d, size_t& at, std::string_view& out) {
  const size_t start = at;
  while (at < d.size() && d[at]) ++at;
  if (at >= d.size()) return false;
  out = {reinterpret_cast<const char*>(d.data() + start), at - start};
  ++at;
  return true;
}

// Reads the terminal information of the node at `node`; false if it has none.
bool terminal(std::span<const uint8_t> d, size_t node, Export& e, size_t& children) {
  size_t at = node;
  uint64_t size;
  if (!uleb(d, at, size)) return false;
  children = at + size;
  if (size == 0) return false;
  if (!uleb(d, at, e.flags)) return false;
  if (e.flags & kExportReexport) {
    uint64_t ordinal;
    std::string_view name;
    if (!uleb(d, at, ordinal) || !cstring(d, at, name)) return false;
    e.ordinal = static_cast<int>(ordinal);
    e.import_name = name;
  } else {
    if (!uleb(d, at, e.address)) return false;
    if ((e.flags & kExportStubAndResolver) && !uleb(d, at, e.resolver)) return false;
  }
  return true;
}

void walk(std::span<const uint8_t> d, size_t node, std::string& prefix, std::vector<Export>& out, unsigned depth) {
  if (node >= d.size() || depth > 512) return;
  Export e;
  size_t at = 0;
  if (terminal(d, node, e, at)) {
    e.name = prefix;
    out.push_back(std::move(e));
  }
  if (at >= d.size()) return;
  const uint8_t count = d[at++];
  for (unsigned k = 0; k < count; ++k) {
    std::string_view edge;
    uint64_t child;
    if (!cstring(d, at, edge) || !uleb(d, at, child)) return;
    if (child == 0 || child >= d.size()) continue;  // (a child is never the root)
    const size_t keep = prefix.size();
    prefix += edge;
    walk(d, child, prefix, out, depth + 1);
    prefix.resize(keep);
  }
}

}  // namespace

std::optional<Export> find_export(std::span<const uint8_t> d, std::string_view name) {
  size_t node = 0;
  std::string_view rest = name;
  for (unsigned steps = 0; steps < 4096 && node < d.size(); ++steps) {
    Export e;
    size_t at = 0;
    const bool has_terminal = terminal(d, node, e, at);
    if (rest.empty()) {
      if (!has_terminal) return std::nullopt;
      e.name = name;
      return e;
    }
    if (at >= d.size()) return std::nullopt;
    const uint8_t count = d[at++];
    bool advanced = false;
    for (unsigned k = 0; k < count; ++k) {
      std::string_view edge;
      uint64_t child;
      if (!cstring(d, at, edge) || !uleb(d, at, child)) return std::nullopt;
      if (rest.starts_with(edge) && !edge.empty()) {
        rest.remove_prefix(edge.size());
        node = child;
        advanced = true;
        break;
      }
    }
    if (!advanced || node == 0) return std::nullopt;
  }
  return std::nullopt;
}

std::vector<Export> all_exports(std::span<const uint8_t> d) {
  std::vector<Export> out;
  std::string prefix;
  walk(d, 0, prefix, out, 0);
  return out;
}

}  // namespace juice::mac
