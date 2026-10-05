#include "linux/abi/initial_stack.hpp"

#include <cstring>

#include "linux/abi/translate.hpp"

namespace juice::lx {

uint64_t build_initial_stack(uint64_t top, uint64_t limit, const InitialStackInput& in) {
  uint64_t sp = top;
  bool overflow = false;
  auto push_bytes = [&](const void* data, size_t size) -> uint64_t {
    if (sp - limit < size) {
      overflow = true;
      return 0;
    }
    sp -= size;
    std::memcpy(reinterpret_cast<void*>(sp), data, size);
    return sp;
  };
  auto push_string = [&](const std::string& s) { return push_bytes(s.c_str(), s.size() + 1); };

  // Strings first (highest addresses), like the kernel: execfn, envp, argv.
  const uint64_t execfn = push_string(in.execfn);
  std::vector<uint64_t> env_ptrs, arg_ptrs;
  for (auto it = in.envp.rbegin(); it != in.envp.rend(); ++it) env_ptrs.insert(env_ptrs.begin(), push_string(*it));
  for (auto it = in.argv.rbegin(); it != in.argv.rend(); ++it) arg_ptrs.insert(arg_ptrs.begin(), push_string(*it));
  const uint64_t platform = push_string(in.platform);
  sp &= ~uint64_t{15};
  const uint64_t random = push_bytes(in.random.data(), in.random.size());
  if (overflow) return 0;

  std::vector<uint64_t> words;
  words.push_back(in.argv.size());
  words.insert(words.end(), arg_ptrs.begin(), arg_ptrs.end());
  words.push_back(0);
  words.insert(words.end(), env_ptrs.begin(), env_ptrs.end());
  words.push_back(0);
  for (const auto& [key, value] : in.auxv) {
    words.push_back(key);
    words.push_back(value);
  }
  for (const auto& [key, value] : {std::pair<uint64_t, uint64_t>{kAtRandom, random},
                                   {kAtPlatform, platform}, {kAtExecfn, execfn}, {kAtNull, 0}}) {
    words.push_back(key);
    words.push_back(value);
  }
  const size_t bytes = words.size() * 8;
  sp = (sp - bytes) & ~uint64_t{15};  // argc must be 16-byte aligned
  if (sp < limit) return 0;
  std::memcpy(reinterpret_cast<void*>(sp), words.data(), bytes);
  return sp;
}

}  // namespace juice::lx
