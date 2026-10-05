#include "linux/binfmt.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>

#include "linux/abi/binfmt_rule.hpp"

namespace juice::lx {

namespace {

constexpr const char* kBinfmtDir = "/proc/sys/fs/binfmt_misc";

std::expected<void, std::string> write_file(const std::string& path, const std::string& text) {
  const int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
  if (fd < 0) return std::unexpected(std::format("cannot open {}: {}", path, std::strerror(errno)));
  const ssize_t n = ::write(fd, text.data(), text.size());
  const int err = errno;
  ::close(fd);
  if (n != static_cast<ssize_t>(text.size()))
    return std::unexpected(std::format("cannot write {}: {}", path, std::strerror(err)));
  return {};
}

std::expected<void, std::string> check_mounted() {
  if (::access(std::format("{}/register", kBinfmtDir).c_str(), F_OK) == 0) return {};
  return std::unexpected(std::format(
      "{} is not mounted (mount -t binfmt_misc binfmt_misc {})", kBinfmtDir, kBinfmtDir));
}

}  // namespace

std::string juice_binary_path() {
  std::error_code ec;
  const auto self = std::filesystem::read_symlink("/proc/self/exe", ec);
  return ec ? std::string("/usr/local/bin/juice") : self.string();
}

std::string binfmt_launcher_path() {
  return (std::filesystem::path(juice_binary_path()).parent_path() / kBinfmtLauncher).string();
}

std::expected<void, std::string> install_binfmt() {
  if (auto ok = check_mounted(); !ok) return ok;
  const std::string launcher = binfmt_launcher_path();
  std::error_code ec;
  std::filesystem::remove(launcher, ec);
  std::filesystem::create_symlink(juice_binary_path(), launcher, ec);
  if (ec) return std::unexpected(std::format("cannot create {}: {}", launcher, ec.message()));

  const std::string entry = std::format("{}/{}", kBinfmtDir, kBinfmtName);
  if (::access(entry.c_str(), F_OK) == 0) {  // replace an older registration
    if (auto ok = write_file(entry, "-1"); !ok) return ok;
  }
  return write_file(std::format("{}/register", kBinfmtDir), binfmt_rule(launcher));
}

std::expected<void, std::string> uninstall_binfmt() {
  if (auto ok = check_mounted(); !ok) return ok;
  const std::string entry = std::format("{}/{}", kBinfmtDir, kBinfmtName);
  if (::access(entry.c_str(), F_OK) != 0) return std::unexpected(std::format("{} is not registered", kBinfmtName));
  return write_file(entry, "-1");
}

std::string binfmt_config() { return binfmt_rule(binfmt_launcher_path()) + "\n"; }

std::string binfmt_status() {
  std::ifstream in(std::format("{}/{}", kBinfmtDir, kBinfmtName));
  if (!in) return "not registered";
  std::stringstream text;
  text << in.rdbuf();
  return text.str();
}

}  // namespace juice::lx
