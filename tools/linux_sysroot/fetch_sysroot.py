#!/usr/bin/env python3
"""Builds an Ubuntu arm64 sysroot for running real AArch64 programs under JUICE.

Resolves the packages and their dependencies from ports.ubuntu.com's arm64
package indexes, downloads the .debs and extracts them with dpkg-deb into ROOT.
The host's apt and dpkg state is not touched.

usage: fetch_sysroot.py ROOT CODENAME package...
  e.g. fetch_sysroot.py ~/arm64root resolute bash coreutils busybox-static python3-minimal

Then: juice --sysroot=ROOT -- ROOT/usr/bin/bash -c 'echo hello'
"""
import lzma
import os
import subprocess
import sys
import urllib.request

MIRROR = "http://ports.ubuntu.com/ubuntu-ports"
# Packages whose maintainer scripts or files the programs don't need.
SKIP = {"debconf", "dpkg", "install-info", "libc-bin", "debianutils"}


def parse_index(data, packages):
    for stanza in data.split("\n\n"):
        fields = {}
        key = None
        for line in stanza.splitlines():
            if line.startswith(" ") and key:
                fields[key] += "\n" + line
            elif ":" in line:
                key, value = line.split(":", 1)
                fields[key] = value.strip()
        if "Package" not in fields:
            continue
        packages[fields["Package"]] = fields  # (later pockets - updates, security - override)
        for provided in fields.get("Provides", "").split(","):
            name = provided.strip().split(" ")[0]
            if name and name not in packages:
                packages.setdefault("virtual:" + name, fields)


def index(codename):
    packages = {}
    for component in ("main", "universe"):
        for suite in (codename, codename + "-updates", codename + "-security"):
            url = f"{MIRROR}/dists/{suite}/{component}/binary-arm64/Packages.xz"
            try:
                data = lzma.decompress(urllib.request.urlopen(url, timeout=60).read())
            except Exception as e:  # (an empty pocket)
                print(f"  {url}: {e}", file=sys.stderr)
                continue
            parse_index(data.decode("utf-8", "replace"), packages)
    return packages


def depends(fields):
    out = []
    for field in ("Pre-Depends", "Depends"):
        for alternatives in fields.get(field, "").split(","):
            alternatives = alternatives.strip()
            if alternatives:  # the first alternative, without version or architecture
                out.append(alternatives.split("|")[0].strip().split(" ")[0].split(":")[0])
    return out


def main():
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    root, codename, wanted = os.path.abspath(sys.argv[1]), sys.argv[2], sys.argv[3:]
    debs = os.path.join(root, ".debs")
    os.makedirs(debs, exist_ok=True)
    packages = index(codename)
    todo, done = list(wanted), set()
    while todo:
        name = todo.pop()
        if name in done or name in SKIP:
            continue
        done.add(name)
        fields = packages.get(name) or packages.get("virtual:" + name)
        if not fields:
            print(f"  not found: {name}", file=sys.stderr)
            continue
        todo.extend(depends(fields))
        filename = fields["Filename"]
        deb = os.path.join(debs, os.path.basename(filename))
        if not os.path.exists(deb):
            print(f"  {fields['Package']} {fields['Version']}")
            urllib.request.urlretrieve(f"{MIRROR}/{filename}", deb)
        subprocess.run(["dpkg-deb", "-x", deb, root], check=True)
    alternatives(root)
    print(f"{len(done)} packages in {root}")


def alternatives(root):
    """The library links update-alternatives would make (maintainer scripts don't run here):
    BLAS and LAPACK implementations live in subdirectories, linked from the library directory."""
    libdir = os.path.join(root, "usr/lib/aarch64-linux-gnu")
    for sub in ("blas", "lapack", "openblas-pthread", "openblas-openmp", "atlas"):
        d = os.path.join(libdir, sub)
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            link = os.path.join(libdir, name)
            if ".so" in name and not os.path.lexists(link):
                os.symlink(os.path.join(sub, name), link)


main()
