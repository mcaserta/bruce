#!/bin/sh
# Builds the online docs into build/book. Needs mdbook on the PATH.
set -eu
cd "$(dirname "$0")/.."
rm -rf build/book-src build/book
mkdir -p build/book-src
cp -R README.md SUMMARY.md essentials api build/book-src/
# Files outside the book (CONTRIBUTING.md, ...) only exist on GitHub.
sed -i.bak 's#](CONTRIBUTING.md)#](https://github.com/mcaserta/bruce/blob/main/CONTRIBUTING.md)#g' build/book-src/README.md
rm build/book-src/README.md.bak
mdbook build
