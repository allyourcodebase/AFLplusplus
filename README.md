# AFLplusplus

[![CI][ci-shd]][ci-url]
[![LC][lc-shd]][lc-url]

## Zig build of [AFLplusplus executable suite](https://github.com/AFLplusplus/AFLplusplus).

### :rocket: Usage

```sh
git clone https://github.com/allyourcodebase/AFLplusplus.git
cd AFLplusplus/
zig build exes -Doptimize=ReleaseFast
./zig-out/bin/afl-fuzz
./zig-out/bin/afl-showmap
./zig-out/bin/afl-tmin
./zig-out/bin/afl-analyze
./zig-out/bin/afl-gotcpu
./zig-out/bin/afl-as
```

<!-- MARKDOWN LINKS -->

[ci-shd]: https://img.shields.io/github/actions/workflow/status/allyourcodebase/AFLplusplus/ci.yaml?branch=main&style=for-the-badge&logo=github&label=CI&labelColor=black
[ci-url]: https://github.com/allyourcodebase/AFLplusplus/blob/main/.github/workflows/ci.yaml
[lc-shd]: https://img.shields.io/github/license/allyourcodebase/AFLplusplus.svg?style=for-the-badge&labelColor=black
[lc-url]: https://github.com/allyourcodebase/AFLplusplus/blob/main/LICENSE
