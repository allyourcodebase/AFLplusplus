# AFLplusplus

[![CI][ci-shd]][ci-url]
[![LC][lc-shd]][lc-url]

## Zig build of [AFLplusplus project](https://github.com/AFLplusplus/AFLplusplus).


### :arrow_down: Dependencies

Requires a build of LLVM. You can either get one from your favorite package manager, or [build it yourself](https://github.com/ziglang/zig/wiki/How-to-build-LLVM,-libclang,-and-liblld-from-source).

### :rocket: Usage

```sh
git clone https://github.com/allyourcodebase/AFLplusplus.git
cd AFLplusplus/
zig build
```

### :100: Easy Source Fuzzing with AFL++

For help fuzzing your executables, see [kristoff-it/zig-afl-kit](https://github.com/kristoff-it/zig-afl-kit).

<!-- MARKDOWN LINKS -->

[ci-shd]: https://img.shields.io/github/actions/workflow/status/allyourcodebase/AFLplusplus/ci.yaml?branch=main&style=for-the-badge&logo=github&label=CI&labelColor=black
[ci-url]: https://github.com/allyourcodebase/AFLplusplus/blob/main/.github/workflows/ci.yaml
[lc-shd]: https://img.shields.io/github/license/allyourcodebase/AFLplusplus.svg?style=for-the-badge&labelColor=black
[lc-url]: https://github.com/allyourcodebase/AFLplusplus/blob/main/LICENSE
