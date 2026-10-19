# Source provenance

The native admission DLL, atomic vtable helper, peer handshake, local C# verification service, diagnostics, tests and build scripts in this repository were authored for this project. No HOI4 executable, decompiled implementation, game asset, save, runtime credential or user configuration is distributed.

The supported executable hash, native target addresses, small entry fingerprints, ABI and admission boundaries were established through read-only research of the user's installed HOI4 executable and an external analysis tree. `TARGETS.md` records this evidence. That analysis tree is not a source, build or runtime dependency, and its decompiled game implementation has not been copied into this repository.

The separate injector's original GUI work drew on the BakkesMod manager layout. This module repository contains no BakkesMod GUI XML, manager source or injection code. Its DLL admission and service protocol are authored code rather than BakkesMod's injection implementation.

Windows and .NET Framework APIs supply process identity, named pipes, BCrypt, hashing and memory protection. The local build uses Zig 0.15.2 and the installed .NET Framework compiler; compiler binaries are not bundled.

The stability guard under `native/stability/` is ported from the user-owned [Razzyk/hoi4-mp-stability-guard](https://github.com/Razzyk/hoi4-mp-stability-guard) at revision `a9c40d7ddf8f7320de0f7e69471c609003957984`. [STABILITY-PROVENANCE.md](STABILITY-PROVENANCE.md) describes the port, live-attach changes and limits. The standalone launcher's injection code is excluded.
