# Standalone stability fixtures

Run on Windows x64 with Zig 0.15.2:

```powershell
.\tests\stability\Test-Stability.ps1 -Zig '<path-to-zig.exe>' -WorkDirectory '.\work\stability-tests' -CacheDirectory '.\work\zig-stability-cache'
```

Reusing `CacheDirectory` avoids rebuilding Zig's runtime. The script restores the caller's Zig cache environment variables after it completes.

The career fixture passes 127 assertions. Its original parallel scheduler produces three same-country overlaps for six entries; the guarded path produces zero while preserving all six entries, weight 266, order, array fields, and ownership. Unique-country lists retain the original scheduler. Invalid inputs fall back once without partial kernel work, and a valid empty list passes through.

The hook fixture includes the integrated production implementation directly with `STABILITY_GUARD_TEST` hooks enabled only in the test executable. Its main run passed 296 assertions; three isolated failure runs passed 14, 14, and 16 assertions. Stress refusals can add assertions on subsequent runs. It executes an authored CALL before installation, through the register-preserving relay, and after restoring the original CALL. It checks changed-byte refusal, suspended-thread RIP refusal, preservation of an existing suspension count, RX protection restoration, and the integrated statistics and installed-verification APIs. Its synthetic original CALL is deliberately different from the pinned game bytes; the restored-state verifier refuses those bytes as a real HOI4 target.

Deterministic API hooks inject a late thread, a reused thread ID with changed creation time, malformed query offsets/counts, truncated/full query buffers, query errors/warnings, missing process/caller records, duplicate IDs, incorrect owners, thread-open/time/context/suspend failures, and a transient resume failure. These checks establish refusal before memory is written and preservation of prior suspension counts. Protection and instruction-cache failures check byte rollback and RX protection. Persistent resume failure checks that the engine retains frozen handles and its preallocated query buffer, poisons future patching, and supports test-only recovery without clearing that poison. Persistent recovery cases run in separate disposable processes.

Actual concurrent CALL workers and a continuous short-lived thread creator run across sixteen installation/removal cycles. In the recorded run, 3,825,651 completed calls and 35 created threads passed; every completed call matched exactly one original callback or one complete guarded callback. The fixture verifies all expected bytes and RX protection after each transaction or safe refusal. Code and relay mappings stay resident until all workers terminate or the isolated fixture exits.

Both fixtures run only in their own disposable processes. They require no HOI4 installation and never launch or inject into the game. These checks do not establish live campaign crash reduction, multiplayer synchronization, hot-join behavior, or performance. The separate army modifier teardown crash remains unpatched.
