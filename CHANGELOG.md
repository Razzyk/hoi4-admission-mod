# v0.5.1 (development, unreleased)

- Restrict difficulty, custom difficulty multipliers, game rules and their reset/alternate settings commands to host authority. Remote clients cannot use these settings to change country/combat modifiers.
- Validate new equipment designs as well as updates against the host equipment type's upgrade definitions and native level predicate. Keep unchanged inherited levels and native first-definition deduplication; refuse type-changing updates.
- Rebuild changed MIO bonus payloads from the host's current organization/type query before native validation and broadcast. Preserve exact inherited bonuses, including designs without an active MIO reference.
- Bind five MIO trait unlock/queue commands to the resolved organization's owner, preserving co-op control and native eligibility.
- Expand the reviewed registry to 36 command classes and 113 hook slots. Keep pending normalization out of early synchronization history and refuse stale references before native lookup.

This development build still has incomplete XP-price, module, event-option eligibility and scripted-GUI authorization coverage. It does not attest remote memory or establish normal campaign compatibility; see AUTHORIZATION.md and VALIDATION.md.

# v0.5.0 (development, unreleased)

- Add host command authorization for 25 reviewed command classes, binding incoming commands to the native transport sender and checking current country control at ordered validation.
- Observe native co-op approvals and scripted country changes; track private command provenance across queues, destruction, reconnects and world loads.
- Prevent pending remote commands from entering early synchronization history before authorization. Keep the native hotjoin-eligibility and post-execution paths separate.
- Check changed matching upgrade levels in same-type equipment updates with the native UI predicate; preserve unchanged inherited levels and continue validating known keys when new keys are present.
- Reject direct spirit/hidden-idea commands, substituted pending event rewards and invalid factory-assignment arithmetic.
- Require authorization hook installation alongside admission and stability, add bounded rejection diagnostics, and inspect all 80 authorization hook slots read-only.

Coverage is partial. Equipment prices/statistics, other command families, hostile-client attestation and local memory edits remain outside these checks. Multiplayer campaign compatibility and overhead are unverified.

# v0.4.0

- Replace same-machine lobby tickets with a direct peer challenge over HOI4's existing multiplayer transport. Independent installations need no shared session configuration or external broker.
- Verify matching module/manifest identities, fresh connection-bound nonces, exact join payload, ten-second expiry, single consumption, bounded pending state and replay refusal before forwarding native admission.
- Add a fourth checked atomic pointer hook for client receive messages; keep local loader/bootstrap protocol 2 compatible with injector 0.4.0.
- Merge the experimental career-profile stability guard from Razzyk/hoi4-mp-stability-guard into the admission DLL. Both guards must install before eligibility; no second injected DLL is needed.

Peer admission is cooperative compatibility enforcement, not hostile-client remote attestation. Separate-network live joins, live hotjoin/reconnect and crossplay remain unverified. The career fix does not patch army modifier-tree teardown or establish campaign crash reduction.
# v0.3.0

- Enforce native lobby admission before the original HOI4 host callback.
- Issue ten-second, single-use tickets bound to the outgoing join packet and a verified local process lease.
- Reject missing, malformed, changed, expired, replayed or unauthorized tickets.
- Validate the supported HOI4 executable and native callback fingerprints before installing three atomic pointer guards.
- Publish a standalone module package for the independent HOI4 Injector updater.

Local normal joining has been tested with a verified injected client accepted and a plain client refused. The verification service currently supports clients on the same machine; remote clients require a network broker. Positive live hotjoin, reconnect and crossplay tests remain outstanding.
