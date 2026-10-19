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
