# Host command authorization

This document describes the authorization work in the development tree. Published module **v0.4.0 does not include these checks**. Runtime and multiplayer validation must be recorded before a new release is described as protected.

The host is trusted. The guard binds selected incoming commands to the machine identity resolved by the native transport, then checks the host's current country assignments at the game's ordered validation boundary. A denied command must reach neither canonical broadcast nor execution. This adds no verification round trip and does not run a second game simulation.

## Coverage and limits

| Command family | Additional host rule |
|---|---|
| Reviewed construction, production, idea, research, focus, decision and country-priority commands | The authenticated sender must currently control the command's actor country. Legal foreign construction and decision targets remain subject to native rules. |
| Add, remove and replace ideas | Remote commands must use the native cost-check flag and reference selectable politics groups. National-spirit groups and hidden idea groups cannot be changed through these commands. Original native affordability, visibility, availability and replacement rules still apply. |
| Event option selection | Match the host's current pending event, definition, recipient and scope; preserve the native leader and permitted co-op event rules and require a valid nonnegative option index. An option request cannot substitute a different reward event or rerun its immediate effects. |
| Factory assignments to equipment production lines | Resolve the native line's owner and check sender control. Check signed arithmetic and each sequential projected assignment, including duplicate references in bulk commands, against zero and the native line maximum. |
| Equipment variant creation/update | Resolve the actor from the reviewed country field or a checked native variant reference, then check control. Same-type updates also check changed, matching upgrade levels with the native UI level-limit predicate. |
| Country controller changes | Preserve pre-game selection, native defeated-country observation, observer entry into an available country, and approved/scripted transitions. Other ungranted self-switches are locked once the game starts. Changes affecting another human or entering an occupied country need an applicable host-observed approval or script transition. |
| Co-op requests and approvals | Bind a request to its authenticated requester and an approval to the currently authorized country leader. An observer can request co-op. |
| Multiplayer debug settings | Accept native authority replication; refuse remote clients submitting authority settings to the host. |

This is a reviewed registry, not a universal rule based on command names or one common country-field offset. Unreviewed command classes keep native behavior. Target-country fields are not automatically actor-country fields.

**Actor authorization and the narrow upgrade-level check do not establish correct prices, all equipment statistics, or every other payload condition.** In particular, native equipment commands carry an XP price supplied by the client. Reconstructing and validating that price remains separate work; changing modifiers and consumable designer discounts can invalidate a naive comparison with the current host price.

The level check applies to updates whose equipment-type pointer matches the current variant. It follows the native merge's canonical definition IDs and checks each changed matching level with the trusted live definition. A new, nonmatching key cannot suppress validation of a known key. Unchanged inherited levels skip the predicate, preserving grandfathered designs after a cap changes. Type-changing edits, creation, XP prices, module/MIO effects and arbitrary stat overrides are outside this subset. A queued choice can become invalid after a legitimate cap or script-condition change; refusal is treated as stale input, not proof of cheating.

The idea rule follows the native politics UI's category metadata rather than spirit names: national-spirit group type `1` and hidden groups are excluded from direct player purchases. Normal focus, decision and event effects modify ideas through the host's script execution path, which is preserved. A custom gameplay mod that intentionally exposes a spirit purchase through these direct commands needs a reviewed compatibility rule.

These checks close specific network-command routes for adding spirits and triggering unearned rewards, including equipment or factories granted by an event. They do **not** establish universal prevention of factory/equipment spawning or hidden troop-stat changes. Arbitrary memory edits, dynamic modifier edits outside reviewed commands, scripted GUI authorization and unreviewed command families remain outside the coverage. Ordinary construction and equipment production continue to use native queues and ticks; they are not treated as illicit spawning.

Event option eligibility is not fully enforced. Vanilla evaluates option triggers when building the buttons and may accept an already displayed choice after its trigger becomes false. A current-state host recheck would reject some normal choices. The original dispatch context flag used by another UI filter is also absent from the pending-event record. Exact enforcement needs trusted eligibility records and corresponding client UI changes; this command filter does not guess the missing history. It also does not bind a client's random-state words to the pending event. These limits require further work and live validation before making a comprehensive event-authorization claim.

The native console already rejects retail multiplayer. The examined equipment-addition and instant-construction console callbacks modify local state directly, rather than submitting the network commands above. A host command filter cannot prevent edits to another computer's memory. The existing public peer handshake is cooperative compatibility checking, not hostile-client attestation.

Native UI and console code can construct the same command. The guard checks authority and state; it cannot reliably determine which input method produced an otherwise authorized action. The absence of a menu option is not used as evidence of permission. The host checks the live game phase and native transition facts.

## Ordering and lifecycle

Receive callbacks record private, bounded provenance and perform narrow loading, reference-type and country-index safety checks before native predicates. Country-control and upgrade-level decisions remain at the verified synchronous and asynchronous execution boundaries. The wrappers preserve the native validity result and cache a refusal for the native motivation retry. Destruction removes provenance, preventing reused object addresses from inheriting it.

The native reentrant update can copy pending commands into its synchronization history before ordinary validation. The guard must suppress that early copy for unaccepted remote commands while preserving the distinct hotjoin-eligibility and post-execution history paths. A rejected command must also be absent from a later hotjoin history snapshot.

Save loading and transport/session replacement invalidate pending approvals. Queued objects retain their old provenance epoch so they can be refused, rather than becoming unrecognized local objects. Stale or loading-time refusals are not grounds for labeling a player a cheater or ejecting them.

Scripted tag changes are observed through the existing native target getter, called once. The observer must preserve its result and RNG behavior, include co-op controllers and bind approvals to the affected player. Repeated requests must not fill the pending-grant store with duplicate permissions.

When a permitted script issues multiple changes from the same source before the first executes, remaining script permissions rebase after the accepted transition. Other assignment changes revoke pending permissions. An unavailable pre/post assignment observation revokes them rather than leaving an old permission reusable.

## Compatibility and validation

The target is HOI4 **1.19.3.0 Windows x64**, SHA256 `7dc947be34970da1e1c787bcddbe7f62b610ff258aebf8f06aa8b348f3a031d5`. Hook installation requires the pinned image, original vtable entries and verified instruction fingerprints. Eligibility must require successful admission, stability and authorization installation.

Standalone policy and provenance tests cover authority changes, observer co-op, approval executor binding, one-use grants, reconnect generations, capacity, concurrency, object reuse and stale epochs. These fixtures do not prove compatibility with a real multiplayer campaign.

Native wrapper fixtures check actual adapter entry points through authored private-image callsites, including AL-only boolean returns, motivation arguments, full-pointer destructor/getter returns, early history, host-local co-op, script batches and embedded variant references. Equipment fixtures use mocked native predicates; they do not substitute for a real equipment designer test.

Live validation must include ordinary construction and equipment design, co-op approval, observers, host reassignment, release-and-play, scripted/capitulation transitions, load/hotjoin/reconnect, backlogged commands and identical accepted command streams. Campaign performance and absence of false positives require those tests; a fast standalone lookup benchmark does not establish zero gameplay overhead.
