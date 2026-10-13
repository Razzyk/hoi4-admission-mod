# v0.3.0

- Enforce native lobby admission before the original HOI4 host callback.
- Issue ten-second, single-use tickets bound to the outgoing join packet and a verified local process lease.
- Reject missing, malformed, changed, expired, replayed or unauthorized tickets.
- Validate the supported HOI4 executable and native callback fingerprints before installing three atomic pointer guards.
- Publish a standalone module package for the independent HOI4 Injector updater.

Local normal joining has been tested with a verified injected client accepted and a plain client refused. The verification service currently supports clients on the same machine; remote clients require a network broker. Positive live hotjoin, reconnect and crossplay tests remain outstanding.
