using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace HOI4Admission
{
    // A short-lived bearer authorization for one exact native join packet. The
    // service must recheck the issuer's live verified lease after consuming it.
    public sealed class JoinTicket
    {
        public readonly int IssuerPid;
        public readonly long IssuerCreation;
        public readonly string Player, Session, Lease, PacketHash;
        public readonly int MessageType;
        public readonly int Channel = 1;
        public readonly int HostPid;
        public readonly long HostCreation;
        public readonly ulong Connection;

        internal JoinTicket(ClientRecord issuer, string hash, int type)
        {
            IssuerPid = issuer.Pid;
            IssuerCreation = issuer.Creation;
            Player = issuer.Player;
            Session = issuer.Session;
            Lease = issuer.Lease;
            PacketHash = hash;
            MessageType = type;
        }

        internal JoinTicket(JoinTicket issued, int hostPid, long hostCreation, ulong connection)
        {
            IssuerPid = issued.IssuerPid;
            IssuerCreation = issued.IssuerCreation;
            Player = issued.Player;
            Session = issued.Session;
            Lease = issued.Lease;
            PacketHash = issued.PacketHash;
            MessageType = issued.MessageType;
            HostPid = hostPid;
            HostCreation = hostCreation;
            Connection = connection;
        }
    }

    public sealed class JoinTicketStore
    {
        private sealed class Entry
        {
            public readonly JoinTicket Ticket;
            public readonly long IssuedAt;
            public Entry(JoinTicket ticket, long issuedAt) { Ticket = ticket; IssuedAt = issuedAt; }
        }

        public const int Capacity = 1024;
        public const int LifetimeSeconds = 10;
        private readonly object sync = new object();
        private readonly Dictionary<string, Entry> pending = new Dictionary<string, Entry>(StringComparer.Ordinal);
        private readonly string session;
        private readonly Func<long> timestamp;
        private readonly long lifetimeTicks;

        public JoinTicketStore(string sessionId) : this(sessionId, Stopwatch.GetTimestamp, Stopwatch.Frequency) { }

        // Injectable monotonic clock makes boundary and concurrency tests
        // deterministic without waiting or changing the system clock.
        public JoinTicketStore(string sessionId, Func<long> monotonicTimestamp, long frequency)
        {
            if (string.IsNullOrEmpty(sessionId)) throw new ArgumentException("Session required", "sessionId");
            if (monotonicTimestamp == null) throw new ArgumentNullException("monotonicTimestamp");
            if (frequency < 1 || frequency > long.MaxValue / LifetimeSeconds) throw new ArgumentOutOfRangeException("frequency");
            session = sessionId;
            timestamp = monotonicTimestamp;
            lifetimeTicks = frequency * LifetimeSeconds;
        }

        public string Issue(ClientRecord issuer, string packetHash, int messageType)
        {
            if (issuer == null || !issuer.Eligible || issuer.Pid <= 0 || issuer.Creation <= 0 ||
                string.IsNullOrEmpty(issuer.Player) || string.IsNullOrEmpty(issuer.Lease) || issuer.Session != session)
                throw new InvalidOperationException("TICKET_ISSUER_NOT_VERIFIED");
            if (!IsHash(packetHash)) throw new ArgumentException("Expected lowercase SHA256", "packetHash");
            if (!IsJoinType(messageType)) throw new ArgumentOutOfRangeException("messageType");
            // Copy the record before retaining it: mutable service records cannot
            // retroactively change who a ticket was issued to.
            var issued = new JoinTicket(issuer, packetHash, messageType);
            lock (sync)
            {
                long now = timestamp();
                Prune(now);
                if (pending.Count >= Capacity) throw new InvalidOperationException("TICKET_CAPACITY_REACHED");
                string token;
                do { token = Files.RandomHex(); } while (pending.ContainsKey(token));
                pending.Add(token, new Entry(issued, now));
                return token;
            }
        }

        public bool TryConsume(string token, string packetHash, int messageType,
            int hostPid, long hostCreation, ulong connection, out JoinTicket ticket, out string reason)
        {
            ticket = null;
            reason = "TICKET_NOT_FOUND";
            if (!IsHash(token)) return false;
            lock (sync)
            {
                long now = timestamp();
                Entry entry;
                if (!pending.TryGetValue(token, out entry)) { Prune(now); return false; }
                // Every lookup of a real ticket consumes it, including rejected
                // attempts. Two concurrent peers cannot redeem the same token.
                pending.Remove(token);
                Prune(now);
                if (Expired(entry, now)) { reason = "TICKET_EXPIRED"; return false; }
                if (hostPid <= 0 || hostCreation <= 0 || connection == 0)
                { reason = "TICKET_HOST_IDENTITY_INVALID"; return false; }
                if (!IsHash(packetHash) || packetHash != entry.Ticket.PacketHash)
                { reason = "TICKET_PAYLOAD_MISMATCH"; return false; }
                if (!IsJoinType(messageType) || messageType != entry.Ticket.MessageType)
                { reason = "TICKET_MESSAGE_MISMATCH"; return false; }
                ticket = new JoinTicket(entry.Ticket, hostPid, hostCreation, connection);
                reason = "TICKET_CONSUMED";
                return true;
            }
        }

        private bool Expired(Entry entry, long now)
        {
            // A backwards clock or wrap beyond the short lifetime fails closed.
            return unchecked((ulong)(now - entry.IssuedAt)) >= (ulong)lifetimeTicks;
        }

        private void Prune(long now)
        {
            List<string> expired = null;
            foreach (var item in pending)
            {
                if (!Expired(item.Value, now)) continue;
                if (expired == null) expired = new List<string>();
                expired.Add(item.Key);
            }
            if (expired != null) foreach (string token in expired) pending.Remove(token);
        }

        private static bool IsJoinType(int type) { return type == 8 || type == 9 || type == 14; }
        private static bool IsHash(string value)
        {
            if (value == null || value.Length != 64) return false;
            foreach (char ch in value) if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
            return true;
        }
    }
}
