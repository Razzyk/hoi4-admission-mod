using System;
using System.Threading;
using System.Threading.Tasks;
using HOI4Admission;

public static class JoinTicketTests
{
    private static int count;
    private static readonly string Hash = new string('a', 64);
    private static void Check(bool value, string description)
    {
        if (!value) throw new Exception(description);
        count++;
        Console.WriteLine("PASS " + description);
    }
    private static ClientRecord Issuer()
    {
        return new ClientRecord { Pid = 123, Creation = 456, Player = "player-one", Session = "test-session", Lease = "lease-one", Eligible = true };
    }
    private static bool Consume(JoinTicketStore store, string token, string hash, int type, out JoinTicket ticket, out string reason)
    { return store.TryConsume(token, hash, type, 234, 567, 678, out ticket, out reason); }
    private static bool Throws(Action operation)
    {
        try { operation(); return false; }
        catch (ArgumentException) { return true; }
        catch (InvalidOperationException) { return true; }
    }

    public static int Main()
    {
        try
        {
            long time = 100;
            var store = new JoinTicketStore("test-session", delegate { return time; }, 1000);
            JoinTicket ticket;
            string reason;
            string token = store.Issue(Issuer(), Hash, 8);
            Check(Files.Unhex(token).Length == 32, "Ticket contains 256 random bits");
            Check(Consume(store, token, Hash, 8, out ticket, out reason) && reason == "TICKET_CONSUMED", "Valid normal join packet consumes ticket");
            Check(ticket.IssuerPid == 123 && ticket.IssuerCreation == 456 && ticket.Player == "player-one" && ticket.Session == "test-session" && ticket.Lease == "lease-one", "Issuer identity and lease retained for live service recheck");
            Check(ticket.HostPid == 234 && ticket.HostCreation == 567 && ticket.Connection == 678 && ticket.Channel == 1, "Consumption binds exact host and native connection");
            Check(!Consume(store, token, Hash, 8, out ticket, out reason) && reason == "TICKET_NOT_FOUND", "Consumed ticket cannot be replayed");
            Check(!Consume(store, null, Hash, 8, out ticket, out reason), "Missing ticket rejected");
            Check(!Consume(store, "short", Hash, 8, out ticket, out reason), "Malformed ticket rejected");
            Check(!Consume(store, new string('0', 64), Hash, 8, out ticket, out reason), "Unissued ticket rejected");

            token = store.Issue(Issuer(), Hash, 8);
            time += 9999;
            Check(Consume(store, token, Hash, 8, out ticket, out reason), "Ticket accepted just before ten-second expiry");
            token = store.Issue(Issuer(), Hash, 8);
            time += 10000;
            Check(!Consume(store, token, Hash, 8, out ticket, out reason) && reason == "TICKET_EXPIRED", "Ticket rejected exactly at ten-second expiry");
            token = store.Issue(Issuer(), Hash, 8);
            time--;
            Check(!Consume(store, token, Hash, 8, out ticket, out reason) && reason == "TICKET_EXPIRED", "Backwards test clock fails closed");

            token = store.Issue(Issuer(), Hash, 8);
            Check(!Consume(store, token, new string('b', 64), 8, out ticket, out reason) && reason == "TICKET_PAYLOAD_MISMATCH", "Changed packet payload rejected");
            Check(!Consume(store, token, Hash, 8, out ticket, out reason), "Payload mismatch burns authorization");
            token = store.Issue(Issuer(), Hash, 8);
            Check(!Consume(store, token, Hash, 9, out ticket, out reason) && reason == "TICKET_MESSAGE_MISMATCH", "Changed message type rejected");
            token = store.Issue(Issuer(), Hash, 9);
            Check(Consume(store, token, Hash, 9, out ticket, out reason), "Verified reconnect accepted");
            token = store.Issue(Issuer(), Hash, 14);
            Check(Consume(store, token, Hash, 14, out ticket, out reason), "Verified hotjoin accepted");
            token = store.Issue(Issuer(), Hash, 8);
            Check(!store.TryConsume(token, Hash, 8, 234, 567, 0, out ticket, out reason) && reason == "TICKET_HOST_IDENTITY_INVALID", "Missing native connection rejected");

            ClientRecord issuer = Issuer();
            token = store.Issue(issuer, Hash, 8);
            issuer.Pid = 999;
            issuer.Player = "changed";
            issuer.Lease = "changed";
            Check(Consume(store, token, Hash, 8, out ticket, out reason) && ticket.IssuerPid == 123 && ticket.Player == "player-one" && ticket.Lease == "lease-one", "Issue snapshots mutable client record");
            issuer = Issuer(); issuer.Eligible = false;
            Check(Throws(delegate { store.Issue(issuer, Hash, 8); }), "Unverified issuer refused");
            issuer = Issuer(); issuer.Session = "other-session";
            Check(Throws(delegate { store.Issue(issuer, Hash, 8); }), "Issuer from another session refused");
            Check(Throws(delegate { store.Issue(Issuer(), "bad-hash", 8); }), "Invalid packet hash refused");
            Check(Throws(delegate { store.Issue(Issuer(), Hash, 7); }), "Non-join message refused");
            token = store.Issue(Issuer(), Hash, 8);
            var otherSession = new JoinTicketStore("other-session", delegate { return time; }, 1000);
            Check(!Consume(otherSession, token, Hash, 8, out ticket, out reason), "Ticket cannot cross service sessions");

            token = store.Issue(Issuer(), Hash, 8);
            int successes = 0;
            using (var gate = new ManualResetEvent(false))
            {
                var tasks = new Task[12];
                for (int i = 0; i < tasks.Length; i++)
                {
                    tasks[i] = Task.Factory.StartNew(delegate
                    {
                        gate.WaitOne();
                        JoinTicket result;
                        string detail;
                        if (Consume(store, token, Hash, 8, out result, out detail)) Interlocked.Increment(ref successes);
                    }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
                }
                gate.Set();
                Task.WaitAll(tasks);
            }
            Check(successes == 1, "Twelve simultaneous consumers authorize exactly one peer");

            var bounded = new JoinTicketStore("test-session", delegate { return time; }, 1000);
            for (int i = 0; i < JoinTicketStore.Capacity; i++) bounded.Issue(Issuer(), Hash, 8);
            Check(Throws(delegate { bounded.Issue(Issuer(), Hash, 8); }), "Pending ticket count capped at 1024");
            time += 10000;
            token = bounded.Issue(Issuer(), Hash, 8);
            Check(Consume(bounded, token, Hash, 8, out ticket, out reason), "Expired entries pruned before new issuance");
            Console.WriteLine(count + " join ticket checks passed.");
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine(e.ToString()); return 1; }
    }
}
