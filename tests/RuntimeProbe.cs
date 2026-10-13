using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using HOI4Admission;

public sealed class LaunchedGame { public string Name; public int Pid; public long Creation; public bool Inject; }
public static class RuntimeProbe
{
    public static int Main(string[] args)
    {
        try
        {
            Configuration c = Files.Load(args[0]);
            ServiceSnapshot snapshot = Files.Json.Deserialize<ServiceSnapshot>(Wire.Control(c, "STATUS"));
            Console.WriteLine("Service running; verified clients=" + snapshot.Clients.Count(r => r.Eligible));
            if (args.Length == 1) return 0;
            LaunchedGame[] launched = Files.Json.Deserialize<LaunchedGame[]>(File.ReadAllText(args[1]));
            var results = launched.Select(game =>
            {
                using (Process p = Process.GetProcessById(game.Pid))
                {
                    if (p.HasExited || Files.Creation(p) != game.Creation) throw new Exception("Launched game identity no longer live");
                    bool loaded = p.Modules.Cast<ProcessModule>().Any(m => string.Equals(m.FileName, c.DllPath, StringComparison.OrdinalIgnoreCase));
                    ClientRecord record = snapshot.Clients.FirstOrDefault(r => r.Pid == game.Pid && r.Creation == game.Creation);
                    string player = record != null ? record.Player : c.Players[0].Id;
                    AdmissionDecision decision = Files.Json.Deserialize<AdmissionDecision>(Wire.Control(c, "ADMIT|" + c.SessionId + "|" + player + "|" + game.Pid + "|" + game.Creation));
                    if (loaded != game.Inject || decision.Eligible != game.Inject) throw new Exception(game.Name + " loading/admission differs from expected state");
                    Console.WriteLine("PASS " + game.Name + " pid=" + game.Pid + " dll=" + loaded + " admission=" + decision.Eligible + " reason=" + decision.Reason);
                    return new { game.Name, game.Pid, game.Creation, DllLoaded = loaded, Eligible = decision.Eligible, decision.Reason, WindowTitle = p.MainWindowTitle, Responding = p.Responding, PrivateMemoryBytes = p.PrivateMemorySize64 };
                }
            }).ToArray();
            // A separate client cannot claim to be one of the admitted game PIDs.
            using (var pipe = new NamedPipeClientStream(".", c.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous))
            {
                pipe.Connect(2000); pipe.ReadMode = PipeTransmissionMode.Message;
                string challenge = Wire.Receive(pipe);
                LaunchedGame claimed = launched.First(g => g.Inject);
                Wire.Send(pipe, "VERIFY|" + c.Protocol + "|" + claimed.Pid + "|" + claimed.Creation + "|" + c.SessionId + "|player-one|" + c.GameVersion + "|" + c.GameHash + "|" + c.ManifestHash + "|" + c.DllHash + "|" + challenge.Substring(10) + "|" + new string('0', 64));
                string rejection = Wire.Receive(pipe);
                if (rejection != "REJECT|PEER_PID_MISMATCH") throw new Exception("External process was not rejected by its actual PID");
                Console.WriteLine("PASS named-pipe peer identity rejects another process claiming an injected game's PID");
            }
            // The join-ticket control commands independently validate their
            // actual Windows pipe peer; ADMIT/STATUS are not ticket authority.
            LaunchedGame claimedJoin = launched.First(g => g.Inject);
            string packetHash = new string('a', 64);
            string syntheticTicket = new string('b', 64);
            string claimedFields = c.Protocol + "|" + c.SessionId + "|" + claimedJoin.Pid + "|" + claimedJoin.Creation + "|8|" + packetHash;
            if (Wire.Control(c, "JOIN_ISSUE|" + claimedFields) != "JOIN_REJECT|PEER_PID_MISMATCH")
                throw new Exception("Join ticket issuance accepted a different process claiming an injected game's PID");
            Console.WriteLine("PASS join ticket issuance rejects a spoofed pipe-peer PID");
            if (Wire.Control(c, "JOIN_CHECK|" + claimedFields + "|" + syntheticTicket + "|1") != "JOIN_REJECT|PEER_PID_MISMATCH")
                throw new Exception("Join ticket consumption accepted a different process claiming an injected game's PID");
            Console.WriteLine("PASS join ticket consumption rejects a spoofed pipe-peer PID");
            using (Process self = Process.GetCurrentProcess())
            {
                string ownFields = c.Protocol + "|" + c.SessionId + "|" + self.Id + "|" + Files.Creation(self) + "|8|" + packetHash;
                if (Wire.Control(c, "JOIN_ISSUE|" + ownFields) != "JOIN_REJECT|CLIENT_NOT_VERIFIED")
                    throw new Exception("Unverified caller was not refused join ticket issuance");
            }
            Console.WriteLine("PASS an unverified caller with its correct PID/creation cannot issue a join ticket");
            File.WriteAllText(Path.Combine(c.RuntimeDirectory, "runtime-verification.json"), Files.Json.Serialize(new
            {
                CheckedUtc = DateTime.UtcNow, Games = results, PeerSpoofRejected = true,
                JoinIssuePeerSpoofRejected = true, JoinCheckPeerSpoofRejected = true, UnverifiedTicketIssuerRejected = true
            }));
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine(e.ToString()); return 1; }
    }
}
