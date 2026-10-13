using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace HOI4Admission
{
    public sealed class VerificationService
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint pid);
        private readonly Configuration config;
        private readonly AdmissionPolicy policy;
        private readonly JoinTicketStore joinTickets;
        private readonly Dictionary<string, ClientRecord> clients = new Dictionary<string, ClientRecord>();
        private readonly object sync = new object();
        private readonly object logLock = new object();
        public VerificationService(Configuration c) { config = c; policy = new AdmissionPolicy(c); joinTickets = new JoinTicketStore(c.SessionId); }

        private NamedPipeServerStream NewPipe(string name)
        {
            var acl = new PipeSecurity();
            acl.SetAccessRuleProtection(true, false);
            acl.AddAccessRule(new PipeAccessRule(WindowsIdentity.GetCurrent().User, PipeAccessRights.FullControl, AccessControlType.Allow));
            acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
            return new NamedPipeServerStream(name, PipeDirection.InOut, 16, PipeTransmissionMode.Message, PipeOptions.Asynchronous, 8192, 8192, acl);
        }
        private void Log(string message)
        {
            lock (logLock) File.AppendAllText(Path.Combine(config.RuntimeDirectory, "service.log"), DateTime.UtcNow.ToString("o") + " " + message + Environment.NewLine);
        }
        public void Run()
        {
            if (Files.Hash(config.GamePath) != config.GameHash || config.GameHash != "7dc947be34970da1e1c787bcddbe7f62b610ff258aebf8f06aa8b348f3a031d5" || Files.Hash(config.DllPath) != config.DllHash || Files.Hash(config.ManifestPath) != config.ManifestHash)
                throw new InvalidDataException("A session dependency hash differs from its pinned build");
            Log("SERVICE_STARTED session=" + config.SessionId);
            Task.Run(() => AcceptControls());
            while (true)
            {
                NamedPipeServerStream pipe;
                try { pipe = NewPipe(config.PipeName); }
                catch (IOException) { Thread.Sleep(50); continue; }
                try { pipe.WaitForConnection(); }
                catch { pipe.Dispose(); throw; }
                Task.Run(() => HandleClient(pipe));
            }
        }

        private string InspectGame(int pid, long creation, bool verifyModule)
        {
            try
            {
                using (Process p = Process.GetProcessById(pid))
                {
                    if (p.HasExited || Files.Creation(p) != creation) return "PROCESS_IDENTITY_MISMATCH";
                    if (!string.Equals(p.MainModule.FileName, config.GamePath, StringComparison.OrdinalIgnoreCase)) return "GAME_PATH_MISMATCH";
                    if (verifyModule)
                    {
                        bool found = p.Modules.Cast<ProcessModule>().Any(m => string.Equals(m.FileName, config.DllPath, StringComparison.OrdinalIgnoreCase));
                        if (!found) return "DLL_NOT_LOADED";
                    }
                }
                return null;
            }
            catch (Exception) { return "PROCESS_UNAVAILABLE"; }
        }
        private void HandleClient(NamedPipeServerStream pipe)
        {
            ClientRecord record = null;
            using (pipe)
            {
                try
                {
                    uint peer;
                    if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out peer)) throw new IOException("Cannot identify pipe peer");
                    string nonce = Files.RandomHex();
                    Wire.Send(pipe, "CHALLENGE|" + nonce);
                    string[] fields = Wire.Receive(pipe).Split('|');
                    int pid; long creation;
                    string reason = fields.Length == 12 && int.TryParse(fields[2], out pid) && long.TryParse(fields[3], out creation) ? null : "INVALID_FRAME";
                    if (reason != null) { Wire.Send(pipe, "REJECT|" + reason); return; }
                    pid = int.Parse(fields[2]); creation = long.Parse(fields[3]);
                    reason = (uint)pid != peer ? "PEER_PID_MISMATCH" : policy.Authenticate(fields, nonce);
                    if (reason == null) reason = InspectGame(pid, creation, true);
                    // Verify the actual local dependencies as well as the reported manifest.
                    if (reason == null && (Files.Hash(config.DllPath) != config.DllHash || Files.Hash(config.ManifestPath) != config.ManifestHash)) reason = "LOCAL_BUILD_CHANGED";
                    if (reason == null)
                    {
                        lock (sync)
                        {
                            ExpireLeases();
                            if (clients.Values.Any(r => r.Eligible && r.Player == fields[5])) reason = "PLAYER_SEAT_IN_USE";
                            else
                            {
                                record = new ClientRecord { Pid = pid, Creation = creation, Player = fields[5], Session = fields[4], Lease = Guid.NewGuid().ToString("N"), Eligible = true, LastSeenUtc = DateTime.UtcNow, LastSeenTicks = Stopwatch.GetTimestamp(), Detail = "Game, manifest, DLL protocol, identity and permission verified; native lobby guard installed" };
                                clients[Files.Identity(pid, creation)] = record;
                            }
                        }
                    }
                    if (reason != null)
                    {
                        Log("CLIENT_REJECTED pid=" + pid + " reason=" + reason);
                        Wire.Send(pipe, "REJECT|" + reason);
                        return;
                    }
                    Log("CLIENT_VERIFIED pid=" + pid + " player=" + record.Player);
                    Wire.Send(pipe, "ACCEPT|" + record.Lease);
                    while (true)
                    {
                        string heartbeat = Wire.Receive(pipe);
                        lock (sync)
                        {
                            if (heartbeat != "HEARTBEAT|" + record.Lease || !record.Eligible || !config.Players.Any(p => p.Id == record.Player && p.Allowed))
                            { Wire.Send(pipe, "REVOKED"); break; }
                            record.LastSeenUtc = DateTime.UtcNow;
                            record.LastSeenTicks = Stopwatch.GetTimestamp();
                        }
                        Wire.Send(pipe, "ALIVE");
                    }
                }
                catch (Exception e) { Log("CLIENT_DISCONNECTED " + e.GetType().Name); }
                finally
                {
                    if (record != null) lock (sync) { record.Eligible = false; record.Detail = "Verification connection closed"; }
                }
            }
        }
        private void ExpireLeases()
        {
            long now = Stopwatch.GetTimestamp();
            foreach (ClientRecord record in clients.Values)
                if (record.Eligible && unchecked((ulong)(now - record.LastSeenTicks)) > (ulong)Stopwatch.Frequency * 8u) { record.Eligible = false; record.Detail = "Heartbeat expired"; }
        }
        private void AcceptControls()
        {
            while (true)
            {
                NamedPipeServerStream pipe;
                try { pipe = NewPipe(config.PipeName + "-control"); }
                catch (IOException) { Thread.Sleep(50); continue; }
                try { pipe.WaitForConnection(); }
                catch { pipe.Dispose(); throw; }
                Task.Run(() => HandleControl(pipe));
            }
        }
        private void HandleControl(NamedPipeServerStream pipe)
        {
            using (pipe)
            {
                try
                {
                    string command = Wire.Receive(pipe);
                    if (command.StartsWith("JOIN_", StringComparison.Ordinal))
                    {
                        HandleJoinControl(pipe, command);
                        return;
                    }
                    if (command == "STATUS")
                    {
                        lock (sync) { ExpireLeases(); Wire.Send(pipe, Files.Json.Serialize(new ServiceSnapshot { SessionId = config.SessionId, Clients = clients.Values.ToArray() })); }
                    }
                    else
                    {
                        string[] fields = command.Split('|');
                        if (fields.Length != 5 || fields[0] != "ADMIT") { Wire.Send(pipe, "{\"Eligible\":false,\"Reason\":\"INVALID_REQUEST\"}"); return; }
                        int pid = int.Parse(fields[3]); long creation = long.Parse(fields[4]);
                        var decision = new AdmissionDecision { Pid = pid, Creation = creation, Reason = "CLIENT_NOT_VERIFIED" };
                        lock (sync)
                        {
                            ExpireLeases();
                            ClientRecord record;
                            if (fields[1] != config.SessionId) decision.Reason = "SESSION_MISMATCH";
                            else if (!config.Players.Any(p => p.Id == fields[2] && p.Allowed)) decision.Reason = "PLAYER_NOT_PERMITTED";
                            else if (clients.TryGetValue(Files.Identity(pid, creation), out record) && record.Eligible && record.Player == fields[2])
                            {
                                string reason = InspectGame(pid, creation, true);
                                if (reason == null && (Files.Hash(config.DllPath) != config.DllHash || Files.Hash(config.ManifestPath) != config.ManifestHash)) reason = "LOCAL_BUILD_CHANGED";
                                decision.Eligible = reason == null;
                                decision.Reason = reason ?? "VERIFIED";
                            }
                        }
                        Log("ADMISSION pid=" + pid + " eligible=" + decision.Eligible + " reason=" + decision.Reason);
                        Wire.Send(pipe, Files.Json.Serialize(decision));
                    }
                }
                catch (Exception e) { Log("CONTROL_ERROR " + e.GetType().Name); }
            }
        }

        private void HandleJoinControl(NamedPipeServerStream pipe, string command)
        {
            string[] fields = command.Split('|');
            bool issue = fields[0] == "JOIN_ISSUE";
            bool consume = fields[0] == "JOIN_CHECK";
            int pid, type;
            long creation;
            ulong connection = 0;
            string reason = null;
            if ((!issue && !consume) || fields.Length != (issue ? 7 : 9) ||
                !int.TryParse(fields[3], out pid) || !long.TryParse(fields[4], out creation) ||
                !int.TryParse(fields[5], out type) || (consume && !ulong.TryParse(fields[8], out connection)))
            { Wire.Send(pipe, "JOIN_REJECT|INVALID_REQUEST"); return; }
            uint peer;
            if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out peer) || peer != (uint)pid) reason = "PEER_PID_MISMATCH";
            else if (fields[1] != config.Protocol.ToString()) reason = "PROTOCOL_MISMATCH";
            else if (fields[2] != config.SessionId) reason = "SESSION_MISMATCH";
            lock (sync)
            {
                ExpireLeases();
                ClientRecord caller;
                if (reason == null) reason = VerifiedCaller(pid, creation, out caller);
                else caller = null;
                if (reason == null && issue)
                {
                    string token;
                    try { token = joinTickets.Issue(caller, fields[6], type); }
                    catch (ArgumentException) { reason = "INVALID_JOIN_PACKET"; token = null; }
                    catch (InvalidOperationException) { reason = "TICKET_CAPACITY"; token = null; }
                    if (reason == null)
                    {
                        // Never log the bearer ticket.
                        Log("JOIN_TICKET_ISSUED pid=" + pid + " type=" + type);
                        Wire.Send(pipe, "TICKET|" + token);
                        return;
                    }
                }
                else if (reason == null)
                {
                    JoinTicket ticket;
                    if (joinTickets.TryConsume(fields[7], fields[6], type, pid, creation, connection, out ticket, out reason))
                    {
                        ClientRecord issuer;
                        reason = VerifiedCaller(ticket.IssuerPid, ticket.IssuerCreation, out issuer);
                        if (reason == null && (issuer.Lease != ticket.Lease || issuer.Player != ticket.Player || ticket.Session != config.SessionId)) reason = "ISSUER_LEASE_CHANGED";
                        if (reason == null)
                        {
                            Log("LOBBY_JOIN_AUTHORIZED host=" + pid + " client=" + ticket.IssuerPid + " player=" + ticket.Player + " type=" + type + " connection=" + connection);
                            Wire.Send(pipe, "JOIN_ACCEPT");
                            return;
                        }
                    }
                }
            }
            Log("LOBBY_JOIN_REJECTED caller=" + pid + " type=" + type + " reason=" + reason);
            Wire.Send(pipe, "JOIN_REJECT|" + (reason ?? "NOT_VERIFIED"));
        }

        private string VerifiedCaller(int pid, long creation, out ClientRecord record)
        {
            if (!clients.TryGetValue(Files.Identity(pid, creation), out record) || !record.Eligible) return "CLIENT_NOT_VERIFIED";
            string player = record.Player;
            if (!config.Players.Any(p => p.Id == player && p.Allowed)) return "PLAYER_NOT_PERMITTED";
            string reason = InspectGame(pid, creation, true);
            if (reason == null && (Files.Hash(config.DllPath) != config.DllHash || Files.Hash(config.ManifestPath) != config.ManifestHash)) reason = "LOCAL_BUILD_CHANGED";
            return reason;
        }
    }
    public static class ServiceProgram
    {
        public static int Main(string[] args)
        {
            Configuration configuration = null;
            try
            {
                if (args.Length != 1) throw new ArgumentException("Usage: AdmissionService.exe SESSION_CONFIG_JSON");
                configuration = Files.Load(args[0]);
                new VerificationService(configuration).Run();
                return 0;
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.ToString());
                if (configuration != null) File.AppendAllText(Path.Combine(configuration.RuntimeDirectory, "service-bootstrap.log"), e.ToString() + Environment.NewLine);
                return 1;
            }
        }
    }
}
