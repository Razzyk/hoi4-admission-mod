using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using HOI4Admission;

public static class PolicyTests
{
    private static int count;
    private static void Check(bool value, string message) { if (!value) throw new Exception(message); count++; Console.WriteLine("PASS " + message); }
    private static string[] Frame(Configuration c, string nonce)
    {
        string[] fields = { "VERIFY", c.Protocol.ToString(), "123", "456", c.SessionId, "player-one", c.GameVersion, c.GameHash, c.ManifestHash, c.DllHash, nonce, "" };
        using (var hmac = new HMACSHA256(Files.Unhex(c.Players[0].Secret))) fields[11] = Files.Hex(hmac.ComputeHash(Encoding.ASCII.GetBytes(string.Join("|", fields.Take(11)))));
        return fields;
    }
    public static int Main()
    {
        try
        {
            var c = new Configuration { SessionId = "test-session", DllHash = new string('d', 64), ManifestHash = new string('e', 64), Players = new[] { new Player { Id = "player-one", Secret = new string('a', 64) } } };
            var policy = new AdmissionPolicy(c);
            string nonce = new string('b', 64);
            Check(policy.Authenticate(Frame(c, nonce), nonce) == null, "Valid challenge/HMAC and all five verification fields accepted");
            string[] frame = Frame(c, nonce); frame[1] = "1";
            Check(policy.Authenticate(frame, nonce) == "PROTOCOL_MISMATCH", "Wrong DLL protocol rejected");
            frame = Frame(c, nonce); frame[4] = "other-session";
            Check(policy.Authenticate(frame, nonce) == "SESSION_MISMATCH", "Wrong session identity rejected");
            frame = Frame(c, nonce); frame[5] = "unknown-player";
            Check(policy.Authenticate(frame, nonce) == "PLAYER_NOT_PERMITTED", "Unenrolled player rejected");
            c.Players[0].Allowed = false;
            Check(policy.Authenticate(Frame(c, nonce), nonce) == "PLAYER_NOT_PERMITTED", "Disallowed player rejected");
            c.Players[0].Allowed = true;
            frame = Frame(c, nonce); frame[6] = "1.19.4.0";
            Check(policy.Authenticate(frame, nonce) == "GAME_VERSION_MISMATCH", "Wrong game version rejected");
            frame = Frame(c, nonce); frame[7] = new string('0', 64);
            Check(policy.Authenticate(frame, nonce) == "GAME_VERSION_MISMATCH", "Wrong game executable hash rejected");
            frame = Frame(c, nonce); frame[8] = new string('0', 64);
            Check(policy.Authenticate(frame, nonce) == "MOD_MANIFEST_MISMATCH", "Wrong mod manifest rejected");
            frame = Frame(c, nonce); frame[9] = new string('0', 64);
            Check(policy.Authenticate(frame, nonce) == "DLL_BUILD_MISMATCH", "Wrong native DLL build rejected");
            Check(policy.Authenticate(Frame(c, nonce), new string('c', 64)) == "CHALLENGE_MISMATCH", "Old nonce proof cannot authenticate a fresh challenge");
            frame = Frame(c, nonce); frame[11] = new string('0', 64);
            Check(policy.Authenticate(frame, nonce) == "AUTHENTICATION_FAILED", "Invalid player credential proof rejected");
            Check(policy.Authenticate(new[] { "VERIFY", "1" }, nonce) == "INVALID_FRAME", "Incomplete frame rejected");
            frame = Frame(c, nonce); frame[11] = "short";
            Check(policy.Authenticate(frame, nonce) == "AUTHENTICATION_FAILED", "Truncated credential proof rejected");
            var bytes = Files.Unhex(Files.RandomHex());
            Check(bytes.Length == 32, "Player credentials use 256 random bits");
            Console.WriteLine(count + " policy checks passed.");
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine(e.ToString()); return 1; }
    }
}
