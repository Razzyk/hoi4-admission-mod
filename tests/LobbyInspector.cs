using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using HOI4Admission;

public sealed class InspectedSlot
{
    public string Name, SlotRva, SlotAddress, CurrentPointer, OriginalPointer, Protection, Error;
    public bool PointsToOriginal, PointsToConfiguredDll, PointsToExecutableDll, Readable, PageProtectionRestored;
}

public sealed class InspectedGame
{
    public int Pid;
    public long Creation;
    public bool IdentityStable, GamePathMatches, GameHashMatches, NativeDLLLoaded, DllHashMatches;
    public bool ServiceRecordMatches, ServiceVerified, HostGuardActive, ClientSendGuardActive, HostSendGuardActive;
    public bool VtablePagesRestored, AllHooksActive;
    public string Error;
    public InspectedSlot[] Slots = new InspectedSlot[0];
}

public static class LobbyInspector
{
    private const string PinnedGameHash = "7dc947be34970da1e1c787bcddbe7f62b610ff258aebf8f06aa8b348f3a031d5";
    private const uint ProcessRead = 0x0010 | 0x0400, PageReadOnly = 0x02, PageGuard = 0x100, MemCommit = 0x1000;

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryRegion
    {
        public IntPtr BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public UIntPtr RegionSize;
        public uint State, Protect, Type;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime { public uint Low, High; }
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(IntPtr process, IntPtr address, byte[] bytes, UIntPtr size, out UIntPtr copied);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UIntPtr VirtualQueryEx(IntPtr process, IntPtr address, out MemoryRegion region, UIntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr process, out FileTime created, out FileTime exited, out FileTime kernel, out FileTime user);

    private static long Creation(IntPtr process)
    {
        FileTime created, exited, kernel, user;
        if (!GetProcessTimes(process, out created, out exited, out kernel, out user)) throw new IOException("Process identity unavailable");
        return unchecked((long)(((ulong)created.High << 32) | created.Low));
    }
    private static string Hex(ulong value) { return "0x" + value.ToString("x"); }
    private static bool SamePath(string left, string right)
    {
        return string.Equals(Path.GetFullPath(left), Path.GetFullPath(right), StringComparison.OrdinalIgnoreCase);
    }
    private static bool IsReadable(uint protection)
    {
        uint access = protection & 0xff;
        return (protection & PageGuard) == 0 && (access == 2 || access == 4 || access == 8 || access == 0x20 || access == 0x40 || access == 0x80);
    }
    private static InspectedSlot ReadSlot(IntPtr process, ulong gameBase, int gameSize, ulong dllBase, int dllSize,
        string name, uint slotRva, uint originalRva)
    {
        var result = new InspectedSlot { Name = name, SlotRva = Hex(slotRva), SlotAddress = Hex(gameBase + slotRva), OriginalPointer = Hex(gameBase + originalRva) };
        if ((ulong)slotRva + 8 > (ulong)gameSize || originalRva >= gameSize || slotRva % 8 != 0)
        { result.Error = "RVA_OUTSIDE_MAIN_IMAGE"; return result; }
        IntPtr address = new IntPtr(unchecked((long)(gameBase + slotRva)));
        MemoryRegion region;
        if (VirtualQueryEx(process, address, out region, new UIntPtr((uint)Marshal.SizeOf(typeof(MemoryRegion)))).ToUInt64() == 0)
        { result.Error = "PAGE_QUERY_FAILED"; return result; }
        result.Protection = Hex(region.Protect);
        result.PageProtectionRestored = region.Protect == PageReadOnly;
        ulong regionStart = unchecked((ulong)region.BaseAddress.ToInt64());
        ulong regionSize = region.RegionSize.ToUInt64();
        if (region.State != MemCommit || region.Type != 0x1000000 || unchecked((ulong)region.AllocationBase.ToInt64()) != gameBase ||
            !IsReadable(region.Protect) || gameBase + slotRva < regionStart ||
            gameBase + slotRva - regionStart > regionSize || 8 > regionSize - (gameBase + slotRva - regionStart))
        { result.Error = "PAGE_NOT_READABLE"; return result; }
        var bytes = new byte[8];
        UIntPtr copied;
        if (!ReadProcessMemory(process, address, bytes, new UIntPtr(8), out copied) || copied.ToUInt64() != 8)
        { result.Error = "POINTER_READ_FAILED"; return result; }
        ulong pointer = BitConverter.ToUInt64(bytes, 0);
        result.Readable = true;
        result.CurrentPointer = Hex(pointer);
        result.PointsToOriginal = pointer == gameBase + originalRva;
        result.PointsToConfiguredDll = dllSize > 0 && pointer >= dllBase && pointer - dllBase < (ulong)dllSize;
        if (result.PointsToConfiguredDll)
        {
            MemoryRegion callback;
            if (VirtualQueryEx(process, new IntPtr(unchecked((long)pointer)), out callback,
                new UIntPtr((uint)Marshal.SizeOf(typeof(MemoryRegion)))).ToUInt64() != 0)
            {
                uint access = callback.Protect & 0xff;
                result.PointsToExecutableDll = callback.State == MemCommit && callback.Type == 0x1000000 &&
                    unchecked((ulong)callback.AllocationBase.ToInt64()) == dllBase && (callback.Protect & PageGuard) == 0 &&
                    (access == 0x10 || access == 0x20 || access == 0x40 || access == 0x80);
            }
        }
        return result;
    }

    private static InspectedGame Inspect(Configuration config, ServiceSnapshot snapshot, int pid)
    {
        var result = new InspectedGame { Pid = pid };
        IntPtr handle = IntPtr.Zero;
        try
        {
            using (Process process = Process.GetProcessById(pid))
            {
                handle = OpenProcess(ProcessRead, false, pid);
                if (handle == IntPtr.Zero) throw new IOException("Process access denied");
                result.Creation = Creation(handle);
                ProcessModule game = process.MainModule;
                result.GamePathMatches = SamePath(game.FileName, config.GamePath);
                result.GameHashMatches = result.GamePathMatches && string.Equals(Files.Hash(game.FileName), PinnedGameHash, StringComparison.OrdinalIgnoreCase);
                // No native address assumptions are applied to an unsupported EXE.
                if (!result.GameHashMatches) { result.Error = "UNSUPPORTED_GAME_IDENTITY"; return result; }
                ProcessModule dll = process.Modules.Cast<ProcessModule>().FirstOrDefault(module => SamePath(module.FileName, config.DllPath));
                result.NativeDLLLoaded = dll != null;
                result.DllHashMatches = dll != null && string.Equals(Files.Hash(dll.FileName), config.DllHash, StringComparison.OrdinalIgnoreCase);
                ulong gameBase = unchecked((ulong)game.BaseAddress.ToInt64());
                ulong dllBase = dll == null ? 0 : unchecked((ulong)dll.BaseAddress.ToInt64());
                int dllSize = dll == null ? 0 : dll.ModuleMemorySize;
                result.Slots = new[]
                {
                    ReadSlot(handle, gameBase, game.ModuleMemorySize, dllBase, dllSize, "HostReceiveGuard", 0x2b530f8, 0x23663f0),
                    ReadSlot(handle, gameBase, game.ModuleMemorySize, dllBase, dllSize, "ClientSendGuard", 0x2b535b8, 0x2363e10),
                    ReadSlot(handle, gameBase, game.ModuleMemorySize, dllBase, dllSize, "HostSendGuard", 0x2b53040, 0x2363e10)
                };
                bool trustedDll = result.NativeDLLLoaded && result.DllHashMatches;
                result.HostGuardActive = trustedDll && result.Slots[0].PointsToExecutableDll;
                result.ClientSendGuardActive = trustedDll && result.Slots[1].PointsToExecutableDll;
                result.HostSendGuardActive = trustedDll && result.Slots[2].PointsToExecutableDll;
                result.VtablePagesRestored = result.Slots.All(slot => slot.Readable && slot.PageProtectionRestored);
                result.IdentityStable = !process.HasExited && Creation(handle) == result.Creation && Files.Creation(process) == result.Creation;
                ClientRecord record = snapshot == null || snapshot.Clients == null ? null : snapshot.Clients.FirstOrDefault(client =>
                    client.Pid == result.Pid && client.Creation == result.Creation && client.Session == config.SessionId);
                result.ServiceRecordMatches = snapshot != null && snapshot.Running && snapshot.SessionId == config.SessionId && record != null;
                result.ServiceVerified = result.ServiceRecordMatches && record.Eligible;
                result.AllHooksActive = result.IdentityStable && result.HostGuardActive && result.ClientSendGuardActive && result.HostSendGuardActive && result.VtablePagesRestored;
            }
        }
        catch (Exception error) { result.Error = error.GetType().Name; }
        finally { if (handle != IntPtr.Zero) CloseHandle(handle); }
        return result;
    }

    public static int Main(string[] args)
    {
        try
        {
            if (IntPtr.Size != 8 || args.Length < 1) throw new ArgumentException("Usage: LobbyInspector.exe session.json [pid] [--require-hooks]");
            bool require = args.Contains("--require-hooks");
            string[] positional = args.Where(arg => arg != "--require-hooks").ToArray();
            if (positional.Length < 1 || positional.Length > 2) throw new ArgumentException("Usage: LobbyInspector.exe session.json [pid] [--require-hooks]");
            Configuration config = Files.Json.Deserialize<Configuration>(File.ReadAllText(positional[0]));
            // Legacy protocol1 is accepted for diagnosing a loaded old DLL.
            if (config == null || (config.Protocol != 1 && config.Protocol != 2) || string.IsNullOrEmpty(config.GamePath) ||
                string.IsNullOrEmpty(config.DllPath) || string.IsNullOrEmpty(config.DllHash) ||
                !Path.IsPathRooted(config.GamePath) || !Path.IsPathRooted(config.DllPath) ||
                !string.Equals(config.GameHash, PinnedGameHash, StringComparison.OrdinalIgnoreCase))
                throw new FormatException("Unsupported session/game configuration");
            ServiceSnapshot snapshot = null;
            string serviceError = null;
            try { snapshot = Files.Json.Deserialize<ServiceSnapshot>(Wire.Control(config, "STATUS")); }
            catch (Exception error) { serviceError = error.GetType().Name; }
            int[] pids = positional.Length == 2 ? new[] { int.Parse(positional[1]) } :
                Process.GetProcessesByName("hoi4").Select(process => { using (process) return process.Id; }).OrderBy(pid => pid).ToArray();
            InspectedGame[] games = pids.Select(pid => Inspect(config, snapshot, pid)).ToArray();
            bool pass = games.Length > 0 && games.All(game => game.AllHooksActive && game.ServiceVerified && game.Error == null);
            Console.WriteLine(Files.Json.Serialize(new
            {
                CheckedUtc = DateTime.UtcNow.ToString("o"), ReadOnly = true,
                Scope = "Live pointer/module/lease inspection; does not prove a join was accepted or rejected",
                ServiceReachable = snapshot != null, ServiceError = serviceError, Games = games,
                AllSelectedGamesHaveVerifiedHooks = pass
            }));
            return require && !pass ? 1 : games.Any(game => game.Error != null) ? 2 : 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error.Message); return 2; }
    }
}
