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
    public string OriginalFingerprintExpected, OriginalFingerprintActual;
    public bool PointsToOriginal, PointsToConfiguredDll, PointsToExecutableDll, Readable, PageProtectionRestored, OriginalFingerprintMatches;
}

public sealed class InspectedGame
{
    public int Pid;
    public long Creation;
    public bool IdentityStable, GamePathMatches, GameHashMatches, NativeDLLLoaded, DllHashMatches;
    public bool ServiceRecordMatches, ServiceVerified, HostGuardActive, ClientSendGuardActive, HostSendGuardActive, ClientReceiveGuardActive;
    public bool AuthorizationGuardActive, VtablePagesRestored, AllHooksActive, AllGuardsActive;
    public InspectedStabilityGuard StabilityGuard;
    public string Error;
    public InspectedSlot[] Slots = new InspectedSlot[0];
    public InspectedSlot[] AuthorizationSlots = new InspectedSlot[0];
}

internal sealed class AuthorizationTarget
{
    public readonly string Name, Fingerprint;
    public readonly uint VtableRva, Slot, OriginalRva;
    public AuthorizationTarget(string name, uint vtableRva, uint slot, uint originalRva, string fingerprint)
    { Name = name; VtableRva = vtableRva; Slot = slot; OriginalRva = originalRva; Fingerprint = fingerprint; }
}

public sealed class InspectedStabilityGuard
{
    public string CallAddress, RelayAddress, WrapperAddress, Error;
    public bool CallProtectionRestored, RelayExecutableReadOnly, WrapperInConfiguredDll, Active;
}

public static class LobbyInspector
{
    private const string PinnedGameHash = "7dc947be34970da1e1c787bcddbe7f62b610ff258aebf8f06aa8b348f3a031d5";
    // BEGIN AUTHORIZATION TARGETS
    private static readonly AuthorizationTarget[] AuthorizationTargets =
    {
        new AuthorizationTarget("AddConstruction.Destructor", 0x2994770, 0, 0xdb4580, "40534883ec20488d053bcf96"),
        new AuthorizationTarget("AddConstruction.IsValid", 0x2994770, 9, 0x11616f0, "48895c241048896c24185657"),
        new AuthorizationTarget("AddConstruction.History", 0x2994770, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("AddProductionLine.Destructor", 0x2993708, 0, 0xdb45f0, "40534883ec20488d05cbce96"),
        new AuthorizationTarget("AddProductionLine.IsValid", 0x2993708, 9, 0x11622f0, "48895c241048896c24184889"),
        new AuthorizationTarget("AddProductionLine.History", 0x2993708, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("AddMassProductionsLine.Destructor", 0x29937d0, 0, 0x11490f0, "48895c240848897424105748"),
        new AuthorizationTarget("AddMassProductionsLine.IsValid", 0x29937d0, 9, 0x1162260, "48895c240848897424105748"),
        new AuthorizationTarget("AddMassProductionsLine.History", 0x29937d0, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("AddIdea.Destructor", 0x2995328, 0, 0xdb45f0, "40534883ec20488d05cbce96"),
        new AuthorizationTarget("AddIdea.IsValid", 0x2995328, 9, 0x1161ac0, "40574883ec20803d5c0a2f02"),
        new AuthorizationTarget("AddIdea.History", 0x2995328, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("RemoveIdea.Destructor", 0x2995648, 0, 0xdb45f0, "40534883ec20488d05cbce96"),
        new AuthorizationTarget("RemoveIdea.IsValid", 0x2995648, 9, 0x1165950, "40574883ec20803dcccb2e02"),
        new AuthorizationTarget("RemoveIdea.History", 0x2995648, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("ReplaceIdea.Destructor", 0x29958a0, 0, 0xdb4520, "40534883ec20488d059bcf96"),
        new AuthorizationTarget("ReplaceIdea.IsValid", 0x29958a0, 9, 0x1165bf0, "48895c241048897424205748"),
        new AuthorizationTarget("ReplaceIdea.History", 0x29958a0, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("SetResearch.Destructor", 0x2994f40, 0, 0xdb45f0, "40534883ec20488d05cbce96"),
        new AuthorizationTarget("SetResearch.IsValid", 0x2994f40, 9, 0x1166bc0, "48895c241048897424205748"),
        new AuthorizationTarget("SetResearch.History", 0x2994f40, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("UnlockResearch.Destructor", 0x2995008, 0, 0xdb45f0, "40534883ec20488d05cbce96"),
        new AuthorizationTarget("UnlockResearch.IsValid", 0x2995008, 9, 0x1167fd0, "48895c241048897424205748"),
        new AuthorizationTarget("UnlockResearch.History", 0x2995008, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("SetNationalFocus.Destructor", 0x2996458, 0, 0xdb4550, "40534883ec20488d056bcf96"),
        new AuthorizationTarget("SetNationalFocus.IsValid", 0x2996458, 9, 0x1166830, "48895c240848897424105748"),
        new AuthorizationTarget("SetNationalFocus.History", 0x2996458, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("SelectDecision.Destructor", 0x2996908, 0, 0xdb4550, "40534883ec20488d056bcf96"),
        new AuthorizationTarget("SelectDecision.IsValid", 0x2996908, 9, 0x1165f10, "48895c2408574881ecf00000"),
        new AuthorizationTarget("SelectDecision.History", 0x2996908, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("SelectTargetedDecision.Destructor", 0x29969d0, 0, 0xdb45f0, "40534883ec20488d05cbce96"),
        new AuthorizationTarget("SelectTargetedDecision.IsValid", 0x29969d0, 9, 0x1166030, "48895c241048896c24184889"),
        new AuthorizationTarget("SelectTargetedDecision.History", 0x29969d0, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("CreateEquipmentVariant.Destructor", 0x2a240c0, 0, 0x19a1de0, "48895c240848896c24104889"),
        new AuthorizationTarget("CreateEquipmentVariant.IsValid", 0x2a240c0, 9, 0x19a5af0, "48895c241048897424185748"),
        new AuthorizationTarget("CreateEquipmentVariant.History", 0x2a240c0, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("UpdateEquipmentVariant.Destructor", 0x2a24188, 0, 0x19a2150, "48895c240848896c24104889"),
        new AuthorizationTarget("UpdateEquipmentVariant.IsValid", 0x2a24188, 9, 0x19a5e20, "48895c241055565741544155"),
        new AuthorizationTarget("UpdateEquipmentVariant.History", 0x2a24188, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("SetCountryController.Destructor", 0x295e368, 0, 0x22d200, "40534883ec20488d05bb424f"),
        new AuthorizationTarget("SetCountryController.IsValid", 0x295e368, 9, 0xcee530, "48895c241048896c24185657"),
        new AuthorizationTarget("SetCountryController.History", 0x295e368, 12, 0x1807b0, "b001c3cccccccccccccccccc"),
        new AuthorizationTarget("SetCountryController.Execute", 0x295e368, 10, 0xcece50, "48895c241848894c2408555657415441"),
        new AuthorizationTarget("ChangeCountryController.Destructor", 0x2996390, 0, 0xdb4550, "40534883ec20488d056bcf96"),
        new AuthorizationTarget("ChangeCountryController.IsValid", 0x2996390, 9, 0x1162b60, "40574883ec30803de5ef4702"),
        new AuthorizationTarget("ChangeCountryController.History", 0x2996390, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("ChangeCountryController.Execute", 0x2996390, 10, 0x1153210, "48894c24085553565741544155415641"),
        new AuthorizationTarget("AskToCoop.Destructor", 0x295e430, 0, 0x22d200, "40534883ec20488d05bb424f"),
        new AuthorizationTarget("AskToCoop.IsValid", 0x295e430, 9, 0xcee2c0, "40534883ec30803d85388f02"),
        new AuthorizationTarget("AskToCoop.History", 0x295e430, 12, 0x1807b0, "b001c3cccccccccccccccccc"),
        new AuthorizationTarget("AskToCoop.Execute", 0x295e430, 10, 0xcec380, "48895c24085556574154415541564157"),
        new AuthorizationTarget("SetMPDebugSettings.Destructor", 0x29e68a0, 0, 0x22d200, "40534883ec20488d05bb424f"),
        new AuthorizationTarget("SetMPDebugSettings.IsValid", 0x29e68a0, 9, 0x1807b0, "b001c3cccccccccccccccccc"),
        new AuthorizationTarget("SetMPDebugSettings.History", 0x29e68a0, 12, 0x1807b0, "b001c3cccccccccccccccccc"),
        new AuthorizationTarget("SetCustomDifficultyMultiplier.Destructor", 0x29e6328, 0, 0x163c1c0, "48895c2408574883ec20488d"),
        new AuthorizationTarget("SetCustomDifficultyMultiplier.IsValid", 0x29e6328, 9, 0x163ddb0, "4c8bdc49895b105556574883"),
        new AuthorizationTarget("SetCustomDifficultyMultiplier.History", 0x29e6328, 12, 0x1807b0, "b001c3cccccccccccccccccc"),
        new AuthorizationTarget("SetDifficulty.Destructor", 0x29e6260, 0, 0x22d200, "40534883ec20488d05bb424f"),
        new AuthorizationTarget("SetDifficulty.IsValid", 0x29e6260, 9, 0x1807b0, "b001c3cccccccccccccccccc"),
        new AuthorizationTarget("SetDifficulty.History", 0x29e6260, 12, 0x1807b0, "b001c3cccccccccccccccccc"),
        new AuthorizationTarget("SetGameRuleOption.Destructor", 0x29e63f0, 0, 0x22d200, "40534883ec20488d05bb424f"),
        new AuthorizationTarget("SetGameRuleOption.IsValid", 0x29e63f0, 9, 0x163e050, "40534883ec30837928ff488b"),
        new AuthorizationTarget("SetGameRuleOption.History", 0x29e63f0, 12, 0x1807b0, "b001c3cccccccccccccccccc"),
        new AuthorizationTarget("ResetCustomDifficultyMultipliers.Destructor", 0x2a99a98, 0, 0x1c94a0, "40534883ec20488d051b8055"),
        new AuthorizationTarget("ResetCustomDifficultyMultipliers.IsValid", 0x2a99a98, 9, 0x1807b0, "b001c3cccccccccccccccccc"),
        new AuthorizationTarget("ResetCustomDifficultyMultipliers.History", 0x2a99a98, 12, 0x1807b0, "b001c3cccccccccccccccccc"),
        new AuthorizationTarget("ResetGameRules.Destructor", 0x2a99b60, 0, 0x1c94a0, "40534883ec20488d051b8055"),
        new AuthorizationTarget("ResetGameRules.IsValid", 0x2a99b60, 9, 0x1807b0, "b001c3cccccccccccccccccc"),
        new AuthorizationTarget("ResetGameRules.History", 0x2a99b60, 12, 0x1807b0, "b001c3cccccccccccccccccc"),
        new AuthorizationTarget("SetGamePlayOptions.Destructor", 0x29e6710, 0, 0xdb45f0, "40534883ec20488d05cbce96"),
        new AuthorizationTarget("SetGamePlayOptions.IsValid", 0x29e6710, 9, 0x1807b0, "b001c3cccccccccccccccccc"),
        new AuthorizationTarget("SetGamePlayOptions.History", 0x29e6710, 12, 0x1807b0, "b001c3cccccccccccccccccc"),
        new AuthorizationTarget("UnlockIndustrialOrganisationTrait.Destructor", 0x2967cd8, 0, 0xdb4520, "40534883ec20488d059bcf96"),
        new AuthorizationTarget("UnlockIndustrialOrganisationTrait.IsValid", 0x2967cd8, 9, 0x199d910, "488bc4488958104889701848"),
        new AuthorizationTarget("UnlockIndustrialOrganisationTrait.History", 0x2967cd8, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("AddIndustrialOrgTraitToQueue.Destructor", 0x2967e68, 0, 0xdb4520, "40534883ec20488d059bcf96"),
        new AuthorizationTarget("AddIndustrialOrgTraitToQueue.IsValid", 0x2967e68, 9, 0x199d220, "48895c2408574883ec20488b"),
        new AuthorizationTarget("AddIndustrialOrgTraitToQueue.History", 0x2967e68, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("RemoveIndustrialOrgTraitFromQueue.Destructor", 0x2967f30, 0, 0xdb4520, "40534883ec20488d059bcf96"),
        new AuthorizationTarget("RemoveIndustrialOrgTraitFromQueue.IsValid", 0x2967f30, 9, 0x199d3a0, "40534883ec20488bd94883c140"),
        new AuthorizationTarget("RemoveIndustrialOrgTraitFromQueue.History", 0x2967f30, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("MoveIndustrialOrgTraitInQueue.Destructor", 0x2967ff8, 0, 0xdb4580, "40534883ec20488d053bcf96"),
        new AuthorizationTarget("MoveIndustrialOrgTraitInQueue.IsValid", 0x2967ff8, 9, 0x199d2f0, "48895c24084889742410574883"),
        new AuthorizationTarget("MoveIndustrialOrgTraitInQueue.History", 0x2967ff8, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("SetIndustrialOrgTraitsInQueue.Destructor", 0x29680c0, 0, 0xdb4620, "48895c24084889742410574883"),
        new AuthorizationTarget("SetIndustrialOrgTraitsInQueue.IsValid", 0x29680c0, 9, 0x199d820, "4889742410574883ec20488bf9"),
        new AuthorizationTarget("SetIndustrialOrgTraitsInQueue.History", 0x29680c0, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("CountryPriority1.Destructor", 0x272dac0, 0, 0x22d200, "40534883ec20488d05bb424f"),
        new AuthorizationTarget("CountryPriority1.IsValid", 0x272dac0, 9, 0x1166710, "837928007e0983792c027703"),
        new AuthorizationTarget("CountryPriority1.History", 0x272dac0, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("CountryPriority2.Destructor", 0x272db88, 0, 0x22d200, "40534883ec20488d05bb424f"),
        new AuthorizationTarget("CountryPriority2.IsValid", 0x272db88, 9, 0x1166710, "837928007e0983792c027703"),
        new AuthorizationTarget("CountryPriority2.History", 0x272db88, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("CountryPriority3.Destructor", 0x272dc50, 0, 0x22d200, "40534883ec20488d05bb424f"),
        new AuthorizationTarget("CountryPriority3.IsValid", 0x272dc50, 9, 0x1166710, "837928007e0983792c027703"),
        new AuthorizationTarget("CountryPriority3.History", 0x272dc50, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("CountryPriority4.Destructor", 0x272dd18, 0, 0x22d200, "40534883ec20488d05bb424f"),
        new AuthorizationTarget("CountryPriority4.IsValid", 0x272dd18, 9, 0x1166710, "837928007e0983792c027703"),
        new AuthorizationTarget("CountryPriority4.History", 0x272dd18, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("CountryPriority5.Destructor", 0x272dde0, 0, 0x22d200, "40534883ec20488d05bb424f"),
        new AuthorizationTarget("CountryPriority5.IsValid", 0x272dde0, 9, 0x1166710, "837928007e0983792c027703"),
        new AuthorizationTarget("CountryPriority5.History", 0x272dde0, 12, 0x11d220, "32c0c3cccccccccccccccccc"),
        new AuthorizationTarget("AddProductionLineFactories.Destructor", 0x2994db0, 0, 0xdb4550, "40534883ec20488d056bcf9601488bd9"),
        new AuthorizationTarget("AddProductionLineFactories.IsValid", 0x2994db0, 9, 0x1162420, "48895c2408574883ec20488bf94883c1"),
        new AuthorizationTarget("AddProductionLineFactories.History", 0x2994db0, 12, 0x11d220, "32c0c3cccccccccccccccccccccccccc"),
        new AuthorizationTarget("AddMassFactoryAssignment.Destructor", 0x2993a28, 0, 0x1149060, "48895c24084889742410574883ec2048"),
        new AuthorizationTarget("AddMassFactoryAssignment.IsValid", 0x2993a28, 9, 0x1161be0, "48895c241048896c2418488974242057"),
        new AuthorizationTarget("AddMassFactoryAssignment.History", 0x2993a28, 12, 0x11d220, "32c0c3cccccccccccccccccccccccccc"),
        new AuthorizationTarget("SelectEventOption.Destructor", 0x2938e60, 0, 0xa0d450, "48895c2408574883ec20488bf98bda48"),
        new AuthorizationTarget("SelectEventOption.IsValid", 0x2938e60, 9, 0x153afb0, "48895c241048896c2418488974242057"),
        new AuthorizationTarget("SelectEventOption.History", 0x2938e60, 12, 0x11d220, "32c0c3cccccccccccccccccccccccccc"),
        new AuthorizationTarget("WorldLoadTask.Execute", 0x2723ca0, 1, 0x1f71b0, "4883ec28488b4908e8a318fdff33c048"),
        new AuthorizationTarget("ChangeTagEffect.TargetGetter", 0x276f848, 25, 0x1399890, "40534883ec2080796000488bda750f48"),
    };
    // END AUTHORIZATION TARGETS

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
                    (access == 0x10 || access == 0x20);
            }
        }
        return result;
    }

    private static InspectedSlot ReadAuthorizationSlot(IntPtr process, ulong gameBase, int gameSize,
        ulong dllBase, int dllSize, AuthorizationTarget target)
    {
        var slot = ReadSlot(process, gameBase, gameSize, dllBase, dllSize, target.Name,
            checked(target.VtableRva + target.Slot * 8), target.OriginalRva);
        slot.OriginalFingerprintExpected = target.Fingerprint;
        int length = target.Fingerprint.Length / 2;
        if ((ulong)target.OriginalRva + (ulong)length > (ulong)gameSize)
        { slot.Error = "FINGERPRINT_OUTSIDE_MAIN_IMAGE"; return slot; }
        byte[] actual = ReadExact(process, gameBase + target.OriginalRva, (uint)length);
        slot.OriginalFingerprintActual = BitConverter.ToString(actual).Replace("-", "").ToLowerInvariant();
        slot.OriginalFingerprintMatches = slot.OriginalFingerprintActual == target.Fingerprint;
        if (!slot.OriginalFingerprintMatches) slot.Error = "ORIGINAL_CODE_FINGERPRINT_DIFFERS";
        return slot;
    }

    private static byte[] ReadExact(IntPtr process, ulong address, uint length)
    {
        byte[] bytes = new byte[length]; UIntPtr copied;
        if (!ReadProcessMemory(process, new IntPtr(checked((long)address)), bytes, new UIntPtr(length), out copied) || copied.ToUInt64() != length)
            throw new IOException("Native stability instruction read failed");
        return bytes;
    }
    private static MemoryRegion Region(IntPtr process, ulong address)
    {
        MemoryRegion region;
        if (VirtualQueryEx(process, new IntPtr(checked((long)address)), out region, new UIntPtr((uint)Marshal.SizeOf(typeof(MemoryRegion)))).ToUInt64() == 0)
            throw new IOException("Native stability page query failed");
        return region;
    }
    private static InspectedStabilityGuard ReadStabilityGuard(IntPtr process, ulong gameBase, int gameSize, ulong dllBase, int dllSize)
    {
        var result = new InspectedStabilityGuard();
        try
        {
            const uint callRva = 0x1d6001;
            if ((ulong)callRva + 5 > (ulong)gameSize) throw new IOException("Stability CALL outside main image");
            ulong call = checked(gameBase + callRva); result.CallAddress = Hex(call);
            MemoryRegion code = Region(process, call);
            result.CallProtectionRestored = code.State == MemCommit && code.Type == 0x1000000 && code.Protect == 0x20 && unchecked((ulong)code.AllocationBase.ToInt64()) == gameBase;
            if (!result.CallProtectionRestored) throw new IOException("Stability CALL page protection differs");
            byte[] instruction = ReadExact(process, call, 5);
            if (instruction[0] != 0xe8) throw new IOException("Stability CALL opcode differs");
            long target = checked((long)call + 5 + BitConverter.ToInt32(instruction, 1));
            if (target <= 0) throw new IOException("Stability relay address invalid");
            ulong relay = (ulong)target; result.RelayAddress = Hex(relay);
            MemoryRegion relayRegion = Region(process, relay);
            result.RelayExecutableReadOnly = relayRegion.State == MemCommit && relayRegion.Type == 0x20000 && relayRegion.Protect == 0x20 &&
                unchecked((ulong)relayRegion.AllocationBase.ToInt64()) == relay && unchecked((ulong)relayRegion.BaseAddress.ToInt64()) == relay && relayRegion.RegionSize.ToUInt64() >= 14;
            if (!result.RelayExecutableReadOnly) throw new IOException("Stability CALL does not point to an RX relay");
            byte[] jump = ReadExact(process, relay, 14);
            if (jump[0] != 0xff || jump[1] != 0x25 || jump.Skip(2).Take(4).Any(value => value != 0)) throw new IOException("Stability relay instruction differs");
            ulong wrapper = BitConverter.ToUInt64(jump, 6); result.WrapperAddress = Hex(wrapper);
            if (dllSize <= 0 || wrapper < dllBase || wrapper - dllBase >= (ulong)dllSize) throw new IOException("Stability wrapper outside configured DLL");
            MemoryRegion body = Region(process, wrapper);
            result.WrapperInConfiguredDll = body.State == MemCommit && body.Type == 0x1000000 && (body.Protect == 0x20 || body.Protect == 0x10) &&
                unchecked((ulong)body.AllocationBase.ToInt64()) == dllBase;
            result.Active = result.CallProtectionRestored && result.RelayExecutableReadOnly && result.WrapperInConfiguredDll;
        }
        catch (Exception error) { result.Error = error.Message; }
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
                    ReadSlot(handle, gameBase, game.ModuleMemorySize, dllBase, dllSize, "HostSendGuard", 0x2b53040, 0x2363e10),
                    ReadSlot(handle, gameBase, game.ModuleMemorySize, dllBase, dllSize, "ClientReceiveGuard", 0x2b53670, 0x236afe0)
                };
                bool trustedDll = result.NativeDLLLoaded && result.DllHashMatches;
                result.AuthorizationSlots = AuthorizationTargets.Select(target =>
                    ReadAuthorizationSlot(handle, gameBase, game.ModuleMemorySize, dllBase, dllSize, target)).ToArray();
                result.AuthorizationGuardActive = trustedDll && AuthorizationTargets.Length == 113 &&
                    result.AuthorizationSlots.Length == AuthorizationTargets.Length &&
                    result.AuthorizationSlots.All(slot => slot.Readable && slot.PointsToExecutableDll &&
                        slot.PageProtectionRestored && slot.OriginalFingerprintMatches && slot.Error == null);
                result.HostGuardActive = trustedDll && result.Slots[0].PointsToExecutableDll;
                result.ClientSendGuardActive = trustedDll && result.Slots[1].PointsToExecutableDll;
                result.HostSendGuardActive = trustedDll && result.Slots[2].PointsToExecutableDll;
                result.ClientReceiveGuardActive = trustedDll && result.Slots[3].PointsToExecutableDll;
                result.VtablePagesRestored = result.Slots.Concat(result.AuthorizationSlots).All(slot => slot.Readable && slot.PageProtectionRestored);
                result.StabilityGuard = ReadStabilityGuard(handle, gameBase, game.ModuleMemorySize, dllBase, dllSize);
                result.IdentityStable = !process.HasExited && Creation(handle) == result.Creation && Files.Creation(process) == result.Creation;
                ClientRecord record = snapshot == null || snapshot.Clients == null ? null : snapshot.Clients.FirstOrDefault(client =>
                    client.Pid == result.Pid && client.Creation == result.Creation && client.Session == config.SessionId);
                result.ServiceRecordMatches = snapshot != null && snapshot.Running && snapshot.SessionId == config.SessionId && record != null;
                result.ServiceVerified = result.ServiceRecordMatches && record.Eligible;
                result.AllHooksActive = result.IdentityStable && result.HostGuardActive && result.ClientSendGuardActive && result.HostSendGuardActive && result.ClientReceiveGuardActive && result.VtablePagesRestored;
                result.AllGuardsActive = result.AllHooksActive && trustedDll && result.StabilityGuard.Active && result.AuthorizationGuardActive;
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
            bool pass = games.Length > 0 && games.All(game => game.AllGuardsActive && game.ServiceVerified && game.Error == null);
            Console.WriteLine(Files.Json.Serialize(new
            {
                CheckedUtc = DateTime.UtcNow.ToString("o"), ReadOnly = true,
                Scope = "Read-only lobby, authorization and stability hook/module/lease inspection; does not prove multiplayer enforcement or campaign stability",
                ServiceReachable = snapshot != null, ServiceError = serviceError, Games = games,
                AllSelectedGamesHaveVerifiedHooks = pass
            }));
            return require && !pass ? 1 : games.Any(game => game.Error != null) ? 2 : 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error.Message); return 2; }
    }
}
