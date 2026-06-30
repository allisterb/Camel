namespace Camel.DFIR.Workflows;
using Camel.DFIR.Toolkits;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

using Camel.Toolkits.Models;
using Camel.DFIR.Toolkits.Models;
using Camel.Workflows.Models;

// FOR500.3 — USB device analysis. Implements the course's registry-correlation methodology: profile each USB
// mass-storage device (vendor/product/serial), then map it to its volume name, drive letter, owning user, and
// first/last connection times across USBSTOR/USB, Windows Portable Devices, MountedDevices/MountPoints2 and the
// setupapi install log. usbdeviceforensics does the heavy correlation; RegRipper's usbstor plugin adds the
// FriendlyName and setupapi.dev.log adds the authoritative first-install time.
public partial class WindowsAnalysisWorkflow
{
    #region Workflow methods
    /// <summary>
    /// Profiles the USB mass-storage devices that were connected to a host by correlating the registry artifacts
    /// the FOR500.3 methodology calls out. <c>usbdeviceforensics</c> reads the SYSTEM/SOFTWARE (+ optional NTUSER)
    /// hives to produce the per-device record — vendor/product/revision, serial, VID/PID, volume name, drive
    /// letter, device GUID, and the install/arrival/removal timestamps from the device-property keys. RegRipper's
    /// <c>usbstor</c> plugin enriches each device with its <em>FriendlyName</em>, and when
    /// <paramref name="setupApiLog"/> (<c>\Windows\inf\setupapi.dev.log</c>) is supplied, each device's serial is
    /// looked up there to confirm/recover the first-connection time. The resulting serials/volume names are the
    /// pivots to correlate with the external-device references surfaced by <see cref="AnalyzeShellItemsAsync"/>.
    /// </summary>
    /// <param name="systemHive">Path to the SYSTEM hive (USBSTOR/USB, MountedDevices).</param>
    /// <param name="softwareHive">Path to the SOFTWARE hive (Windows Portable Devices, EMDMgmt).</param>
    /// <param name="ntuserHive">Optional NTUSER.DAT (MountPoints2 → the user who mounted the device).</param>
    /// <param name="setupApiLog">Optional path to <c>setupapi.dev.log</c> for first-install corroboration.</param>
    public async Task<WorkflowResult<UsbDeviceReport>> AnalyzeUsbDevicesAsync(
        string systemHive, string softwareHive, string? ntuserHive = null, string? setupApiLog = null)
    {
        using var _audit = AuditScope();
        using var op = Begin("Analyzing USB devices from {0}", systemHive);

        var records = (await WindowsAnalysis.UsbDeviceForensicsAsync(systemHive, softwareHive, ntuserHive)).Result;
        if (records is null)
            return WorkflowResult<UsbDeviceReport>.Failure(
                $"usbdeviceforensics could not profile the hives ('{systemHive}', '{softwareHive}'); check they are valid SYSTEM/SOFTWARE hives.");

        // FriendlyName per serial from RegRipper's usbstor plugin (usbdeviceforensics' TSV omits it).
        var usbstor = (await WindowsAnalysis.RegRipperAsync(systemHive, "usbstor")).Result;
        var friendlyBySerial = ParseUsbstorFriendlyNames(usbstor);

        var devices = new List<UsbDevice>();
        foreach (var r in records)
        {
            var sources = new List<string> { "usbdeviceforensics" };
            var friendly = MatchFriendly(friendlyBySerial, r.SerialNumber);
            if (friendly is not null) sources.Add("usbstor");

            // setupapi.dev.log corroboration: the device's serial appears when it was first installed.
            bool inSetupApi = false;
            if (setupApiLog is not null && r.SerialNumber is { Length: > 0 } sn)
            {
                var hits = (await DiskAnalysis.GrepLinesAsync(setupApiLog, [sn], ignoreCase: true, maxMatches: 1)).Result;
                inSetupApi = hits is { Length: > 0 };
                if (inSetupApi) sources.Add("setupapi.dev.log");
            }

            devices.Add(new UsbDevice
            {
                SerialNumber = r.SerialNumber, Vendor = r.Vendor, Product = r.Product, Revision = r.Version,
                FriendlyName = friendly, Vid = r.Vid, Pid = r.Pid,
                VolumeName = r.VolumeName, DriveLetter = r.DriveLetter, DeviceGuid = r.Guid,
                ParentIdPrefix = r.ParentIdPrefix,
                FirstConnected = r.FirstInstallDate, LastConnected = r.LastArrivalDate, LastRemoved = r.LastRemovalDate,
                InSetupApiLog = inSetupApi, Sources = sources.ToArray(),
            });
        }

        var ordered = devices.OrderBy(d => d.FirstConnected ?? DateTime.MaxValue).ToArray();

        op.Complete();
        var report = new UsbDeviceReport { Devices = ordered };
        return WorkflowResult<UsbDeviceReport>.Success(report,
            ordered.Length == 0
                ? "No USB mass-storage devices found in the registry."
                : $"Profiled {ordered.Length} USB device(s): " +
                  string.Join("; ", ordered.Take(5).Select(d =>
                      $"{d.Vendor} {d.Product} (S/N {d.SerialNumber})" +
                      (d.VolumeName is { Length: > 0 } ? $" vol '{d.VolumeName}'" : "") +
                      (d.FirstConnected is { } f ? $", first {f:yyyy-MM-dd}" : ""))) + ".");
    }
    #endregion

    // Parses RegRipper usbstor output into serial -> FriendlyName. The plugin prints a device header, then per
    // S/N a "S/N: <serial> [...]" line followed (a few lines later) by "    FriendlyName : <name>".
    private static Dictionary<string, string> ParseUsbstorFriendlyNames(RegRipperResult? r)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (r is null) return map;
        string? serial = null;
        foreach (var raw in r.Lines)
        {
            var sn = Regex.Match(raw, @"S/N:\s*(\S+)");
            if (sn.Success) { serial = sn.Groups[1].Value; continue; }
            var fn = Regex.Match(raw, @"FriendlyName\s*:\s*(.+)$");
            if (fn.Success && serial is not null) map[serial] = fn.Groups[1].Value.Trim();
        }
        return map;
    }

    // usbdeviceforensics reports the bare serial (e.g. "4C5300..."); usbstor's S/N carries the "&0" instance
    // suffix. Match by prefix so the two line up.
    private static string? MatchFriendly(Dictionary<string, string> bySerial, string? serial)
    {
        if (serial is not { Length: > 0 }) return null;
        if (bySerial.TryGetValue(serial, out var exact)) return exact;
        return bySerial.FirstOrDefault(kv => kv.Key.StartsWith(serial, StringComparison.OrdinalIgnoreCase)
                                          || serial.StartsWith(kv.Key, StringComparison.OrdinalIgnoreCase)).Value;
    }
}
