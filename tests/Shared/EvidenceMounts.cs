namespace Camel.Tests;

using Camel.Environments;

/// <summary>
/// Best-effort setup of the read-only NTFS evidence mounts the disk-backed integration tests depend on
/// (<c>/mnt/ewf</c>, <c>/mnt/dlpc</c>, <c>/mnt/windows_mount2</c>), layered on the E01 images in
/// <c>/mnt/artifacts</c>. A reset SIFT workstation keeps the raw images but loses these mounts, so the
/// disk-backed suites would otherwise fail with "file not found"; <see cref="EnsureAll"/> re-establishes
/// them. Shared (linked) into each disk-backed test project because the test base <c>TestsRuntime</c> lives
/// in Camel.Runtime, which cannot reference Camel.Environments. Paths/offsets are hardcoded to the project
/// SIFT workstation for now.
/// </summary>
public static class EvidenceMounts
{
    const string Artifacts = "/mnt/artifacts";   // raw E01 images (auto-mounted disk); NTFS volumes are layered on top

    // Set once the mounts have been attempted, so the work runs a single time per test assembly per run
    // rather than on every test's construction (the per-mount checks are idempotent regardless).
    static bool ensured;
    static readonly object gate = new();

    /// <summary>
    /// Ensure all three evidence mounts are present (READ-ONLY), mounting any that are missing. Runs its work
    /// at most once per process; later calls are no-ops. Never throws — if a mount cannot be established the
    /// disk-backed tests surface their own "file not found", which is clearer than a constructor failure.
    /// </summary>
    public static void EnsureAll(AuditEnvironment env)
    {
        lock (gate)
        {
            if (ensured) return;
            ensured = true;
            try
            {
                // ROCBA Surface C: drive (rocba-cdrive.e01): a single-volume image (no partition table) that is
                // hibernated, so mount the whole device (offset 0) read-only via ntfs-3g with force — the kernel
                // NTFS driver refuses a hibernated/dirty volume.
                EnsureEwfMount(env, "/mnt/ewf", "/mnt/rocba_ewf", "rocba-cdrive.e01",
                    "-t ntfs-3g -o ro,force,streams_interface=windows,show_sys_files");

                // CFREDS "Data Leakage" PC (cfreds_2015_data_leakage_pc.E01): the main NTFS partition starts at
                // sector 206848 = byte offset 105906176 (sector 2048 is the 100MB System Reserved volume).
                EnsureEwfMount(env, "/mnt/dlpc", "/mnt/dlpc_ewf", "cfreds_2015_data_leakage_pc.E01",
                    "-o ro,loop,offset=105906176,show_sys_files,streams_interface=windows");

                // Greg Schardt XP (4Dell Latitude CPi.E01): single NTFS partition at sector 63 = byte offset 32256.
                EnsureEwfMount(env, "/mnt/windows_mount2", "/mnt/ewf_mount2", "4Dell Latitude CPi.E01",
                    "-o ro,loop,offset=32256,show_sys_files,streams_interface=windows");
            }
            catch { /* best-effort: disk-backed tests surface their own errors */ }
        }
    }

    // Expose <image> (an E01 under /mnt/artifacts) as a raw device via ewfmount under <rawDir>, then mount its
    // NTFS volume read-only at <target> with <mountOpts>. Each step is skipped when already mounted, so this is
    // safe on an already-mounted box. Runs as one shell line (SSH executes it via the login shell).
    static void EnsureEwfMount(AuditEnvironment env, string target, string rawDir, string image, string mountOpts)
    {
        var script =
            $"sudo mkdir -p {rawDir} {target}; " +
            $"mountpoint -q {rawDir} || sudo ewfmount '{Artifacts}/{image}' {rawDir}; " +
            $"mountpoint -q {target} || sudo mount {mountOpts} {rawDir}/ewf1 {target}";
        env.ExecuteCommand("sudo", script, out _, false);
    }
}
