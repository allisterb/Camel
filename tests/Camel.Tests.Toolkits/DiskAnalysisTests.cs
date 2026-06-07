using Camel.Environments;
using Camel.Toolkits;

namespace Camel.Tests.Toolkits;

public class DiskAnalysisTests : TestsRuntime
{
    public DiskAnalysisTests()
    {
        var sshconfig = LoadConfigFile("sshtestappsettings.json");
        localenv = new LocalEnvironment();
        sshenv = AuditEnvironment.CreateFromConfig(sshconfig);
        toolkit = new DiskAnalysisToolkit(sshenv, sshconfig);
    }

    [Fact]
    public void CanLoadAllToolsFromConfig()
    {
        // Constructing the toolkit loads every ToolList entry from config; verify all resolved.
        Assert.Equal(toolkit.ToolList.Length, toolkit.Tools.Count);
        Assert.All(toolkit.ToolList, name =>
        {
            Assert.True(toolkit.Tools.ContainsKey(name));
            Assert.StartsWith("/bin/", toolkit.Tools[name].Command);
            Assert.NotEmpty(toolkit.Tools[name].Descriptioon);
        });
    }

    [Fact]
    public void CanRunEwfInfo()
    {
        var r = toolkit.EwfInfo(Image);
        Assert.NotNull(r);
        Assert.Equal("aee4fcd9301c03b3b054623ca261959a", r.MD5);
        Assert.Equal("Greg Schardt", r.CaseNumber);
        Assert.Equal(512, r.BytesPerSector);
        Assert.Equal(9514260, r.NumberOfSectors);
    }

    [Fact]
    public void CanRunEwfVerify()
    {
        var r = toolkit.EwfVerify(Image);
        Assert.NotNull(r);
        Assert.True(r.Success);
        Assert.Equal(r.StoredMD5, r.CalculatedMD5);
        Assert.Equal("aee4fcd9301c03b3b054623ca261959a", r.CalculatedMD5);
    }

    [Fact]
    public void CanRunImgStat()
    {
        var r = toolkit.ImgStat(Image);
        Assert.NotNull(r);
        Assert.Equal("ewf", r.ImageType);
        Assert.Equal(4871301120, r.SizeOfData);
        Assert.Equal(512, r.SectorSize);
    }

    [Fact]
    public void CanRunMmls()
    {
        var r = toolkit.Mmls(Image);
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        var ntfs = Assert.Single(r, e => e.Description.Contains("NTFS"));
        Assert.Equal(63, ntfs.Start);
    }

    [Fact]
    public void CanRunFsStat()
    {
        var r = toolkit.FsStat(Image, NtfsOffset);
        Assert.NotNull(r);
        Assert.Equal("NTFS", r.FileSystemType);
        Assert.Equal(5, r.RootDirectory);
        Assert.Equal(512, r.SectorSize);
    }

    [Fact]
    public void CanRunFls()
    {
        var r = toolkit.Fls(Image, NtfsOffset);
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.Contains(r, e => e.Name == "boot.ini");
        Assert.Contains(r, e => e.Deleted); // image has deleted entries at root
    }

    [Fact]
    public void CanRunIstat()
    {
        var r = toolkit.Istat(Image, 3664, NtfsOffset); // boot.ini
        Assert.NotNull(r);
        Assert.Equal(3664, r.Entry);
        Assert.True(r.Allocated);
        Assert.NotNull(r.Created);
    }

    [Fact]
    public void CanRunFfind()
    {
        var r = toolkit.Ffind(Image, 3664, NtfsOffset);
        Assert.NotNull(r);
        Assert.Contains("boot.ini", r);
    }

    [Fact]
    public void CanRunIls()
    {
        var r = toolkit.Ils(Image, NtfsOffset);
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, e => Assert.True(e.StIno >= 0));
    }

    [Fact]
    public void CanRunMactime()
    {
        // mactime consumes a bodyfile; generate one on the workstation first (fls -m).
        const string bodyfile = "/tmp/camel_mactime_bf.txt";
        sshenv.ExecuteCommand("bash",
            $"-c \"fls -o {NtfsOffset} -m / '{Image}' 5 > {bodyfile}\"", out _, false);

        var r = toolkit.Mactime(bodyfile);
        Assert.NotNull(r);
        Assert.NotEmpty(r);
        Assert.All(r, e => Assert.NotEmpty(e.Date));
        Assert.Contains(r, e => e.FileName.Contains("boot.ini"));
    }

    const string Image = "/mnt/memory-images/4Dell Latitude CPi.E01";
    const int NtfsOffset = 63;

    LocalEnvironment localenv;
    AuditEnvironment sshenv;
    DiskAnalysisToolkit toolkit;
}
