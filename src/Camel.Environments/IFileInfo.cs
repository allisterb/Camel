namespace Camel.Environments;

using System;

public interface IFileInfo : IFileSystemInfo
{
    IFileInfo Create(string file_path);
    string ReadAsText();
    IDirectoryInfo Directory { get; }
    string DirectoryName { get; }
    bool IsReadOnly { get; }
    long Length { get; }
    DateTime LastWriteTimeUtc { get; }
    bool PathExists(string file_path);
}
