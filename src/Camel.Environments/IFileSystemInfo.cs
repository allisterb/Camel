namespace Camel.Environments;

using System;

public interface IFileSystemInfo
{
    string PathSeparator { get; }
    string Name { get; }
    string FullName { get; }
    bool Exists { get; }
}
