namespace Camel.Environments;

using System.IO;

public interface IDirectoryInfo : IFileSystemInfo
{
    IDirectoryInfo Parent { get; }
    IDirectoryInfo Root { get; }
    IDirectoryInfo Create(string dir_path);
    IDirectoryInfo[] GetDirectories();
    IDirectoryInfo[] GetDirectories(string searchPattern);
    IDirectoryInfo[] GetDirectories(string searchPattern, SearchOption searchOption);
    IFileInfo[] GetFiles();
    IFileInfo[] GetFiles(string searchPattern);
    IFileInfo[] GetFiles(string searchPattern, SearchOption searchOption);    
}
