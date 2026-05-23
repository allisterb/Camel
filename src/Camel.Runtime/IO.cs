namespace Camel;

using System;
using System.Collections.Generic;
using System.IO;

public class IO : Runtime
{       
    public static string[] GetFiles(string pattern, string srcPath = ".", bool recurse = false)
    {
        if (!Directory.Exists(srcPath))
        {
            Error("The path {0} does not exist.", srcPath);
            return new string[0];
        }
        else
        {
            var files = Directory.GetFiles(srcPath, pattern, recurse ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly);
            return files;
        }
    }

    public static int DeleteFiles(string pattern, string srcPath = ".", bool recurse = false)
    {
        if (!Directory.Exists(srcPath))
        {
            Error("The path {0} does not exist.", srcPath);
            return -1;
        }
        else
        {
            var files = GetFiles(pattern, srcPath, recurse);
            foreach(var file in files)
            {
                File.Delete(Path.Combine(srcPath, file));
            }
            return files.Length;
        }
    }
    public static string GetRelativePath(string fromPath, string toPath)
    {       
        Uri fromUri = new Uri(fromPath);
        Uri toUri = new Uri(toPath);

        if (fromUri.Scheme != toUri.Scheme) { return toPath; } // path can't be made relative.

        Uri relativeUri = fromUri.MakeRelativeUri(toUri);
        String relativePath = Uri.UnescapeDataString(relativeUri.ToString());

        if (toUri.Scheme.Equals("file", StringComparison.InvariantCultureIgnoreCase))
        {
            relativePath = relativePath.Replace(Path.AltDirectorySeparatorChar, Path.DirectorySeparatorChar);
        }

        return relativePath;
    }
}
