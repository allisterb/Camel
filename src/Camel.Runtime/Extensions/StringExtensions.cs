using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Camel
{
    public static class StringExtensions
    {
        public static string Delete(this string s, string r) => s.Replace(r, string.Empty);

        public static string JoinSuperscript(this string s, string r)
        {
            if (s.Contains("_"))
            {
                return s.Insert(s.IndexOf("_") + 1, "{") + s + r + "}";
            }
            else
            {
                return s + "_" + r;
            }
        }
    }
}
