using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TCPcap
{
    public static class PatternRecognition
    {
        public static string LongestRepeatedSubstring(string str, out int occurences)
        {
            occurences = 0;

            if (string.IsNullOrEmpty(str))
                return null;

            int N = str.Length;
            string[] substrings = new string[N];

            for (int i = 0; i < N; i++)
            {
                substrings[i] = str.Substring(i);
            }

            Array.Sort(substrings);

            string result = "";

            for (int i = 0; i < N - 1; i++)
            {
                string lcs = LongestCommonString(substrings[i], substrings[i + 1]);

                if (lcs.Length > result.Length)
                {
                    result = lcs;
                    occurences = 2;
                }
            }

            return result;
        }

        private static string LongestCommonString(string a, string b)
        {
            int n = Math.Min(a.Length, b.Length);
            string result = "";

            for (int i = 0; i < n; i++)
            {
                if (a[i] == b[i])
                    result = result + a[i];
                else
                    break;
            }

            return result;
        }

        public static IEnumerable<string> GetMostCommonSubstrings(this IList<string> strings)
        {
            if (strings == null)
                throw new ArgumentNullException("strings");
            if (!strings.Any() || strings.Any(s => string.IsNullOrEmpty(s)))
                throw new ArgumentException("None string must be empty", "strings");

            var allSubstrings = new List<List<string>>();
            for (int i = 0; i < strings.Count; i++)
            {
                var substrings = new List<string>();
                string str = strings[i];
                for (int c = 0; c < str.Length - 1; c++)
                {
                    for (int cc = 1; c + cc <= str.Length; cc++)
                    {
                        string substr = str.Substring(c, cc);
                        if (allSubstrings.Count < 1 || allSubstrings.Last().Contains(substr))
                            substrings.Add(substr);
                    }
                }
                allSubstrings.Add(substrings);
            }
            if (allSubstrings.Last().Any())
            {
                var mostCommon = allSubstrings.Last()
                    .GroupBy(str => str)
                    .OrderByDescending(g => g.Key.Length)
                    .ThenByDescending(g => g.Count())
                    .Select(g => g.Key);
                return mostCommon;
            }
            return Enumerable.Empty<string>();
        }

    }
}
