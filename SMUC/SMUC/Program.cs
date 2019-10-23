using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

namespace SMUC
{
    class Program
    {
        static readonly string[] zipFileBlacklist =
        {
            "/",
            ".txt",
            ".ini",
            ".bat",
            ".exe"
        };

        static void Main(string[] args)
        {
            Console.Title = "Zen2 SMU Checker";

            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);

            if (args.Length == 0)
            {
                return;
            }

            foreach(var arg in args)
            {
                if (!File.Exists(arg))
                {
                    continue;
                }

                string biosName = null;
                byte[] biosBytes = null;

                if (arg.EndsWith(".zip"))
                {
                    using (var zipArchive = ZipFile.OpenRead(arg))
                    {
                        foreach(var zipEntry in zipArchive.Entries)
                        {
                            if (string.IsNullOrEmpty(zipEntry.Name) || zipFileBlacklist.Any(x => zipEntry.Name.EndsWith(x)))
                            {
                                continue;
                            }

                            biosName = zipEntry.Name;

                            using (var byteStream = zipEntry.Open())
                            using (var memStream = new MemoryStream())
                            {
                                byteStream.CopyTo(memStream);
                                biosBytes = memStream.ToArray();
                            }
                            break;
                        }
                    }

                    if (biosName is null || biosBytes is null)
                    {
                        Log($"Could not retrieve bios from {arg}\n", ConsoleColor.DarkRed);
                        continue;
                    }
                }
                else
                {
                    biosName = Path.GetFileName(arg);
                    biosBytes = File.ReadAllBytes(arg);
                }

                Log($"Scanning: {biosName} ({BytesToKB(biosBytes.Length).ToString("N0")} KB)", newLine: false);

                var agesaVersion = SearchPattern(biosBytes, "3D 9B 25 70 41 47 45 53 41", 0xD)
                    .FirstOrDefault();
                if (agesaVersion != 0)
                {
                    var buf = new byte[255];
                    Array.Copy(biosBytes, agesaVersion, buf, 0, buf.Length);

                    var versionStr = Encoding.UTF8.GetString(buf);
                    if (versionStr.Contains('\0'))
                    {
                        versionStr = versionStr.Substring(0, versionStr.IndexOf('\0'));
                    }

                    Log($" {versionStr}");
                }
                else
                {
                    Console.Write(Environment.NewLine);
                }

                var smuMods = SearchPattern(biosBytes, "24 50 53 31 00 00", -0x10);
                if (smuMods.Any())
                {
                    foreach (var smuOffset in smuMods)
                    {
                        var smuLen = BitConverter.ToInt32(biosBytes, smuOffset + 0x6C);
                        var smuVer = $"{biosBytes[smuOffset + 0x62]}.{biosBytes[smuOffset + 0x61]}.{biosBytes[smuOffset + 0x60]}";

                        Log($"   {smuVer} ({BytesToKB(smuLen).ToString("N0").PadLeft(3, ' ')} KB) " +
                            $"[{smuOffset.ToString("X").PadLeft(8, '0')} - {(smuOffset + smuLen).ToString("X").PadLeft(8, '0')}]", ConsoleColor.DarkGreen);
                    }
                }
                else
                {
                    Log("Could not find any smu modules", ConsoleColor.DarkRed);
                }

                Console.Write(Environment.NewLine);
            }

            Log("Done.", wait: true);
        }

        static double BytesToKB(int bytes)
        {
            return bytes / 1024d;
        }

        static void Log(string message, ConsoleColor color = ConsoleColor.White, bool newLine = true, bool wait = false)
        {
            Console.ForegroundColor = color;
            Console.Write(newLine ? message + Environment.NewLine : message);
            Console.ResetColor();

            if (wait)
            {
                Console.ReadLine();
            }
        }

        static int[] CreateMatchingsTable((byte, bool)[] patternTuple)
        {
            var skipTable = new int[256];
            var wildcards = patternTuple.Select(x => x.Item2).ToArray();
            var lastIndex = patternTuple.Length - 1;

            var diff = lastIndex - Math.Max(Array.LastIndexOf(wildcards, false), 0);
            if (diff == 0)
            {
                diff = 1;
            }

            for (var i = 0; i < skipTable.Length; i++)
            {
                skipTable[i] = diff;
            }

            for (var i = lastIndex - diff; i < lastIndex; i++)
            {
                skipTable[patternTuple[i].Item1] = lastIndex - i;
            }

            return skipTable;
        }

        static List<int> SearchPattern(byte[] data, string pattern, int offset = 0x0)
        {
            if (!data.Any() || string.IsNullOrEmpty(pattern))
            {
                throw new ArgumentException("Data or Pattern is empty");
            }

            var patternTuple = pattern.Split(' ')
                .Select(hex => hex.Contains('?')
                    ? (byte.MinValue, false)
                    : (Convert.ToByte(hex, 16), true))
                .ToArray();

            if (!patternTuple.Any())
            {
                throw new Exception("Failed to parse Pattern");
            }

            if (data.Length < pattern.Length)
            {
                throw new ArgumentException("Data cannot be smaller than the Pattern");
            }

            var lastPatternIndex = patternTuple.Length - 1;
            var skipTable = CreateMatchingsTable(patternTuple);
            var adressList = new List<int>();

            for (var i = 0; i <= data.Length - patternTuple.Length; i += Math.Max(skipTable[data[i + lastPatternIndex] & 0xFF], 1))
            {
                for (var j = lastPatternIndex; !patternTuple[j].Item2 || data[i + j] == patternTuple[j].Item1; --j)
                {
                    if (j == 0)
                    {
                        adressList.Add(i + offset);
                        break;
                    }
                }
            }

            return adressList;
        }
    }
}
