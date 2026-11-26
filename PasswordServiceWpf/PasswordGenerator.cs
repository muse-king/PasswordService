using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace PasswordServiceWpf;

public static class PasswordGenerator
{
    public const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public const string Lower = "abcdefghijklmnopqrstuvwxyz";
    public const string Digits = "0123456789";
    public const string Special = "!@#$%^&*()-_=+[]{}:;,.?";

    public static string Generate(int length, bool useUpper, bool useLower, bool useDigits, bool useSymbols)
    {
        var pools = new List<string>();
        if (useUpper) pools.Add(Upper);
        if (useLower) pools.Add(Lower);
        if (useDigits) pools.Add(Digits);
        if (useSymbols) pools.Add(Special);

        if (pools.Count == 0)
            throw new ArgumentException("请至少选择一种字符类型");
        if (length < 1 || length > 256)
            throw new ArgumentOutOfRangeException(nameof(length), "长度应为 1 到 256");
        if (length < pools.Count)
            throw new ArgumentException("长度不足，无法满足所选类型要求");

        var allChars = string.Concat(pools);
        var chars = new char[length];
        for (int i = 0; i < pools.Count; i++)
        {
            chars[i] = pools[i][RandomNumberGenerator.GetInt32(pools[i].Length)];
        }
        for (int i = pools.Count; i < length; i++)
        {
            chars[i] = allChars[RandomNumberGenerator.GetInt32(allChars.Length)];
        }

        // Fisher-Yates shuffle
        for (int i = chars.Length - 1; i > 0; i--)
        {
            int j = RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }

        return new string(chars);
    }
}
