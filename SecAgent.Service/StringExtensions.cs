namespace SecAgent.Service;

internal static class StringExtensions
{
    /// <summary>Corta em <paramref name="max"/> caracteres acrescentando "..." quando trunca.</summary>
    public static string Truncate(this string s, int max) =>
        s.Length <= max ? s : s[..max] + "...";
}
