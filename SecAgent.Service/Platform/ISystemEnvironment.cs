using System.Diagnostics.CodeAnalysis;

namespace SecAgent.Service.Platform;

/// <summary>Fatos do processo/máquina (arquivos, env vars, nome da máquina) — seam para testes.</summary>
public interface ISystemEnvironment
{
    bool FileExists(string path);
    string? GetEnvironmentVariable(string name);
    string MachineName { get; }
    string OsVersion { get; }

    /// <summary>Diretório do executável do Service (usado no filtro de auto-referência).</summary>
    string BaseDirectory { get; }
}

[ExcludeFromCodeCoverage(Justification = "Adapter fino de SO")]
internal sealed class SystemEnvironment : ISystemEnvironment
{
    public bool FileExists(string path) => File.Exists(path);
    public string? GetEnvironmentVariable(string name) => Environment.GetEnvironmentVariable(name);
    public string MachineName => Environment.MachineName;
    public string OsVersion => Environment.OSVersion.VersionString;
    public string BaseDirectory => AppContext.BaseDirectory;
}
