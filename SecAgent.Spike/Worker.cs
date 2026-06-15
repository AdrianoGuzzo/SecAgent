using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;

namespace SecAgent.Spike;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly ClaudeOptions _claude;
    private readonly SpikeOptions _spike;

    public Worker(ILogger<Worker> logger, IOptions<ClaudeOptions> claude, IOptions<SpikeOptions> spike)
    {
        _logger = logger;
        _claude = claude.Value;
        _spike = spike.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await AppendLogAsync("=== Spike started ===");
        await AppendLogAsync(DiagnoseEnvironment());

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var result = await InvokeClaudeAsync(stoppingToken);
                await AppendLogAsync(result);
            }
            catch (OperationCanceledException) { throw; }
            catch (Exception ex)
            {
                await AppendLogAsync($"[ERROR] {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
            }

            try { await Task.Delay(TimeSpan.FromSeconds(_spike.RunIntervalSeconds), stoppingToken); }
            catch (OperationCanceledException) { break; }
        }

        await AppendLogAsync("=== Spike stopped ===");
    }

    private string DiagnoseEnvironment()
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Identity:      {WindowsIdentity.GetCurrent().Name}");
        sb.AppendLine($"WorkingDir:    {Environment.CurrentDirectory}");
        sb.AppendLine($"USERPROFILE:   {Environment.GetEnvironmentVariable("USERPROFILE") ?? "(null)"}");
        sb.AppendLine($"HOME:          {Environment.GetEnvironmentVariable("HOME") ?? "(null)"}");
        sb.AppendLine($"APPDATA:       {Environment.GetEnvironmentVariable("APPDATA") ?? "(null)"}");
        sb.AppendLine($"PATH (head):   {(Environment.GetEnvironmentVariable("PATH") ?? "").Substring(0, Math.Min(200, (Environment.GetEnvironmentVariable("PATH") ?? "").Length))}");
        sb.AppendLine($"ClaudeExe:     {_claude.ExePath} (exists: {File.Exists(_claude.ExePath)})");
        var token = Environment.GetEnvironmentVariable(_claude.TokenEnvVarName);
        sb.AppendLine($"{_claude.TokenEnvVarName}: {(string.IsNullOrEmpty(token) ? "(MISSING)" : $"present ({token.Length} chars)")}");
        return sb.ToString();
    }

    private async Task<string> InvokeClaudeAsync(CancellationToken ct)
    {
        if (!File.Exists(_claude.ExePath))
            return $"[ERROR] claude.exe not found at {_claude.ExePath}";

        var token = Environment.GetEnvironmentVariable(_claude.TokenEnvVarName);
        if (string.IsNullOrEmpty(token))
            return $"[ERROR] env var {_claude.TokenEnvVarName} is empty";

        var psi = new ProcessStartInfo(_claude.ExePath)
        {
            ArgumentList =
            {
                "-p", _spike.TestPrompt,
                "--output-format", "json",
                "--model", _claude.Model,
                "--permission-mode", "bypassPermissions"
            },
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(_spike.LogPath) ?? @"C:\ProgramData\SecAgent"
        };
        psi.Environment[_claude.TokenEnvVarName] = token;

        var sw = Stopwatch.StartNew();
        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Process.Start returned null");

        var stdoutTask = process.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = process.StandardError.ReadToEndAsync(ct);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(_claude.TimeoutSeconds));

        try { await process.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            try { process.Kill(true); } catch { }
            return $"[ERROR] claude timed out after {_claude.TimeoutSeconds}s";
        }

        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        sw.Stop();

        if (process.ExitCode != 0)
            return $"[FAIL] exit={process.ExitCode} elapsed={sw.ElapsedMilliseconds}ms\nSTDERR:\n{stderr}\nSTDOUT:\n{stdout}";

        string? text = null;
        bool? isError = null;
        try
        {
            using var doc = JsonDocument.Parse(stdout);
            var root = doc.RootElement;
            if (root.TryGetProperty("result", out var r)) text = r.GetString();
            if (root.TryGetProperty("is_error", out var e)) isError = e.GetBoolean();
        }
        catch (JsonException jx)
        {
            return $"[FAIL] could not parse JSON ({jx.Message})\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}";
        }

        return $"[OK] elapsed={sw.ElapsedMilliseconds}ms is_error={isError} result={text}";
    }

    private async Task AppendLogAsync(string message)
    {
        var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}";
        _logger.LogInformation("{Message}", message);
        try
        {
            var dir = Path.GetDirectoryName(_spike.LogPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            await File.AppendAllTextAsync(_spike.LogPath, line);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to write spike log to {Path}", _spike.LogPath);
        }
    }
}
