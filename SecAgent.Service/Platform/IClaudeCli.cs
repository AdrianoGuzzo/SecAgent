using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace SecAgent.Service.Platform;

public record ClaudeCliRequest(
    string ExePath,
    IReadOnlyList<string> Arguments,
    string Stdin,
    IReadOnlyDictionary<string, string> Environment,
    string WorkingDirectory,
    TimeSpan Timeout);

/// <summary>
/// Resultado bruto da execução. <see cref="Error"/> != null quando o processo
/// não pôde rodar até o fim (falha ao iniciar, timeout, cancelamento).
/// </summary>
public record ClaudeCliResult(
    string Stdout,
    string Stderr,
    int? ExitCode,
    long ElapsedMs,
    string? Error);

/// <summary>Executa o claude CLI com o prompt no stdin (limite ~32K da linha de comando).</summary>
public interface IClaudeCli
{
    Task<ClaudeCliResult> RunAsync(ClaudeCliRequest request, CancellationToken ct);
}

[ExcludeFromCodeCoverage(Justification = "Adapter fino de Process")]
internal sealed class ProcessClaudeCli : IClaudeCli
{
    public async Task<ClaudeCliResult> RunAsync(ClaudeCliRequest request, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(request.ExePath)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            // claude.exe emite/consome UTF-8. Sem isto o .NET usa a code page do
            // console (CP850/1252) e os acentos chegam corrompidos.
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            StandardInputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = request.WorkingDirectory
        };
        foreach (var a in request.Arguments) psi.ArgumentList.Add(a);
        foreach (var kv in request.Environment) psi.Environment[kv.Key] = kv.Value;

        var sw = Stopwatch.StartNew();
        Process? process;
        try { process = Process.Start(psi); }
        catch (Exception ex) { return new("", "", null, sw.ElapsedMilliseconds, $"Process.Start failed: {ex.Message}"); }
        if (process is null) return new("", "", null, sw.ElapsedMilliseconds, "Process.Start returned null");

        using (process)
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            timeout.CancelAfter(request.Timeout);
            try
            {
                // Lê stdout/stderr EM PARALELO à escrita do stdin: com prompt grande,
                // escrever tudo antes de ler podia travar nos buffers do pipe.
                var stdoutTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
                var stderrTask = process.StandardError.ReadToEndAsync(timeout.Token);

                await process.StandardInput.WriteAsync(request.Stdin.AsMemory(), timeout.Token);
                process.StandardInput.Close();

                await process.WaitForExitAsync(timeout.Token);
                var stdout = await stdoutTask;
                var stderr = await stderrTask;
                sw.Stop();
                return new(stdout, stderr, process.ExitCode, sw.ElapsedMilliseconds, null);
            }
            catch (OperationCanceledException)
            {
                sw.Stop();
                var why = ct.IsCancellationRequested
                    ? "Claude cancelled (service stopping)"
                    : $"Claude timed out after {(int)request.Timeout.TotalSeconds}s";
                return new("", "", null, sw.ElapsedMilliseconds, why);
            }
            catch (Exception ex)
            {
                sw.Stop();
                return new("", "", null, sw.ElapsedMilliseconds, $"Failed to talk to claude: {ex.Message}");
            }
            finally
            {
                // Nunca deixa claude.exe órfão (timeout, cancelamento ou erro de pipe).
                try { if (!process.HasExited) process.Kill(entireProcessTree: true); } catch { }
            }
        }
    }
}
