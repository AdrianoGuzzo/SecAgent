using System.Diagnostics.CodeAnalysis;
using System.Management;

namespace SecAgent.Service.Platform;

/// <summary>
/// Executa uma consulta WQL e devolve cada objeto como dicionário propriedade→valor.
/// Os coletores só fazem o mapeamento (testável); o acesso a WMI fica aqui.
/// </summary>
public interface IWmiQuery
{
    IReadOnlyList<IReadOnlyDictionary<string, object?>> Query(string scope, string wql);
}

[ExcludeFromCodeCoverage(Justification = "Adapter fino de WMI")]
internal sealed class WmiQuery : IWmiQuery
{
    public IReadOnlyList<IReadOnlyDictionary<string, object?>> Query(string scope, string wql)
    {
        var result = new List<IReadOnlyDictionary<string, object?>>();
        using var searcher = new ManagementObjectSearcher(scope, wql);
        using var collection = searcher.Get();
        foreach (ManagementBaseObject obj in collection)
        {
            using (obj)
            {
                var dict = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                foreach (var p in obj.Properties)
                    dict[p.Name] = p.Value;
                result.Add(dict);
            }
        }
        return result;
    }
}
