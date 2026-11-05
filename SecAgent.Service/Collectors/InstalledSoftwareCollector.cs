using SecAgent.Service.Models;
using SecAgent.Service.Platform;

namespace SecAgent.Service.Collectors;

/// <summary>Software instalado (chaves Uninstall), sem nomes vazios e sem duplicatas (nome+versão).</summary>
public class InstalledSoftwareCollector
{
    private readonly IUninstallRegistry _registry;

    public InstalledSoftwareCollector(IUninstallRegistry registry) => _registry = registry;

    public List<SoftwareEntry> Collect()
        => _registry.ReadEntries()
            .Where(s => !string.IsNullOrWhiteSpace(s.Name))
            .GroupBy(s => (s.Name, s.Version))
            .Select(g => g.First())
            .OrderBy(s => s.Name)
            .ToList();
}
