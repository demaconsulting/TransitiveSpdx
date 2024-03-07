using System.Text.Json.Serialization;

namespace DemaConsulting.Sbom.TransitiveSpdx.Spdx;

/// <summary>
/// SPDX Element class
/// </summary>
public class SpdxElement : SpdxNode
{
    /// <summary>
    /// Identity field
    /// </summary>
    [JsonIgnore]
    public string? ElementId { get; set; }

    /// <summary>
    /// SPDX Name field
    /// </summary>
    [JsonIgnore]
    public string? ElementName { get; set; }
}
