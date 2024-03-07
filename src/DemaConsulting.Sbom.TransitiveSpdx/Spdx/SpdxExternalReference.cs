using System.Text.Json.Serialization;

namespace DemaConsulting.Sbom.TransitiveSpdx.Spdx;

/// <summary>
/// SPDX External Reference class
/// </summary>
public class SpdxExternalReference
{
    /// <summary>
    /// Reference Category field
    /// </summary>
    [JsonPropertyName("referenceCategory")]
    public string? Category { get; set; }

    /// <summary>
    /// Reference Type field
    /// </summary>
    [JsonPropertyName("referenceType")]
    public string? Type { get; set; }

    /// <summary>
    /// Reference Locator field
    /// </summary>
    [JsonPropertyName("referenceLocator")]
    public string? Locator { get; set; }

    /// <summary>
    /// Reference Comment field (optional)
    /// </summary>
    [JsonPropertyName("comment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Comment { get; set; }
}
