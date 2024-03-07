using System.Text.Json.Serialization;

namespace DemaConsulting.Sbom.TransitiveSpdx.Spdx;

/// <summary>
/// SPDX Creation Information class
/// </summary>
public class SpdxCreationInformation
{
    /// <summary>
    /// Creators field
    /// </summary>
    [JsonPropertyName("creators")]
    public List<string>? Creators { get; set; }

    /// <summary>
    /// Created field
    /// </summary>
    [JsonPropertyName("created")]
    public string? Created { get; set; }

    /// <summary>
    /// Comment field (optional)
    /// </summary>
    [JsonPropertyName("comment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Comment { get; set; }

    /// <summary>
    /// License list version field (optional)
    /// </summary>
    [JsonPropertyName("licenseListVersion")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LicenseListVersion { get; set; }
}