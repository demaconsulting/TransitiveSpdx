using System.Text.Json.Serialization;

namespace DemaConsulting.Sbom.TransitiveSpdx.Spdx;

/// <summary>
/// SPDX Checksum class
/// </summary>
public class SpdxChecksum
{
    /// <summary>
    /// Checksum algorithm field
    /// </summary>
    [JsonPropertyName("algorithm")]
    public string? Algorithm { get; set; }

    /// <summary>
    /// Checksum value field
    /// </summary>
    [JsonPropertyName("checksumValue")]
    public string? Value { get; set; }
}
