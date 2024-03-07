using System.Text.Json;
using System.Text.Json.Serialization;

namespace DemaConsulting.Sbom.TransitiveSpdx.Spdx;

/// <summary>
/// SPDX File class
/// </summary>
public class SpdxFile : SpdxElement
{
    /// <summary>
    /// File Name field
    /// </summary>
    [JsonPropertyName("fileName")]
    public string? FileName
    {
        get => ElementName;
        set => ElementName = value;
    }

    /// <summary>
    /// SPDX Identifier field
    /// </summary>
    [JsonPropertyName("SPDXID")]
    public string? SpdxId
    {
        get => ElementId;
        set => ElementId = value;
    }

    /// <summary>
    /// File checksums field
    /// </summary>
    [JsonPropertyName("checksums")]
    public List<SpdxChecksum>? Checksums { get; set; }

    /// <summary>
    /// File license concluded field
    /// </summary>
    [JsonPropertyName("licenseConcluded")]
    public string? LicenseConcluded { get; set; }

    /// <summary>
    /// File license info in files field
    /// </summary>
    [JsonPropertyName("licenseInfoInFiles")]
    public List<string>? LicenseInfoInFiles { get; set; }

    /// <summary>
    /// File copyright field
    /// </summary>
    [JsonPropertyName("copyrightText")]
    public string? Copyright { get; set; }

    /// <summary>
    /// Make a deep-copy of this file
    /// </summary>
    /// <returns>Deep-copy of this file</returns>
    public SpdxFile DeepCopy()
    {
        return JsonSerializer.Deserialize<SpdxFile>(JsonSerializer.Serialize(this)) ??
               throw new InvalidOperationException("Unable to deep copy file");
    }
}
