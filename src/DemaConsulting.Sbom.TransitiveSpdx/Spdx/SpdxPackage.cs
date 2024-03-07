using System.Text.Json;
using System.Text.Json.Serialization;

namespace DemaConsulting.Sbom.TransitiveSpdx.Spdx;

/// <summary>
/// SPDX Package class
/// </summary>
public class SpdxPackage : SpdxElement
{
    /// <summary>
    /// Package Name field
    /// </summary>
    [JsonPropertyName("name")]
    public string? Name
    {
        get => ElementName;
        set => ElementName = value;
    }

    /// <summary>
    /// Package ID field
    /// </summary>
    [JsonPropertyName("SPDXID")]
    public string? SpdxId
    {
        get => ElementId;
        set => ElementId = value;
    }

    /// <summary>
    /// Package version field
    /// </summary>
    [JsonPropertyName("versionInfo")]
    public string? Version { get; set; }

    /// <summary>
    /// Package file name field (optional)
    /// </summary>
    [JsonPropertyName("packageFileName")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? FileName { get; set; }

    /// <summary>
    /// Package download location
    /// </summary>
    [JsonPropertyName("downloadLocation")]
    public string? DownloadLocation { get; set; }

    /// <summary>
    /// Package files analyzed (optional)
    /// </summary>
    [JsonPropertyName("filesAnalyzed")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? FilesAnalyzed { get; set; }

    /// <summary>
    /// Package checksums field (optional)
    /// </summary>
    [JsonPropertyName("checksums")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<SpdxChecksum>? Checksums { get; set; }

    /// <summary>
    /// Package home page field (optional)
    /// </summary>
    [JsonPropertyName("homepage")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? HomePage { get; set; }

    /// <summary>
    /// Package source information field (optional)
    /// </summary>
    [JsonPropertyName("sourceInfo")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Source { get; set; }

    /// <summary>
    /// Package license concluded
    /// </summary>
    [JsonPropertyName("licenseConcluded")]
    public string? LicenseConcluded { get; set; }

    /// <summary>
    /// Package license info from files (optional)
    /// </summary>
    [JsonPropertyName("licenseInfoFromFiles")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? LicenseInfoFromFiles { get; set; }

    /// <summary>
    /// Package license declared
    /// </summary>
    [JsonPropertyName("licenseDeclared")]
    public string? LicenseDeclared { get; set; }

    /// <summary>
    /// Package license comments (optional)
    /// </summary>
    [JsonPropertyName("licenseComments")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LicenseComments { get; set; }

    /// <summary>
    /// Package copyright
    /// </summary>
    [JsonPropertyName("copyrightText")]
    public string? Copyright { get; set; }

    /// <summary>
    /// Package summary (optional)
    /// </summary>
    [JsonPropertyName("summary")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Summary { get; set; }

    /// <summary>
    /// Package description (optional)
    /// </summary>
    [JsonPropertyName("description")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Description { get; set; }

    /// <summary>
    /// Package comment (optional)
    /// </summary>
    [JsonPropertyName("comment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Comment { get; set; }

    /// <summary>
    /// Package external references (optional)
    /// </summary>
    [JsonPropertyName("externalRefs")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<SpdxExternalReference>? ExternalReferences { get; set; }

    /// <summary>
    /// Package supplier (optional)
    /// </summary>
    [JsonPropertyName("supplier")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Supplier { get; set; }

    /// <summary>
    /// Package originator (optional)
    /// </summary>
    [JsonPropertyName("originator")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Originator { get; set; }

    /// <summary>
    /// Package attributions (optional)
    /// </summary>
    [JsonPropertyName("attributionTexts")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? Attributions { get; set; }

    /// <summary>
    /// Package has files field (optional)
    /// </summary>
    [JsonPropertyName("hasFiles")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? FilesList { get; set; }

    /// <summary>
    /// Make a deep-copy of this package
    /// </summary>
    /// <returns>Deep-copy of this package</returns>
    public SpdxPackage DeepCopy()
    {
        return JsonSerializer.Deserialize<SpdxPackage>(JsonSerializer.Serialize(this)) ?? 
               throw new InvalidOperationException("Unable to deep copy package");
    }

    /// <summary>
    /// Find dependent packages of this package
    /// </summary>
    /// <returns>Dependent packages</returns>
    public IEnumerable<SpdxPackage> FindDependentPackages()
    {
        // If no document then no dependencies
        if (Document == null)
            return Enumerable.Empty<SpdxPackage>();

        // Get the packages we depend on
        var dependsOn = Document
            .Relationships
            .Where(r => r.RelationshipType == "DEPENDS_ON" && r.ElementId == ElementId)
            .Select(r => r.RelatedElementId);

        // Get the packages that are dependencies of us
        var dependencyOf = Document
            .Relationships
            .Where(r => r.RelationshipType == "DEPENDENCY_OF" && r.RelatedElementId == ElementId)
            .Select(r => r.ElementId);

        // Assemble a set of dependent package IDs
        var packageIds = dependsOn.Concat(dependencyOf).Distinct().ToHashSet();

        // Return the packages with IDs in the set
        return Document.Packages.Where(p => packageIds.Contains(p.ElementId));
    }

    /// <summary>
    /// Find dependent packages of this package
    /// </summary>
    /// <returns>Contained packages</returns>
    public IEnumerable<SpdxPackage> FindContainedPackages()
    {
        // If no document then nothing contained
        if (Document == null)
            return Enumerable.Empty<SpdxPackage>();

        // Get the packages we contain
        var contains = Document
            .Relationships
            .Where(r => r.RelationshipType == "CONTAINS" && r.ElementId == ElementId)
            .Select(r => r.RelatedElementId);

        // Get the packages that are contained by us
        var containedBy = Document
            .Relationships
            .Where(r => r.RelationshipType == "CONTAINED_BY" && r.RelatedElementId == ElementId)
            .Select(r => r.ElementId);

        // Assemble a set of contained package IDs
        var packageIds = contains.Concat(containedBy).Distinct().ToHashSet();

        // Return the packages with IDs in the set
        return Document.Packages.Where(p => packageIds.Contains(p.ElementId));
    }
}
