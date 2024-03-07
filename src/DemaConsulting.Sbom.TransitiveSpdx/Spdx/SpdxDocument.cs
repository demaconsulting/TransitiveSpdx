using System.Text.Json;
using System.Text.Json.Serialization;

namespace DemaConsulting.Sbom.TransitiveSpdx.Spdx;

/// <summary>
/// SPDX Document class
/// </summary>
public class SpdxDocument : SpdxElement
{
    /// <summary>
    /// Document ID field
    /// </summary>
    [JsonPropertyName("SPDXID")]
    public string? SpdxId
    {
        get => ElementId;
        set => ElementId = value;
    }

    /// <summary>
    /// Document Name field
    /// </summary>
    [JsonPropertyName("name")]
    public string? Name
    {
        get => ElementName;
        set => ElementName = value;
    }

    /// <summary>
    /// SPDX version field
    /// </summary>
    [JsonPropertyName("spdxVersion")]
    public string? SpdxVersion { get; set; }

    /// <summary>
    /// Data License
    /// </summary>
    [JsonPropertyName("dataLicense")]
    public string? DataLicense { get; set; }

    /// <summary>
    /// Document namespace
    /// </summary>
    [JsonPropertyName("documentNamespace")]
    public string? DocumentNamespace { get; set; }

    /// <summary>
    /// Document comment field (optional)
    /// </summary>
    [JsonPropertyName("comment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Comment { get; set; }

    /// <summary>
    /// Creation information
    /// </summary>
    [JsonPropertyName("creationInfo")]
    public SpdxCreationInformation? CreationInformation { get; set; }

    /// <summary>
    /// List of files
    /// </summary>
    [JsonPropertyName("files")]
    public List<SpdxFile>? FileList { get; set; }

    /// <summary>
    /// List of packages
    /// </summary>
    [JsonPropertyName("packages")]
    public List<SpdxPackage>? PackageList { get; set; }

    /// <summary>
    /// List of relationships
    /// </summary>
    [JsonPropertyName("relationships")]
    public List<SpdxRelationship>? RelationshipList { get; set; }

    /// <summary>
    /// Document describes field
    /// </summary>
    [JsonPropertyName("documentDescribes")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? DescribesList { get; set; }

    /// <summary>
    /// Files
    /// </summary>
    [JsonIgnore]
    public IEnumerable<SpdxFile> Files => FileList ?? Enumerable.Empty<SpdxFile>();

    /// <summary>
    /// Packages
    /// </summary>
    [JsonIgnore]
    public IEnumerable<SpdxPackage> Packages => PackageList ?? Enumerable.Empty<SpdxPackage>();

    /// <summary>
    /// Relationships
    /// </summary>
    [JsonIgnore]
    public IEnumerable<SpdxRelationship> Relationships => RelationshipList ?? Enumerable.Empty<SpdxRelationship>();

    /// <summary>
    /// Child nodes
    /// </summary>
    [JsonIgnore]
    public override IEnumerable<SpdxNode> Children => Files.Concat<SpdxNode>(Packages).Concat(Relationships);

    /// <summary>
    /// Get the root package(s) this document describes
    /// </summary>
    /// <returns>Root package(s)</returns>
    public IEnumerable<SpdxPackage> GetDescribes()
    {
        // Get IDs from the describes list
        var rootIds = (DescribesList ?? Enumerable.Empty<string>()).ToHashSet();

        // Add IDs that are described by the document
        foreach (var relationship in Relationships)
            if (relationship.ElementId == ElementId && 
                relationship is {RelationshipType: "DESCRIBES", RelatedElementId: not null})
                rootIds.Add(relationship.RelatedElementId);

        // Return all packages matching the ID
        return Packages.Where(p => p.ElementId != null && rootIds.Contains(p.ElementId));
    }

    /// <summary>
    /// Load an SPDX document from JSON file
    /// </summary>
    /// <param name="fileName">File name</param>
    /// <returns>SPDX document</returns>
    public static SpdxDocument LoadJson(string fileName)
    {
        return ParseJson(File.ReadAllText(fileName));
    }

    /// <summary>
    /// Save an SPDX document to JSON file
    /// </summary>
    /// <param name="fileName">File name</param>
    public void SaveJson(string fileName)
    {
        File.WriteAllText(fileName, ToJsonString());
    }

    /// <summary>
    /// Parse an SPDX document from JSON text
    /// </summary>
    /// <param name="jsonText">JSON text</param>
    /// <returns>SPDX document</returns>
    public static SpdxDocument ParseJson(string jsonText)
    {
        // Deserialize the document
        var doc = JsonSerializer.Deserialize<SpdxDocument>(jsonText) 
               ?? throw new InvalidDataException("Invalid SPDX Json");

        // Rebuild the tree
        doc.RebuildTree(doc, doc);

        // Return the document
        return doc;
    }

    /// <summary>
    /// Convert an SPDX document to JSON string
    /// </summary>
    /// <returns>JSON string</returns>
    public string ToJsonString()
    {
        return JsonSerializer.Serialize(
            this, 
            new JsonSerializerOptions
            {
                WriteIndented = true
            });
    }
}
