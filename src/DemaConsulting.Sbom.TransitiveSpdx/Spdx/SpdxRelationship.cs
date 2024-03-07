using System.Text.Json.Serialization;

namespace DemaConsulting.Sbom.TransitiveSpdx.Spdx;

/// <summary>
/// SPDX Relationship class
/// </summary>
public class SpdxRelationship : SpdxNode
{
    /// <summary>
    /// SPDX element ID
    /// </summary>
    [JsonPropertyName("spdxElementId")]
    public string? ElementId { get; set; }

    /// <summary>
    /// Relationship type
    /// </summary>
    [JsonPropertyName("relationshipType")]
    public string? RelationshipType { get; set; }

    /// <summary>
    /// Related Element ID
    /// </summary>
    [JsonPropertyName("relatedSpdxElement")]
    public string? RelatedElementId { get; set; }
}
