using System.Text.Json.Serialization;

namespace DemaConsulting.Sbom.TransitiveSpdx.Spdx;

/// <summary>
/// SPDX Node
/// </summary>
public class SpdxNode
{
    /// <summary>
    /// Parent document
    /// </summary>
    [JsonIgnore]
    public SpdxDocument? Document { get; set; }

    /// <summary>
    /// Parent node
    /// </summary>
    [JsonIgnore]
    public SpdxNode? Parent { get; set; }

    /// <summary>
    /// Child nodes
    /// </summary>
    [JsonIgnore]
    public virtual IEnumerable<SpdxNode> Children => Enumerable.Empty<SpdxNode>();

    /// <summary>
    /// Rebuild the node tree
    /// </summary>
    /// <param name="document">Root document</param>
    /// <param name="parent">Parent node</param>
    public void RebuildTree(SpdxDocument document, SpdxNode parent)
    {
        // Set our tree data
        Document = document;
        Parent = parent;

        // Update child tree data
        foreach (var child in Children)
            child.RebuildTree(document, this);
    }
}