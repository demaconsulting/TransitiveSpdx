using DemaConsulting.Sbom.TransitiveSpdx.Utility;

namespace DemaConsulting.Sbom.TransitiveSpdx.Spdx;

/// <summary>
/// SPDX Indexer class
/// </summary>
public class SpdxIndexer
{
    /// <summary>
    /// Dictionary of document names to loaded documents
    /// </summary>
    private readonly Dictionary<string, SpdxDocument> _documents = new ();

    /// <summary>
    /// Dictionary of populated packages
    /// </summary>
    private readonly List<SpdxPackage> _detailedPackages = new();

    /// <summary>
    /// Populated packages
    /// </summary>
    public IEnumerable<SpdxPackage> DetailedPackages => _detailedPackages;

    /// <summary>
    /// Index the files matching the specified pattern
    /// </summary>
    /// <param name="pattern">File glob search pattern</param>
    public void IndexFiles(string pattern)
    {
        // Process all files
        foreach (var file in FileGlob.FindFiles(pattern))
        {
            // Skip if the file is already loaded
            if (_documents.ContainsKey(file))
                continue;

            // Add the document to the indexer
            AddDocument(file, SpdxDocument.LoadJson(file));
        }
    }

    /// <summary>
    /// Populate the specified document with enhanced details from the indexer
    /// </summary>
    /// <param name="doc">Document to populate</param>
    public void Populate(SpdxDocument doc)
    {
        // Trigger an update for all packages in the document
        foreach (var package in doc.Packages.ToArray())
            UpdatePackage(doc, package);
    }

    /// <summary>
    /// Update a package
    /// </summary>
    /// <param name="doc">SPDX document</param>
    /// <param name="package">Package to update</param>
    private void UpdatePackage(SpdxDocument doc, SpdxPackage package)
    {
        // Construct the list of child packages to update
        var children = new HashSet<SpdxPackage>();
        children.UnionWith(package.FindDependentPackages());
        children.UnionWith(package.FindContainedPackages());

        // Look for detailed information on this package
        var detailed = DetailedPackages.FirstOrDefault(p => p.Name == package.Name && p.Version == package.Version);
        if (detailed != null)
        {
            // Copy information (from a duplicate, so we can own it)
            var dup = detailed.DeepCopy();
            package.FileName = dup.FileName;
            package.DownloadLocation = dup.DownloadLocation;
            package.FilesAnalyzed = dup.FilesAnalyzed;
            package.Checksums = dup.Checksums;
            package.HomePage = dup.HomePage;
            package.Source = dup.Source;
            package.LicenseConcluded = dup.LicenseConcluded;
            package.LicenseInfoFromFiles = dup.LicenseInfoFromFiles;
            package.LicenseDeclared = dup.LicenseDeclared;
            package.LicenseComments = dup.LicenseComments;
            package.Copyright = dup.Copyright;
            package.Summary = dup.Summary;
            package.Description = dup.Description;
            package.Comment = dup.Comment;
            package.ExternalReferences = dup.ExternalReferences;
            package.Supplier = dup.Supplier;
            package.Originator = dup.Originator;
            package.Attributions = dup.Attributions;

            // Add any dependency packages from the detailed package
            foreach (var dependency in detailed.FindDependentPackages())
            {
                // Get or create the dependent package
                var child = GetOrCreatePackageStub(doc, dependency);
                SetRelationship(doc, package, "DEPENDS_ON", child);
                SetRelationship(doc, child, "DEPENDENCY_OF", package);
                children.Add(child);
            }

            // Add any contained packages from the detailed package
            foreach (var dependency in detailed.FindContainedPackages())
            {
                // Get or create the contained package
                var child = GetOrCreatePackageStub(doc, dependency);
                SetRelationship(doc, package, "CONTAINS", child);
                SetRelationship(doc, child, "CONTAINED_BY", package);
                children.Add(child);
            }
        }

        // Process all child packages
        foreach (var child in children)
            UpdatePackage(doc, child);
    }

    /// <summary>
    /// Get or create a package in the target document
    /// </summary>
    /// <param name="doc">SPDX document</param>
    /// <param name="pattern">Package pattern</param>
    /// <returns>Existing or new package</returns>
    private SpdxPackage GetOrCreatePackageStub(SpdxDocument doc, SpdxPackage pattern)
    {
        // Ensure target document has package list
        doc.PackageList ??= new List<SpdxPackage>();

        // Find the package in the target document
        var package = doc.PackageList.Find(p => p.Name == pattern.Name && p.Version == pattern.Version);
        if (package == null)
        {
            // Duplicate the provided pattern - this may be enhanced further if we have more details
            package = pattern.DeepCopy();
            package.FilesList = null;
            doc.PackageList.Add(package);
        }

        // Return the package
        return package;
    }

    /// <summary>
    /// Set a package relationship in the document
    /// </summary>
    /// <param name="doc">SPDX document</param>
    /// <param name="element">Element</param>
    /// <param name="type">Relationship type</param>
    /// <param name="related">Related element</param>
    private void SetRelationship(SpdxDocument doc, SpdxElement element, string type, SpdxElement related)
    {
        // Ensure we have a relationships list
        doc.RelationshipList ??= new List<SpdxRelationship>();

        // Skip if already exists
        if (doc.RelationshipList.Any(r =>
                r.ElementId == element.ElementId &&
                r.RelationshipType == type &&
                r.RelatedElementId == related.ElementId))
            return;

        // Add the missing relationship
        doc.RelationshipList.Add(new SpdxRelationship
        {
            Document = doc,
            Parent = doc,
            ElementId = element.ElementId,
            RelationshipType = type,
            RelatedElementId = related.ElementId
        });
    }

    /// <summary>
    /// Add a document to the indexer
    /// </summary>
    /// <param name="documentName">Document name</param>
    /// <param name="document">Document contents</param>
    private void AddDocument(string documentName, SpdxDocument document)
    {
        // Save the document
        _documents[documentName] = document;

        // Add all analyzed packages
        _detailedPackages.AddRange(
            document.Packages.Where(p => p.FilesAnalyzed != false));
    }
}
