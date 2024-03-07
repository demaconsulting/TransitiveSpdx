using Microsoft.Extensions.FileSystemGlobbing;

namespace DemaConsulting.Sbom.TransitiveSpdx.Utility;

/// <summary>
/// File Glob helper class
/// </summary>
public static class FileGlob
{
    /// <summary>
    /// Find all files matching the specified glob pattern
    /// </summary>
    /// <param name="pattern">Glob pattern</param>
    /// <returns>Found files</returns>
    public static string[] FindFiles(string pattern)
    {
        // Check for direct file name (no wildcards)
        if (!pattern.Contains('*'))
        {
            // Convert to full path
            pattern = Path.GetFullPath(pattern);

            // If the file does not exist then return an empty array
            if (!File.Exists(pattern))
                return Array.Empty<string>();

            // Return the file
            return new[] {pattern};
        }

        // Check for a root
        var root = Path.GetPathRoot(pattern) ?? string.Empty;
        if (root.Length == 0)
        {
            // Use the current directory as the search root
            root = Directory.GetCurrentDirectory();
        }
        else
        {
            // Make the pattern relative under the search root
            pattern = Path.GetRelativePath(root, pattern);
        }

        // Ensure all slashes are correct for glob-pattern
        pattern = pattern.Replace('\\', '/');

        // Construct the glob matcher
        var matcher = new Matcher();
        matcher.AddInclude(pattern);

        // Run the search and return the results
        return matcher
            .GetResultsInFullPath(root)
            .ToArray();
    }
}