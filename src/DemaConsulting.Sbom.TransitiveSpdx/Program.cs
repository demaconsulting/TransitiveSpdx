using System.Reflection;
using DemaConsulting.Sbom.TransitiveSpdx.Spdx;

namespace DemaConsulting.Sbom.TransitiveSpdx;

/// <summary>
/// Program class
/// </summary>
public class Program
{
    /// <summary>
    /// Application entry point
    /// </summary>
    /// <param name="args">Program arguments</param>
    public static void Main(string[] args)
    {
        // Handle version query
        if (args.Contains("-v") || args.Contains("--version"))
        {
            Console.WriteLine(Version);
            Environment.Exit(0);
        }

        // Handle help query
        if (args.Length == 0 || args.Contains("-h") || args.Contains("--help"))
        {
            PrintUsage();
            Environment.Exit(0);
        }

        try
        {
            ParseArguments(
                args,
                out var input,
                out var output,
                out var paths,
                out var mermaid);

            // Construct the indexer
            var indexer = new SpdxIndexer();
            foreach (var path in paths)
                indexer.IndexFiles(path);

            // Load the document
            var doc = SpdxDocument.LoadJson(input);
            indexer.Populate(doc);
            doc.SaveJson(output);

            // Print the output
            Console.WriteLine($"Output written to {output}");

            // Handle mermaid output
            if (mermaid)
                PrintMermaid(doc);
        }
        catch (InvalidOperationException e)
        {
            // Print error message and terminate gracefully
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(e.Message);
            Console.ResetColor();
            Environment.Exit(1);
        }
        catch (Exception e)
        {
            // Print error message and die
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(e.Message);
            Console.ResetColor();
            throw;
        }
    }

    /// <summary>
    /// Print the usage
    /// </summary>
    public static void PrintUsage()
    {
        Console.WriteLine("Usage: transitive-sbom [options]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  -v, --version                          Output the version");
        Console.WriteLine("  -h, --help                             Display help");
        Console.WriteLine("  -i, --input <sbom.spdx.json>           Input SPDX json file");
        Console.WriteLine("  -o, --output <sbom.spdx.json>          Output SPDX json file");
        Console.WriteLine("  -p, --path <glob-pattern>              Supplemental SBOM search path");
        Console.WriteLine("  --mermaid                              Generate mermaid diagram");
    }

    /// <summary>
    /// Parse command-line arguments
    /// </summary>
    /// <param name="args">Arguments</param>
    /// <param name="input">Input file</param>
    /// <param name="output">Output file</param>
    /// <param name="paths">Search paths</param>
    /// <param name="mermaid">Mermaid flag</param>
    public static void ParseArguments(
        string[] args,
        out string input,
        out string output,
        out List<string> paths,
        out bool mermaid)
    {
        input = string.Empty;
        output = string.Empty;
        paths = new List<string>();
        mermaid = false;

        // Process the arguments
        for (var i = 0; i < args.Length;)
        {
            // Get the argument
            var arg = args[i++];
            switch (arg)
            {
                case "-i":
                case "--input":
                    // Sanity check argument
                    if (i >= args.Length)
                        throw new InvalidOperationException("Missing input file argument");

                    // Save the input file
                    input = args[i++];
                    break;

                case "-o":
                case "--output":
                    // Sanity check argument
                    if (i >= args.Length)
                        throw new InvalidOperationException("Missing output file argument");

                    // Save the output file
                    output = args[i++];
                    break;

                case "-p":
                case "--path":
                    // Sanity check argument
                    if (i >= args.Length)
                        throw new InvalidOperationException("Missing output file argument");

                    // Save the path
                    paths.Add(args[i++]);
                    break;

                case "--mermaid":
                    mermaid = true;
                    break;

                default:
                    // Unknown argument
                    throw new InvalidOperationException($"Unsupported argument {arg}");
            }
        }
    }

    /// <summary>
    /// Print mermaid output for document
    /// </summary>
    /// <param name="doc">SPDX document</param>
    static void PrintMermaid(SpdxDocument doc)
    {
        // Write the diagram header
        Console.WriteLine();
        Console.WriteLine("mindmap");

        // Write each root package
        foreach (var package in doc.GetDescribes())
            PrintMermaidPackage(2, package);

    }

    /// <summary>
    /// Print mermaid output for package
    /// </summary>
    /// <param name="depth">Nesting depth</param>
    /// <param name="package">Package</param>
    static void PrintMermaidPackage(int depth, SpdxPackage package)
    {
        // Get the package name
        var name = package.Name ?? "Anonymous";

        // Write the package entry
        Console.WriteLine($"{new string(' ', depth)}{name.Replace('.', ' ')}");

        // Recurse into dependent packages
        foreach (var dependent in package.FindDependentPackages())
            PrintMermaidPackage(depth + 2, dependent);

        // Recurse into contained packaged
        foreach (var contained in package.FindContainedPackages())
            PrintMermaidPackage(depth + 2, contained);
    }
    
    /// <summary>
    /// Version of the assembly containing this program
    /// </summary>
    public static string Version => typeof(Program)
        .Assembly
        .GetCustomAttributes()
        .OfType<AssemblyInformationalVersionAttribute>()
        .Select(v => v.InformationalVersion)
        .FirstOrDefault() ?? "Unknown Version";
}