![GitHub forks](https://img.shields.io/github/forks/demaconsulting/TransitiveSpdx?style=plastic)
![GitHub Repo stars](https://img.shields.io/github/stars/demaconsulting/TransitiveSpdx?style=plastic)
![GitHub contributors](https://img.shields.io/github/contributors/demaconsulting/TransitiveSpdx?style=plastic)
![GitHub](https://img.shields.io/github/license/demaconsulting/TransitiveSpdx?style=plastic)

# About

This utility enhances an SPDX SBOM with transitive dependency information
provided by other SBOMs.


# Usage

```
Usage: transitive-sbom [options]

Options:
  -v, --version                          Output the version
  -h, --help                             Display help
  -i, --input <sbom.spdx.json>           Input SPDX json file
  -o, --output <sbom.spdx.json>          Output SPDX json file
  -p, --path <glob-pattern>              Supplemental SBOM search path
  --mermaid                              Generate mermaid diagram
```


# Mermaid Diagrams

The mermaid option generates a mermaid "Mindmap" diagram of the package names.

```
mindmap
  INFUSION
    Windows Embedded Standard 7
       Net Frame Work
    Windows Embedded Standard 7 with SP1 patches
    SQL 2005 Express
    Java 8
      Tomcat 9
      Spring Framework
```

This can be processed by tools such as [mermaid-cli](https://github.com/mermaid-js/mermaid-cli)
into a diagram such as:

![Mermaid](https://raw.githubusercontent.com/demaconsulting/TransitiveSpdx/main/docs/mermaid.png)
