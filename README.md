# Look4Gold13 - AU-13 Compliance Tool

A PowerShell toolkit for monitoring and maintaining compliance with **NIST SP 800-53 AU-13 (Monitoring for Information Disclosure)**.

AU-13 requires organizations to monitor open-source information and publicly accessible sites for evidence of unauthorized disclosure of organizational information.

## Project Structure

```
Look4Gold13/
├── src/
│   ├── Look4Gold13.psm1        # Root module
│   ├── Public/                  # Exported functions
│   └── Private/                 # Internal helper functions
├── tests/                       # Pester tests
├── config/                      # Configuration templates
└── docs/                        # Documentation
```

## Getting Started

```powershell
Import-Module ./src/Look4Gold13.psm1
```

## Requirements

- PowerShell 7.0+
- Pester 5.x (for tests)
