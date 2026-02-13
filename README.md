# Look4Gold13

AU-13 Publicly Available Content (PAC) scanner for NIST SP 800-53 compliance.

Automates DuckDuckGo dorking across paste sites, code repos, and breach databases, then optionally summarizes findings with GenAI (Ask Sage or Grok).

## Quick Start

```powershell
# 1. Set up keywords
Copy-Item config/keywords.example.txt config/keywords.txt
# Edit keywords.txt with your organization-specific terms

# 2. Run a basic scan (last 30 days, DDG dorks only)
./Look4Gold13.ps1

# 3. Include breach/security-news dorks
./Look4Gold13.ps1 -IncludeBreach

# 4. Custom date range
./Look4Gold13.ps1 -DaysBack 90 -IncludeBreach
```

## Tips

**Reduce DuckDuckGo rate limiting:** Before running the script, open
<https://html.duckduckgo.com/html/> in a browser on the same machine.
Having an active browser session on that endpoint significantly reduces
CAPTCHA / rate-limit blocks during automated queries.

## Configuration

See [`config/README.txt`](config/README.txt) for full configuration instructions including GenAI setup, custom dork sources, and proxy settings.

## License

GNU General Public License v2.0 - see [LICENSE](LICENSE) for details.
