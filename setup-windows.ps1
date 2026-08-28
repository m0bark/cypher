Write-Host "== Cypher Windows setup ==" -ForegroundColor Cyan

if (-not (Test-Path ".venv\Scripts\python.exe")) {
  Write-Host "Creating virtual environment..."
  python -m venv .venv
}
& ".venv\Scripts\python.exe" -m pip install --upgrade pip | Out-Null
& ".venv\Scripts\python.exe" -m pip install -e ".[all]" | Out-Null
Write-Host "  [ok] Cypher installed (core + AI + phonenumbers)" -ForegroundColor Green

& ".venv\Scripts\python.exe" -m pip install --quiet pipx
& ".venv\Scripts\python.exe" -m pipx ensurepath | Out-Null
function PipxInstall($pkg, $label) {
  Write-Host "  installing $label ..."
  & ".venv\Scripts\python.exe" -m pipx install $pkg 2>$null | Out-Null
}
PipxInstall "sherlock-project" "sherlock"
PipxInstall "holehe"           "holehe"
PipxInstall "maigret"          "maigret"
PipxInstall "socialscan"       "socialscan"
PipxInstall "theHarvester"     "theHarvester"

if (Get-Command winget -ErrorAction SilentlyContinue) {
  Write-Host "  installing nmap (winget) ..."
  winget install --id Insecure.Nmap -e --silent --accept-source-agreements --accept-package-agreements 2>$null | Out-Null
} else {
  Write-Host "  [skip] winget not found - install nmap manually from nmap.org" -ForegroundColor Yellow
}

if (Get-Command go -ErrorAction SilentlyContinue) {
  Write-Host "  installing Go tools (subfinder, amass, httpx, nuclei, katana, gau, waybackurls, assetfinder) ..."
  $gotools = @(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "github.com/owasp-amass/amass/v4/...@master",
    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "github.com/lc/gau/v2/cmd/gau@latest",
    "github.com/tomnomnom/waybackurls@latest",
    "github.com/tomnomnom/assetfinder@latest"
  )
  foreach ($t in $gotools) { go install $t 2>$null }
  Write-Host "  Go tools install to `$env:USERPROFILE\go\bin - make sure that's on PATH." -ForegroundColor Yellow
} else {
  Write-Host "  [skip] Go not installed - subfinder/amass/httpx/nuclei/katana/gau unavailable." -ForegroundColor Yellow
  Write-Host "         Install Go from go.dev/dl to enable them." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done. Open a NEW terminal (for PATH), then:  .\.venv\Scripts\cypher.exe modules" -ForegroundColor Cyan
Write-Host "Launch the UI with:  .\run.bat" -ForegroundColor Cyan
Write-Host "Note: nikto/wpscan/wafw00f/dnsrecon/sslscan/rustscan remain Linux-only - use Kali for full coverage." -ForegroundColor DarkGray
