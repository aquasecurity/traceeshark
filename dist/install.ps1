function Version-LessThan {
    param (
        [string]$version1,
        [string]$version2
    )

    $version1Parts = $version1.Split('.')
    $version2Parts = $version2.Split('.')

    $major1 = [int]$version1Parts[0]
    $minor1 = [int]$version1Parts[1]

    $major2 = [int]$version2Parts[0]
    $minor2 = [int]$version2Parts[1]

    if ($major1 -lt $major2 -or ($major1 -eq $major2 -and $minor1 -lt $minor2)) {
        return $true
    }
    else {
        return $false
    }
}

$wsVersionWanted = (Get-Content -Path "ws_version.txt" | Select-String -Pattern "\d+\.\d+\.\d+" -AllMatches).Matches.Value

if (Get-Command "wireshark" -ErrorAction SilentlyContinue) {
    $wsVersionExists = (wireshark --version | Select-String -Pattern "Wireshark \d+\.\d+\.\d+" -AllMatches).Matches.Value -replace 'Wireshark '

    if ($wsVersionWanted -ne $wsVersionExists) {
        $userInput = Read-Host "Plugins were compiled for Wireshark $wsVersionWanted but you have version $wsVersionExists, install plugins anyway? (y/n)"
        if ($userInput -ne "y" -and $userInput -ne "Y") {
            exit 1
        }
    }
} elseif (Get-Command "$env:ProgramFiles\Wireshark\Wireshark.exe" -ErrorAction SilentlyContinue) {
    $wsPath = Join-Path -Path $env:ProgramFiles -ChildPath "Wireshark\Wireshark.exe"
    $wsVersionExists = (& $wsPath --version | Select-String -Pattern "Wireshark \d+\.\d+\.\d+" -AllMatches).Matches.Value -replace 'Wireshark '

    if ($wsVersionWanted -ne $wsVersionExists) {
        $userInput = Read-Host "Plugins were compiled for Wireshark $wsVersionWanted but you have version $wsVersionExists, install plugins anyway? (y/n)"
        if ($userInput -ne "y" -and $userInput -ne "Y") {
            exit 1
        }
    }
} else {
    $userInput = Read-Host "Wireshark installation not found, install plugins anyway? (y/n)"
    if ($userInput -ne "y" -and $userInput -ne "Y") {
        exit 1
    }
}

$wsVersionParts = $wsVersionExists -split '\.'
$wsShortVersion = $wsVersionParts[0] + '.' + $wsVersionParts[1]


$wsPersonalDir = "$env:APPDATA\Wireshark"

New-Item -Path "$wsPersonalDir\profiles" -ItemType Directory -Force | Out-Null
Copy-Item -Path "profiles\Tracee" -Destination "$wsPersonalDir\profiles" -Recurse -Force
Write-Output "[*] Installed profile to $wsPersonalDir\profiles\Tracee"

if (Version-LessThan -version1 $wsShortVersion -version2 "4.3") {
    $wsPluginsDir = "$wsPersonalDir\plugins\$wsShortVersion"
}
else {
    $wsPluginsDir = "$wsPersonalDir\plugins"
}

New-Item -Path "$wsPluginsDir\epan" -ItemType Directory -Force | Out-Null
Copy-Item "tracee-event.dll" "$wsPluginsDir\epan" -Force
Copy-Item "tracee-network-capture.dll" "$wsPluginsDir\epan" -Force
New-Item -Path "$wsPluginsDir\wiretap" -ItemType Directory -Force | Out-Null
Copy-Item "tracee-json.dll" "$wsPluginsDir\wiretap" -Force
Write-Output "[*] Installed plugins to $wsPluginsDir"

Copy-Item -Path "extcap" -Destination "$wsPersonalDir" -Recurse -Force
Write-Output "[*] Installed extcap to $wsPersonalDir\extcap"