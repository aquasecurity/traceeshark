$wsVersionWanted = (Get-Content -Path "ws_version.txt" | Select-String -Pattern "\d+\.\d+\.\d+" -AllMatches).Matches.Value

if (Get-Command "wireshark" -ErrorAction SilentlyContinue) {
    $wsVersionExists = (wireshark --version | Select-String -Pattern "Wireshark \d+\.\d+\.\d+" -AllMatches).Matches.Value -replace 'Wireshark '

    if ($wsVersionWanted -ne $wsVersionExists) {
        $userInput = Read-Host "Plugins were compiled for Wireshark $wsVersionWanted but you have version $wsVersionExists, install plugins anyway? (y/n)"
        if ($userInput -ne "y" -and $userInput -ne "Y") {
            exit 1
        }
    }
} elseif (Get-Command "$env:Programfiles\Wireshark\Wiresharka.exe" -ErrorAction SilentlyContinue) {
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

New-Item -Path "$wsPersonalDir\plugins\$wsShortVersion\epan" -ItemType Directory -Force | Out-Null
Copy-Item "tracee-event.dll" "$wsPersonalDir\plugins\$wsShortVersion\epan" -Force
Copy-Item "tracee-network-capture.dll" "$wsPersonalDir\plugins\$wsShortVersion\epan" -Force

New-Item -Path "$wsPersonalDir\plugins\$wsShortVersion\wiretap" -ItemType Directory -Force | Out-Null
Copy-Item "tracee-json.dll" "$wsPersonalDir\plugins\$wsShortVersion\wiretap" -Force

New-Item -Path "$wsPersonalDir\profiles" -ItemType Directory -Force | Out-Null
Copy-Item -Path "profiles\Tracee" -Destination "$wsPersonalDir\profiles" -Recurse -Force