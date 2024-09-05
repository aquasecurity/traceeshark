#!/usr/bin/env python3

import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from typing import Any, Dict, Optional, Tuple
import urllib.request
import zipfile


def get_system_info() -> Tuple[str, str]:
    if sys.platform.startswith("linux"):
        os_ = "linux"
    elif os.name == "nt":
        os_ = "windows"
    elif sys.platform == "darwin":
        os_ = "darwin"
    else:
        raise ValueError(f"incompatible platform {sys.platform}")
    
    if platform.machine() in ["AMD64", "x86_64"]:
        arch = "x86_64"
    elif platform.machine() in ["arm64", "aarch64"]:
        arch = platform.machine()
    else:
        raise ValueError(f"incompatible architecture {platform.machine()}")
    
    return os_, arch


def get_wireshark_version_output(os_: str, wireshark_path: Optional[str] = None) -> Optional[str]:
    ws_path = wireshark_path or "wireshark" # Try running Wireshark from PATH

    try:
        output = subprocess.check_output([ws_path, "--version"]).decode()
    except FileNotFoundError:
        if os_ == "windows" and wireshark_path is None:
            ws_path = os.path.join(os.getenv("ProgramFiles"), "Wireshark", "Wireshark.exe")
            output = get_wireshark_version_output(os_, ws_path)
        else:
            output = None
    
    return output


def get_wireshark_version(os_: str) -> Optional[str]:
    output = get_wireshark_version_output(os_)
    if output is None:
        return None
    
    return re.search(r"^Wireshark (\d\.\d\.\d)", output).group(1)


def get_latest_release_info() -> Dict[Any, Any]:
    url = "https://api.github.com/repos/aquasecurity/traceeshark/releases/latest"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    if len(sys.argv) == 2:
        headers["Authorization"] = f"Bearer {sys.argv[1]}"
    
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def is_candidate_asset(asset: str, os_: str, arch: str) -> bool:
    parts = asset.split("-")

    # Check OS
    if os_ != parts[2]:
        return False
    
    # Check arch
    if arch != parts[3]:
        return False
    
    return True


def release_wireshark_version(release_name: str) -> str:
    return release_name.removesuffix(".zip").split("-")[5]


def prompt_selected_asset(assets: Dict[str, str], wireshark_version: Optional[str]) -> Optional[str]:
    if wireshark_version is None:
        print("Traceeshark autoinstall was unable to find your Wireshark installation.")
        print('To find your Wireshark version, open Wireshark and on the main window you shoud see "You are running Wireshark x.y.z".')
    elif len(assets) > 1:
        print(f"Your installed Wireshark version ({wireshark_version}) did not match any of the available releases.")
    else:
        print(f"Your installed Wireshark version ({wireshark_version}) did not match the release's version ({release_wireshark_version(list(assets.keys())[0])}).")
    
    if len(assets) == 1:
        print(f"Do you wish to install the release for Wireshark version {release_wireshark_version(list(assets.keys())[0])}? (Y/n): ", end="")
        if input().lower() == "y":
            return list(assets.keys())[0]
        else:
            return None
    
    print("Traceeshark releases were found for the following Wireshark versions. Please select which one to install:")
    asset_names = list(assets.keys())
    for i, asset in enumerate(asset_names):
        print(f"{i+1}. {release_wireshark_version(asset)}")
    print(f"{i+2}. Abort")

    answer = input("\n>>> ")
    try:
        answer = int(answer)
        if answer <= 0 or answer > i+2:
            raise ValueError()
    except ValueError:
        print(f"Invalid input {answer}, aborting.")
        return None
    
    # Abort
    if answer == i+2:
        return None
    return asset_names[answer-1]


def download_asset(asset_id: str, file_name: str):
    url = f"https://api.github.com/repos/aquasecurity/traceeshark/releases/assets/{asset_id}"
    headers = {
        "Accept": "application/octet-stream"
    }
    if len(sys.argv) == 2:
        headers["Authorization"] = f"Bearer {sys.argv[1]}"
    
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req) as resp:
        with open(file_name, "wb") as f:
            f.write(resp.read())


def run_install_script(os_: str, release_dir: str):
    if os_ in ["linux", "darwin"]:
        install_script = os.path.join(release_dir, "install.sh")
        os.chmod(install_script, os.stat(install_script).st_mode | stat.S_IEXEC)
        subprocess.run(["./install.sh"], cwd=release_dir)
    else:
        subprocess.run(["powershell", "-executionpolicy", "bypass", "-File", "install.ps1"], cwd=release_dir)


def main():
    os_, arch = get_system_info()
    ws_version = get_wireshark_version(os_)
    latest_release = get_latest_release_info()

    assets = {asset["name"]: asset["id"] for asset in latest_release["assets"] if is_candidate_asset(asset["name"], os_, arch)}

    if len(assets) == 0:
        print("No releases exist for your system. Please open an issue and request a release to be added, or build Traceeshark from source.")
        return
    
    selected_asset = None
    if ws_version is not None:
        for asset in assets.keys():
            if release_wireshark_version(asset) == ws_version:
                selected_asset = asset
    if selected_asset is None:
        selected_asset = prompt_selected_asset(assets, ws_version)
        if selected_asset is None:
            return
    
    print(f"Downloading {selected_asset} ...")
    download_asset(assets[selected_asset], selected_asset)

    print(f"Extracting {selected_asset} ...")
    release_dir = selected_asset.removesuffix(".zip")
    os.makedirs(release_dir, exist_ok=True)
    with zipfile.ZipFile(selected_asset, "r") as zip:
        zip.extractall(release_dir)
    
    print(f"Running install script...")
    run_install_script(os_, release_dir)

    print(f"Cleaning up...")
    shutil.rmtree(release_dir)
    os.remove(selected_asset)

if __name__ == "__main__":
    main()
