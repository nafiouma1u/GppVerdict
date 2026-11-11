"""Minimal wrapper around ADB."""
from __future__ import annotations

import re
import subprocess


class AdbError(RuntimeError):
    pass


def _list_devices(adb_path: str) -> list[tuple[str, str]]:
    try:
        out = subprocess.run([adb_path, "devices"], capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        raise AdbError(f"ADB not found ('{adb_path}'). Install Android Platform Tools "
                       "or pass the path with --adb.")
    devices = []
    for line in out.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            devices.append((parts[0], parts[1]))
    return devices


class Device:
    def __init__(self, serial: str | None = None, adb_path: str = "adb"):
        self.adb_path = adb_path
        devices = _list_devices(adb_path)
        if not devices:
            raise AdbError("No device detected. Check the cable and USB debugging.")
        if serial:
            match = [d for d in devices if d[0] == serial]
            if not match:
                raise AdbError(f"Device '{serial}' not found. Devices seen: {devices}")
            serial, state = match[0]
        else:
            ready = [d for d in devices if d[1] == "device"]
            if len(ready) > 1:
                raise AdbError("Several devices connected, specify --serial among: "
                               + ", ".join(d[0] for d in ready))
            serial, state = ready[0] if ready else devices[0]
        if state != "device":
            raise AdbError(f"Device '{serial}' in state '{state}'. If 'unauthorized', "
                           "accept the USB-debugging prompt on the phone.")
        self.serial = serial

    @property
    def base(self) -> list[str]:
        return [self.adb_path, "-s", self.serial]

    def run(self, args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
        return subprocess.run(self.base + list(args), capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)

    def shell(self, cmd: str, timeout: int = 60) -> str:
        return self.run(["shell", cmd], timeout).stdout.strip()

    # --- Info --------------------------------------------------------------
    def getprop(self, key: str) -> str:
        return self.shell(f"getprop {key}")

    def sdk_int(self) -> int:
        try:
            return int(self.getprop("ro.build.version.sdk"))
        except ValueError:
            return 0

    def package_version(self, pkg: str) -> str | None:
        out = self.shell(f"dumpsys package {pkg}", timeout=90)
        m = re.search(r"versionName=(\S+)", out)
        return m.group(1) if m else None

    def get_global(self, key: str) -> str:
        return self.shell(f"settings get global {key}")

    def put_global(self, key: str, value) -> bool:
        self.run(["shell", "settings", "put", "global", key, str(value)])
        return self.get_global(key) == str(value)

    def info(self) -> dict:
        return {
            "serial": self.serial,
            "manufacturer": self.getprop("ro.product.manufacturer"),
            "model": self.getprop("ro.product.model"),
            "android_version": self.getprop("ro.build.version.release"),
            "sdk_int": self.sdk_int(),
            "security_patch": self.getprop("ro.build.version.security_patch"),
            "gms_version": self.package_version("com.google.android.gms"),
            "play_store_version": self.package_version("com.android.vending"),
            "verifier_verify_adb_installs": self.get_global("verifier_verify_adb_installs"),
            "package_verifier_enable": self.get_global("package_verifier_enable"),
        }

    # --- Packages ----------------------------------------------------------
    def third_party_packages(self) -> set[str]:
        out = self.shell("pm list packages -3", timeout=90)
        return {l.split(":", 1)[1].strip() for l in out.splitlines() if l.startswith("package:")}

    def uninstall(self, pkg: str) -> bool:
        return "Success" in self.run(["uninstall", pkg], timeout=120).stdout

    def stay_awake(self) -> None:
        self.shell("svc power stayon usb")
