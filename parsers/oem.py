import logging
import re
from pathlib import Path

from parsers.base import load_records, normalize_date
from parsers.csvjson import convert_csv_to_json

logger = logging.getLogger(__name__)

JSON_FILES = [
    ("pixel_devices.json", "Google"),
    ("motorola_devices.json", "Motorola"),
    ("samsung_devices.json", "Samsung"),
    ("oppo_devices.json", "OPPO"),
    ("vivo_devices.json", "Vivo"),
    ("xiaomi_phones.json", "Xiaomi"),
]

# Static metadata mapping for major Android releases to populate android_version table
ANDROID_METADATA = {
    "Android 4.0": {"api_level": 14, "release_date": "2011-10-18"},
    "Android 4.1": {"api_level": 16, "release_date": "2012-07-09"},
    "Android 4.2": {"api_level": 17, "release_date": "2012-11-13"},
    "Android 4.3": {"api_level": 18, "release_date": "2013-07-24"},
    "Android 4.4": {"api_level": 19, "release_date": "2013-10-31"},
    "Android 5.0": {"api_level": 21, "release_date": "2014-11-12"},
    "Android 5.1": {"api_level": 22, "release_date": "2015-03-09"},
    "Android 6.0": {"api_level": 23, "release_date": "2015-10-05"},
    "Android 7.0": {"api_level": 24, "release_date": "2016-08-22"},
    "Android 7.1": {"api_level": 25, "release_date": "2016-10-04"},
    "Android 8.0": {"api_level": 26, "release_date": "2017-08-21"},
    "Android 8.1": {"api_level": 27, "release_date": "2017-12-05"},
    "Android 9": {"api_level": 28, "release_date": "2018-08-06"},
    "Android 10": {"api_level": 29, "release_date": "2019-09-03"},
    "Android 11": {"api_level": 30, "release_date": "2020-09-08"},
    "Android 12": {"api_level": 31, "release_date": "2021-10-04"},
    "Android 13": {"api_level": 33, "release_date": "2022-08-15"},
    "Android 14": {"api_level": 34, "release_date": "2023-10-04"},
    "Android 15": {"api_level": 35, "release_date": "2024-09-03"},
    "Android 16": {"api_level": 36, "release_date": "2025-06-03"},
    "Android 17": {"api_level": 37, "release_date": "2026-06-16"},
}


def _slugify(name: str) -> str:
    return re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')


def _guess_chipset_vendor(chipset_name: str) -> str:
    lower = chipset_name.lower()
    if "snapdragon" in lower or "qualcomm" in lower:
        return "Qualcomm"
    if "helio" in lower or "mediatek" in lower or "dimensity" in lower or "mt6" in lower or "mt8" in lower:
        return "MediaTek"
    if "exynos" in lower:
        return "Samsung"
    if "tensor" in lower:
        return "Google"
    if "unisoc" in lower:
        return "Unisoc"
    if "xring" in lower:
        return "Xiaomi"
    return "Unknown"


def _extract_android_versions(os_string: str) -> list[dict]:
    """Parse distinct Android versions from strings like 'Android 11-12' or 'Android 15 (Go)'."""
    if not os_string:
        return []
    versions = []
    # Find any numeric patterns like 'Android 15' or 'Android 8.1'
    matches = re.findall(r'Android\s*(\d+(?:\.\d+)?)', os_string, re.IGNORECASE)
    for num in matches:
        version_name = f"Android {num}"
        # Fallback to major version if decimal part is 0, e.g. Android 9.0 -> Android 9
        if version_name.endswith(".0"):
            version_name = version_name[:-2]
        
        if version_name in ANDROID_METADATA:
            meta = ANDROID_METADATA[version_name]
            versions.append({
                "version_name": version_name,
                "api_level": meta["api_level"],
                "release_date": meta["release_date"]
            })
    return versions


def prepare(data_dir: Path) -> dict[str, list[dict]]:
    # Check if JSON files exist; if not, trigger the conversion
    missing = False
    for filename, _ in JSON_FILES:
        if not (data_dir / filename).exists():
            missing = True
            break

    if missing:
        logger.info("JSON device files missing. Running CSV-to-JSON conversion...")
        try:
            convert_csv_to_json()
        except Exception as e:
            logger.error("Failed to convert CSV to JSON: %s", e)

    devices: list[dict] = []
    chipsets: dict[str, dict] = {}
    vendors: dict[str, dict] = {}
    android_versions: dict[str, dict] = {}

    def clean_and_normalize(raw_date):
        if not raw_date:
            return None
        s = str(raw_date).replace("Available.", "").strip()
        return normalize_date(s)

    for filename, brand_name in JSON_FILES:
        filepath = data_dir / filename
        records = load_records(filepath)
        if not records:
            continue

        for r in records:
            # Handle headers across different OEM formats
            name = (r.get("device_name") or r.get("device") or "").strip()
            if not name:
                continue

            brand = (r.get("brand") or brand_name).strip()
            chipset = r.get("chipset", "").strip()
            
            # Map OS versions
            launch_os = (r.get("base_os") or r.get("base_android_os") or r.get("Base OS") or "").strip()
            current_os = (r.get("current_os") or r.get("current_android_os") or r.get("curent_available_os") or "").strip()
            
            # Extract android_version metadata
            for v in _extract_android_versions(launch_os) + _extract_android_versions(current_os):
                android_versions[v["version_name"]] = v

            # User interface
            ui = (r.get("current_user_interface") or r.get("User Interface") or "").strip() or None
            
            # Release Date
            release_date_str = r.get("release_date") or r.get("official_release_date")
            launch_date = clean_and_normalize(release_date_str)
            
            devices.append({
                "name": name,
                "codename": _slugify(name),
                "model_number": None,
                "device_type": r.get("device_type", "Phone").strip(),
                "launch_os": launch_os,
                "current_os": current_os,
                "launch_user_interface": None,
                "current_user_interface": ui,
                "source": r.get("source", "").strip() or None,
                "region": None,
                "launch_date": launch_date,
                "eol_date": None,
                "is_flagship": None,
                "vendor_name": brand,
                "chipset_name": chipset,
            })
            
            if brand not in vendors:
                vendors[brand] = {"name": brand, "country": None, "security_bulletin_url": None}
            
            if chipset and chipset not in chipsets:
                chipsets[chipset] = {
                    "name": chipset,
                    "vendor": _guess_chipset_vendor(chipset),
                    "model_number": None,
                    "chipset_family": None,
                    "release_date": None,
                }

    result = {}
    if devices:
        result["device"] = devices
    if chipsets:
        result["chipset"] = list(chipsets.values())
    if vendors:
        result["vendor"] = list(vendors.values())
    if android_versions:
        result["android_version"] = list(android_versions.values())

    logger.info(
        "OEM Parser: %d devices, %d chipsets, %d vendors, %d android versions parsed",
        len(devices), len(chipsets), len(vendors), len(android_versions)
    )
    return result
