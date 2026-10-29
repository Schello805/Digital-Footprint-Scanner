import io
from typing import Dict, Any, Optional, Tuple
from PIL import Image, ExifTags

def _convert_to_degrees(value) -> Optional[float]:
    """Helper function to convert the GPS coordinates stored in the EXIF to degrees in float format"""
    if not value:
        return None
    try:
        # Value can be a tuple of IFDRational or tuple of floats
        d = float(value[0])
        m = float(value[1])
        s = float(value[2])
        return d + (m / 60.0) + (s / 3600.0)
    except Exception:
        return None

def extract_exif_metadata(image_bytes: bytes, filename: str = "") -> Dict[str, Any]:
    try:
        image = Image.open(io.BytesIO(image_bytes))
    except Exception as e:
        return {
            "success": False,
            "error": f"Ungültige Bilddatei oder Dateiformat wird nicht unterstützt: {str(e)}"
        }

    info = {
        "filename": filename,
        "format": image.format,
        "size": {
            "width": image.width,
            "height": image.height
        },
        "mode": image.mode,
        "has_exif": False,
        "metadata": {},
        "gps": None,
        "risk_level": "LOW", # LOW, MEDIUM, HIGH, CRITICAL
        "risk_reasons": []
    }

    exif_data = None
    try:
        exif_data = image.getexif()
    except Exception:
        pass

    if not exif_data:
        info["risk_reasons"].append("Keine EXIF-Metadaten vorhanden (Bild ist anonymisiert oder bereinigt).")
        return {"success": True, "data": info}

    info["has_exif"] = True

    # Standard EXIF tags
    raw_tags = {}
    for tag_id, val in exif_data.items():
        tag_name = ExifTags.TAGS.get(tag_id, f"Tag_{tag_id}")
        raw_tags[tag_name] = str(val)

    # Check GPS IFD specifically
    gps_info = {}
    gps_coords = None
    
    # In Pillow, GPS IFD is tag 0x8825 (34853)
    gps_ifd = exif_data.get_ifd(0x8825) if hasattr(exif_data, "get_ifd") else None
    if not gps_ifd and 34853 in exif_data:
        gps_ifd = exif_data[34853]

    if gps_ifd:
        for k, v in gps_ifd.items():
            sub_tag = ExifTags.GPSTAGS.get(k, f"GPS_{k}")
            gps_info[sub_tag] = v

        lat_val = gps_info.get("GPSLatitude")
        lat_ref = gps_info.get("GPSLatitudeRef", "N")
        lon_val = gps_info.get("GPSLongitude")
        lon_ref = gps_info.get("GPSLongitudeRef", "E")

        lat_deg = _convert_to_degrees(lat_val)
        lon_deg = _convert_to_degrees(lon_val)

        if lat_deg is not None and lon_deg is not None:
            if lat_ref == "S":
                lat_deg = -lat_deg
            if lon_ref == "W":
                lon_deg = -lon_deg

            altitude = gps_info.get("GPSAltitude")
            alt_float = float(altitude) if altitude is not None else None

            gps_coords = {
                "latitude": round(lat_deg, 6),
                "longitude": round(lon_deg, 6),
                "altitude_m": round(alt_float, 1) if alt_float else None,
                "google_maps_url": f"https://www.google.com/maps?q={lat_deg},{lon_deg}",
                "osm_url": f"https://www.openstreetmap.org/?mlat={lat_deg}&mlon={lon_deg}#map=16/{lat_deg}/{lon_deg}"
            }
            info["gps"] = gps_coords

    # Filter out binary or very long raw tags for human display
    display_metadata = {}
    critical_fields = ["Make", "Model", "Software", "DateTime", "DateTimeOriginal", "Artist", "Copyright", "LensModel", "SerialNumber"]
    
    for k, v in raw_tags.items():
        if len(str(v)) < 150:
            display_metadata[k] = v

    info["metadata"] = display_metadata

    # Calculate Privacy Risk Assessment
    if info["gps"]:
        info["risk_level"] = "CRITICAL"
        info["risk_reasons"].append(f"Exakte GPS-Standortkoordinaten gefunden ({info['gps']['latitude']}, {info['gps']['longitude']}). Verrät Wohnort, Aufenthaltsort oder Reiseroute.")

    if any(k in display_metadata for k in ["Make", "Model"]):
        device = f"{display_metadata.get('Make', '')} {display_metadata.get('Model', '')}".strip()
        info["risk_reasons"].append(f"Gerätemodell identifizierbar: {device}")
        if info["risk_level"] == "LOW":
            info["risk_level"] = "MEDIUM"

    if any(k in display_metadata for k in ["DateTime", "DateTimeOriginal"]):
        date_str = display_metadata.get("DateTimeOriginal") or display_metadata.get("DateTime")
        info["risk_reasons"].append(f"Präziser Aufnahmezeitstempel vorhanden: {date_str}")
        if info["risk_level"] == "LOW":
            info["risk_level"] = "MEDIUM"

    if any(k in display_metadata for k in ["Artist", "Copyright", "SerialNumber"]):
        info["risk_reasons"].append("Persönliche Identifikatoren oder Seriennummern gefunden.")
        if info["risk_level"] in ["LOW", "MEDIUM"]:
            info["risk_level"] = "HIGH"

    if not info["risk_reasons"]:
        info["risk_reasons"].append("Keine sensiblen Daten entdeckt. Bild ist sauber.")

    return {"success": True, "data": info}


def strip_exif_metadata(image_bytes: bytes) -> Tuple[bytes, str]:
    """
    Strips all metadata from the image and returns clean image bytes.
    """
    image = Image.open(io.BytesIO(image_bytes))
    
    # Create a fresh image with identical pixel data but zero metadata
    data = list(image.getdata())
    clean_image = Image.new(image.mode, image.size)
    clean_image.putdata(data)
    
    output = io.BytesIO()
    fmt = image.format or "JPEG"
    if fmt.upper() in ["JPEG", "JPG"]:
        clean_image.save(output, format="JPEG", quality=95)
    elif fmt.upper() == "PNG":
        clean_image.save(output, format="PNG")
    elif fmt.upper() == "WEBP":
        clean_image.save(output, format="WEBP", quality=95)
    else:
        clean_image.save(output, format="JPEG", quality=95)
        fmt = "JPEG"
        
    return output.getvalue(), fmt.lower()
