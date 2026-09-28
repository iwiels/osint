"""
SpecterOSINT - Cronolocalización (P1): acotar el instante de captura de una
foto a partir de su sombra, según la metodología de verificación de UGC del
Protocolo de Berkeley y las guías de geolocalización de Bellingcat.

Método (Python puro, sin dependencias):
  1. El objeto vertical de la escena actúa como gnomon: de la escena se mide
     la razón altura/sombra → elevación solar α = arctan(h / s), y el acimut
     del vector de sombra respecto al norte geográfico (la sombra apunta
     ALEJÁNDOSE del sol: acimut solar = acimut de sombra ± 180°).
  2. Con las coordenadas (EXIF GPS o geolocalización manual) y la fecha, se
     calcula la posición solar con el algoritmo de la NOAA, barriendo minuto
     a minuto el día UTC.
  3. Se devuelven en UTC las ventanas donde acimut y elevación son compatibles
     con lo observado (dentro de tolerancia).

Referencias: NOAA Global Monitoring Division, "General Solar Position
Calculations"; Meeus, "Astronomical Algorithms" (posicionamiento solar).
"""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta
from typing import Any

ACIMUT_TOLERANCE_DEG = 1.0
ELEVATION_TOLERANCE_DEG = 1.5
STEP_MINUTES = 1


def _julian_day(dt_utc: datetime) -> float:
    """Día juliano (fracción incluida) de un datetime UTC."""
    year, month = dt_utc.year, dt_utc.month
    day = dt_utc.day + (dt_utc.hour * 3600 + dt_utc.minute * 60 + dt_utc.second) / 86400.0
    if month <= 2:
        year -= 1
        month += 12
    a = year // 100
    b = 2 - a + a // 4
    return math.floor(365.25 * (year + 4716)) + math.floor(30.6001 * (month + 1)) + day + b - 1524.5


def _jd_from_unix(unix_seconds: float) -> float:
    return unix_seconds / 86400.0 + 2440587.5


def solar_position(latitude: float, longitude: float, when: datetime) -> dict[str, float]:
    """(elevación, acimut) solares en grados para un instante y lugar.

    `when` puede ser naive (se asume UTC) o aware. El acimut se devuelve
    0-360° desde el NORTE (convención de navegación/bellingcat), no la
    convención NOAA desde el sur.
    """
    when = when.replace(tzinfo=UTC) if when.tzinfo is None else when.astimezone(UTC)
    jd = _jd_from_unix(when.timestamp())
    jc = (jd - 2451545.0) / 36525.0

    # Geometría solar (NOAA)
    l0 = (280.46646 + jc * (36000.76983 + jc * 0.0003032)) % 360
    m = 357.52911 + jc * (35999.05029 - 0.0001537 * jc)
    center = (
        math.sin(math.radians(m)) * (1.914602 - jc * (0.004817 + 0.000014 * jc))
        + math.sin(math.radians(2 * m)) * (0.019993 - 0.000101 * jc)
        + math.sin(math.radians(3 * m)) * 0.000289
    )
    true_long = l0 + center
    omega = 125.04 - 1934.136 * jc
    lambda_app = true_long - 0.00569 - 0.00478 * math.sin(math.radians(omega))
    seconds = 21.448 - jc * (46.8150 + jc * (0.00059 - jc * 0.001813))
    e0 = 23.0 + (26.0 + seconds / 60.0) / 60.0
    e0 += 0.00256 * math.cos(math.radians(omega))
    declination = math.degrees(
        math.asin(math.sin(math.radians(e0)) * math.sin(math.radians(lambda_app)))
    )

    # Ecuación del tiempo (minutos) y minuto solar verdadero
    y = math.tan(math.radians(e0 / 2.0)) ** 2
    eq_time = 4.0 * math.degrees(
        y * math.sin(2 * math.radians(l0))
        - 2 * 0.016708634 * math.sin(math.radians(m))
        + 4 * 0.016708634 * y * math.sin(math.radians(m)) * math.cos(2 * math.radians(l0))
        - 0.5 * y * y * math.sin(4 * math.radians(l0))
        - 1.25 * 0.016708634 * 0.016708634 * math.sin(2 * math.radians(m))
    )
    minutes_utc = when.hour * 60.0 + when.minute + when.second / 60.0
    true_solar_time = (minutes_utc + eq_time + 4.0 * longitude) % 1440.0
    # Ángulo horario (NOAA: 0 = mediodía solar, negativo mañana)
    ha = true_solar_time / 4.0 - 180.0
    if ha < -180:
        ha += 360

    lat_rad = math.radians(latitude)
    decl_rad = math.radians(declination)
    ha_rad = math.radians(ha)

    cos_zenith = math.sin(lat_rad) * math.sin(decl_rad) + math.cos(lat_rad) * math.cos(
        decl_rad
    ) * math.cos(ha_rad)
    cos_zenith = max(-1.0, min(1.0, cos_zenith))
    zenith = math.degrees(math.acos(cos_zenith))
    elevation = 90.0 - zenith

    # Acimut desde el norte vía sistema horizontal estándar (atan2):
    #   sin(A) = -sin(HA)*cos(dec) / sin(zenith)
    #   cos(A) = (sin(dec) - sin(lat)*cos(zenith)) / (cos(lat)*sin(zenith))
    sin_zenith = math.sin(math.radians(zenith))
    if sin_zenith < 1e-10:
        azimuth_north = 0.0  # sol en el cenit: acimut indefinido
    else:
        sin_a = -math.sin(ha_rad) * math.cos(decl_rad) / sin_zenith
        cos_a = (math.sin(decl_rad) - math.sin(lat_rad) * cos_zenith) / (
            math.cos(lat_rad) * sin_zenith
        )
        sin_a = max(-1.0, min(1.0, sin_a))
        cos_a = max(-1.0, min(1.0, cos_a))
        azimuth_north = math.degrees(math.atan2(sin_a, cos_a)) % 360.0

    return {
        "elevation": round(elevation, 3),
        "azimuth": round(azimuth_north, 3),
        "declination": round(declination, 3),
        "eq_time_min": round(eq_time, 3),
    }


def shadow_to_solar_elevation(shadow_length: float, object_height: float) -> float:
    """Elevación solar α = arctan(h / s) desde la sombra (gnomon)."""
    if shadow_length <= 0 or object_height <= 0:
        raise ValueError("Sombra y altura deben ser positivas")
    return math.degrees(math.atan(object_height / shadow_length))


def _brute_force_day(
    latitude: float, longitude: float, day: datetime, step_minutes: int
) -> list[dict[str, Any]]:
    """Posiciones solares del día UTC (step fijo), de 00:00 a 24:00 UTC."""
    day = day.replace(tzinfo=UTC) if day.tzinfo is None else day.astimezone(UTC)
    base = day.replace(hour=0, minute=0, second=0, microsecond=0, tzinfo=UTC)
    positions: list[dict[str, Any]] = []
    for offset in range(0, 24 * 60, max(1, step_minutes)):
        moment = base + timedelta(minutes=offset)
        pos = solar_position(latitude, longitude, moment)
        positions.append({"utc": moment, **pos})
    return positions


def estimate_capture_window(
    latitude: float,
    longitude: float,
    day: datetime,
    *,
    shadow_azimuth_deg: float | None = None,
    solar_elevation_deg: float | None = None,
    shadow_length: float | None = None,
    object_height: float | None = None,
    tolerance_azimuth: float = ACIMUT_TOLERANCE_DEG,
    tolerance_elevation: float = ELEVATION_TOLERANCE_DEG,
    step_minutes: int = STEP_MINUTES,
) -> dict[str, Any]:
    """Acota la hora de captura cruzando sombra observada y efemérides solares.

    Acepta la elevación ya calculada (`solar_elevation_deg`), o la pareja
    `shadow_length`/`object_height` (se computa arctan). El acimut de sombra
    se convierte a acimut solar (+180°). Devuelve ventanas contiguas de
    minutos UTC compatibles. El analista aplica el offset local del sitio.
    """
    if solar_elevation_deg is None:
        if shadow_length is None or object_height is None:
            raise ValueError("Se requiere solar_elevation_deg o shadow_length+object_height")
        solar_elevation_deg = shadow_to_solar_elevation(shadow_length, object_height)

    solar_azimuth_deg = None
    if shadow_azimuth_deg is not None:
        solar_azimuth_deg = (float(shadow_azimuth_deg) + 180.0) % 360.0

    day_utc = day.replace(tzinfo=UTC) if day.tzinfo is None else day.astimezone(UTC)
    positions = _brute_force_day(latitude, longitude, day_utc, step_minutes)

    def _matches(pos: dict[str, Any]) -> bool:
        if pos["elevation"] <= 0:
            return False
        if abs(pos["elevation"] - float(solar_elevation_deg)) > tolerance_elevation:
            return False
        if solar_azimuth_deg is not None:
            delta = abs((pos["azimuth"] - solar_azimuth_deg + 180.0) % 360.0 - 180.0)
            if delta > tolerance_azimuth:
                return False
        return True

    # Agrupar minutos contiguos en ventanas.
    windows: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    for pos in positions:
        if _matches(pos):
            current.append(pos)
        elif current:
            windows.append(current)
            current = []
    if current:
        windows.append(current)

    # La salida se mantiene en UTC; el analista aplica la zona horaria del sitio.
    windows_out = [
        {
            "start_utc": w[0]["utc"].isoformat(),
            "end_utc": w[-1]["utc"].isoformat(),
            "minutes": len(w),
            "elevation_at_mid": w[len(w) // 2]["elevation"],
            "azimuth_at_mid": w[len(w) // 2]["azimuth"],
        }
        for w in windows
    ]
    return {
        "location": {"latitude": latitude, "longitude": longitude},
        "day_utc": day_utc.date().isoformat(),
        "observed": {
            "solar_elevation_deg": round(float(solar_elevation_deg), 2),
            "solar_azimuth_deg": round(solar_azimuth_deg, 2)
            if solar_azimuth_deg is not None
            else None,
        },
        "tolerances": {"azimuth_deg": tolerance_azimuth, "elevation_deg": tolerance_elevation},
        "windows": windows_out,
        "window_count": len(windows_out),
        "note": (
            "Los tiempos son UTC: el analista debe aplicar el offset horario local "
            "del sitio (incluido DST) para la cronología del suceso."
        ),
    }
