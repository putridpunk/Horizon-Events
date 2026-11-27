"""Where in the world is an IP address? Answered from a MaxMind-format database file (GeoLite2 or similar) that the
user provides. The lookup is done on this computer: no address is ever sent anywhere.

The database is not bundled (its licence requires an account with the publisher). Without one, every lookup answers
"unknown" and the location rules stay silent."""
from __future__ import annotations

import ipaddress
import math
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

MAX_DB_BYTES = 500 * 1024 * 1024


class GeoError(ValueError):
    """A database that cannot be used; the message is shown to the user."""


@dataclass(frozen=True)
class Location:
    country_code: str | None = None
    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None

    @property
    def has_coordinates(self) -> bool:
        return self.latitude is not None and self.longitude is not None

    def label(self) -> str:
        return ", ".join(p for p in (self.city, self.country or self.country_code) if p) or "an unknown place"

    def as_dict(self) -> dict:
        return {"country_code": self.country_code, "country": self.country, "city": self.city,
                "latitude": self.latitude, "longitude": self.longitude}


def haversine_km(a: Location, b: Location) -> float:
    """Great-circle distance between two locations that have coordinates."""
    lat1, lon1, lat2, lon2 = map(math.radians, (a.latitude, a.longitude, b.latitude, b.longitude))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(h))


def _name(block) -> str | None:
    names = (block or {}).get("names") or {}
    return names.get("en") or next(iter(names.values()), None)


def parse_record(record: dict | None) -> Location | None:
    if not record:
        return None
    country = record.get("country") or record.get("registered_country") or {}
    place = record.get("location") or {}
    loc = Location(country_code=country.get("iso_code"), country=_name(country), city=_name(record.get("city")),
                   latitude=place.get("latitude"), longitude=place.get("longitude"))
    return loc if (loc.country_code or loc.has_coordinates) else None


class GeoLocator:
    """Wraps anything with a `get(ip) -> dict | None` method (a maxminddb reader, or a fake in tests)."""

    def __init__(self, reader, info: dict | None = None):
        self._reader, self.info = reader, info or {}
        self._lookup = lru_cache(maxsize=8192)(self._raw_lookup)

    @classmethod
    def open(cls, path: str) -> "GeoLocator":
        file = Path(path)
        if file.suffix.lower() != ".mmdb" or not file.is_absolute():
            raise GeoError("Choose the full path of a .mmdb file, for example the GeoLite2-City.mmdb you downloaded.")
        try:
            size = file.stat().st_size if file.is_file() else None
        except OSError:
            size = None
        if size is None:
            raise GeoError("That file was not found.")
        if size > MAX_DB_BYTES:
            raise GeoError("That file is larger than 500 MB, which is too big for a location database.")
        try:
            import maxminddb
        except ImportError:  # the optional reader is not installed
            raise GeoError("The maxminddb package is not installed, so location databases cannot be read.") from None
        try:
            reader = maxminddb.open_database(str(file))
        except (maxminddb.InvalidDatabaseError, ValueError, OSError):
            raise GeoError("That file is not a location database (.mmdb).") from None
        meta = reader.metadata()
        return cls(reader, {"type": meta.database_type, "built": meta.build_epoch})

    def _raw_lookup(self, ip: str) -> Location | None:
        try:
            return parse_record(self._reader.get(ip))
        except (ValueError, OSError, TypeError):
            return None

    def lookup(self, ip: str | None) -> Location | None:
        """The place an address is registered to, or None for private, malformed or unknown addresses."""
        try:
            if not ip or not ipaddress.ip_address(ip.strip()).is_global:
                return None
        except ValueError:
            return None
        return self._lookup(ip.strip())

    def close(self) -> None:
        close = getattr(self._reader, "close", None)
        if close:
            close()


_lock = threading.Lock()
_locator: GeoLocator | None = None


def get_locator() -> GeoLocator | None:
    return _locator


def set_locator(locator: GeoLocator | None) -> None:
    global _locator
    with _lock:
        old, _locator = _locator, locator
    if old is not None and old is not locator:
        old.close()


def locate(ip: str | None) -> Location | None:
    locator = _locator
    return locator.lookup(ip) if locator else None
