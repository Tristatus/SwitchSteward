"""Erzeugt fehlende lokale Laufzeitdateien bei der Erstinbetriebnahme."""

import ipaddress
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

if TYPE_CHECKING:
    from .config import Settings

logger = logging.getLogger("switchsteward.runtime_files")


def _exists(path: Path) -> bool:
    # Auch defekte Symlinks sind vorhandene, nicht zu ersetzende Dateien.
    return path.exists() or path.is_symlink()


def _create_known_hosts(path: Path | None, setting_name: str) -> None:
    if path is None or _exists(path):
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
    except FileExistsError:
        return
    except OSError as exc:
        raise RuntimeError(f"{setting_name} kann nicht angelegt werden: {path}: {exc}") from exc
    logger.warning(
        "%s wurde leer angelegt: %s. Vertrauenswürdige Host-Schlüssel müssen "
        "nach unabhängiger Prüfung manuell eingetragen werden; "
        "die strenge Host-Key-Prüfung bleibt aktiv, sofern konfiguriert.",
        setting_name,
        path,
    )


def _generate_tls_pair(settings: "Settings") -> None:
    cert_path, key_path = settings.tls_cert_file, settings.tls_key_file
    if not cert_path or not key_path:
        raise RuntimeError(
            "Für tls.generate_self_signed müssen tls.cert_file und tls.key_file konfiguriert sein."
        )
    if cert_path.resolve() == key_path.resolve():
        raise RuntimeError("tls.cert_file und tls.key_file müssen unterschiedliche Dateien sein.")
    cert_exists, key_exists = _exists(cert_path), _exists(key_path)
    if cert_exists and key_exists:
        return
    if cert_exists or key_exists:
        raise RuntimeError(
            "TLS-Zertifikat und privater Schlüssel sind unvollständig: "
            f"tls.cert_file={cert_path}, tls.key_file={key_path}. "
            "Das fehlende Gegenstück muss wiederhergestellt werden; "
            "vorhandene Dateien werden nicht ersetzt."
        )

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    names: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ]
    host = settings.server_host.strip().strip("[]")
    if host and "*" not in host:
        host_name = None
        try:
            address = ipaddress.ip_address(host)
            if not address.is_unspecified:
                host_name = x509.IPAddress(address)
        except ValueError:
            host_name = x509.DNSName(host.encode("idna").decode("ascii"))
        if host_name is not None and host_name not in names:
            names.append(host_name)
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    files = (
        (
            key_path,
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        ),
        (cert_path, certificate.public_bytes(serialization.Encoding.PEM)),
    )
    created: list[Path] = []
    try:
        for path, content in files:
            path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
    except OSError as exc:
        for path in created:
            path.unlink(missing_ok=True)
        raise RuntimeError(f"Selbstsignierte TLS-Dateien können nicht angelegt werden: {exc}") from exc
    logger.warning(
        "Selbstsigniertes TLS-Zertifikat für die Erstinbetriebnahme erzeugt: %s "
        "(365 Tage gültig). Für den regulären Betrieb ein vertrauenswürdiges "
        "Zertifikat für den verwendeten Servernamen konfigurieren.",
        cert_path,
    )


def prepare_runtime_files(settings: "Settings") -> None:
    """Ergänzt lokale Dateien, ohne Schlüssel oder Vertrauensanker zu ersetzen."""
    _create_known_hosts(settings.ssh_known_hosts_file, "ssh.known_hosts_file")
    if settings.wireless_netconf_strict_host_keys:
        _create_known_hosts(
            settings.wireless_netconf_known_hosts_file,
            "wireless.netconf_known_hosts_file",
        )
    if settings.tls_enabled and settings.tls_generate_self_signed:
        _generate_tls_pair(settings)
