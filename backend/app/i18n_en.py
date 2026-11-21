"""English translations for backend messages; keys are the German message IDs."""

MESSAGES: dict[str, str] = {
    # Switch drivers, capabilities, model catalog
    "Unbekannter Gerätetyp.": "Unknown device type.",
    "Das Modell gehört nicht zum gewählten Gerätetyp.": "The model does not belong to the selected device type.",
    "Es wurde keine Änderung angegeben.": "No change was specified.",
    "Speed und Duplex müssen gemeinsam gesetzt werden.": "Speed and duplex must be set together.",
    "Unbekannter Gerätetyp – bitte im Bearbeiten-Dialog einen unterstützten Typ wählen.":
        "Unknown device type – please choose a supported type in the edit dialog.",
    "Diese Funktion wird vom Treiber nicht unterstützt.": "This function is not supported by the driver.",
    "Das Modell {model} hat keine PoE-Ports.": "The model {model} has no PoE ports.",
    "Das Modell ist nicht bekannt; PoE-Leistungsprofile bleiben gesperrt.":
        "The model is unknown; PoE power profiles remain locked.",
    "Der Wert {value} wird von diesem Gerät nicht unterstützt.": "The value {value} is not supported by this device.",
    "Dieses Interface stellt kein PoE bereit.": "This interface does not provide PoE.",
    "Die PoE-Unterstuetzung dieses Interfaces konnte nicht bestaetigt werden.":
        "PoE support of this interface could not be confirmed.",
    # Authentication and administration
    "Nicht angemeldet": "Not signed in",
    "Administratorrechte erforderlich": "Administrator rights required",
    "Ungültiger CSRF-Token": "Invalid CSRF token",
    "Ungültige Eingabe.": "Invalid input.",
    "Steuerzeichen und Zeilenumbrüche sind nicht erlaubt.": "Control characters and line breaks are not allowed.",
    "Der Anmeldeweg, über den Sie angemeldet sind, kann nicht deaktiviert werden.":
        "The sign-in method you are currently signed in with cannot be disabled.",
    "Ein neues Client-Secret und das Entfernen des Secrets schließen sich aus.":
        "A new client secret and removing the secret are mutually exclusive.",
    "Anmeldung erfolgreich.": "Sign-in successful.",
    "Anmeldung erfolgreich, aber keine Rolle zugeordnet.": "Sign-in successful, but no role is assigned.",
    "Tenant-ID und Client-ID müssen GUIDs sein.": "Tenant ID and client ID must be GUIDs.",
    "Benutzer nicht gefunden.": "User not found.",
    "Das eigene Konto kann nicht gelöscht werden.": "You cannot delete your own account.",
    "AD-Gruppen werden als Distinguished Name (CN=…,DC=…) angegeben.":
        "AD groups are specified as distinguished name (CN=…,DC=…).",
    "Eine Zuordnung benötigt eine Rolle.": "A mapping needs a role.",
    "Benutzername oder Passwort falsch.": "Incorrect username or password.",
    "Entra-ID-Konfiguration erfolgreich geladen.": "Entra ID configuration loaded successfully.",
    "Der Benutzername darf nur Buchstaben, Ziffern und . _ @ - enthalten (1–64 Zeichen).":
        "The username may only contain letters, digits and . _ @ - (1–64 characters).",
    "Ein lokaler Benutzer mit diesem Namen existiert bereits.": "A local user with this name already exists.",
    "Lokale Benutzer benötigen eine Rolle.": "Local users need a role.",
    "Passwörter können nur für lokale Benutzer gesetzt werden.": "Passwords can only be set for local users.",
    "Der Status muss aktiv oder gesperrt sein.": "The status must be active or disabled.",
    "Das eigene Konto kann nicht gesperrt werden.": "You cannot disable your own account.",
    "Die eigene Administratorrolle kann nicht entzogen werden.": "You cannot remove your own administrator role.",
    "Ungültige Gruppenkennung.": "Invalid group identifier.",
    "Entra-ID-Gruppen werden mit ihrer Objekt-ID (GUID) angegeben.":
        "Entra ID groups are specified by their object ID (GUID).",
    "Diese Gruppe ist bereits zugeordnet.": "This group is already mapped.",
    "Zuordnung nicht gefunden.": "Mapping not found.",
    "Die Entra-ID-Konfiguration konnte nicht geladen werden.": "The Entra ID configuration could not be loaded.",
    "Die Änderung würde den letzten Administratorzugang entfernen.":
        "The change would remove the last administrator access.",
    "Active Directory ist deaktiviert.": "Active Directory is disabled.",
    "Mindestens ein AD-Server muss konfiguriert sein.": "At least one AD server must be configured.",
    "AD-Verzeichnissuche fehlgeschlagen.": "AD directory search failed.",
    "AD-Benutzeridentität ist nicht eindeutig.": "The AD user identity is ambiguous.",
    "AD-Benutzeridentität konnte nicht aufgelöst werden.": "The AD user identity could not be resolved.",
    "AD-Anmeldedienst ist nicht erreichbar.": "The AD sign-in service is unreachable.",
    "AD-Anmeldedienst hat die Bind-Anfrage nicht verarbeitet.": "The AD sign-in service did not process the bind request.",
    "AD-Anmeldedienst hat die erneute Bind-Anfrage nicht verarbeitet.":
        "The AD sign-in service did not process the second bind request.",
    "AD-Gruppenprüfung fehlgeschlagen.": "AD group check failed.",
    "Das Passwort muss 12 bis 1024 Zeichen lang sein.": "The password must be 12 to 1024 characters long.",
    "Das Passwort darf keine Steuerzeichen enthalten.": "The password must not contain control characters.",
    "Benutzername darf nicht leer sein.": "Username must not be empty.",
    "Anmeldedienst ist nicht verfügbar.": "The sign-in service is not available.",
    "Weiter zu SwitchSteward": "Continue to SwitchSteward",
    "Die öffentliche Adresse muss eine https://-URL (http:// nur für localhost) ohne Pfad, "
    "Query oder abschließenden Schrägstrich sein.":
        "The public address must be an https:// URL (http:// only for localhost) without path, query or "
        "trailing slash.",
    "AD-Server müssen als ldap://host[:port] oder ldaps://host[:port] angegeben werden.":
        "AD servers must be given as ldap://host[:port] or ldaps://host[:port].",
    "AD-Server-URLs dürfen keine Zugangsdaten, Pfade, Querys oder Fragmente enthalten.":
        "AD server URLs must not contain credentials, paths, queries or fragments.",
    "Ungültiger Port in der AD-Server-URL.": "Invalid port in the AD server URL.",
    "Die angegebene AD-CA-Datei existiert nicht.": "The specified AD CA file does not exist.",
    "Für Entra ID muss die öffentliche Adresse (public_base_url) gesetzt sein.":
        "Entra ID requires the public address (public_base_url) to be set.",
    "Ungültige AD-Server-URL.": "Invalid AD server URL.",
    "AD-Server, Domain und Base-DN müssen gesetzt sein.": "AD servers, domain and base DN must be set.",
    "Unverschlüsseltes LDAP ist deaktiviert. LDAPS verwenden oder die unsichere Ausnahme explizit aktivieren.":
        "Unencrypted LDAP is disabled. Use LDAPS or explicitly enable the insecure exception.",
    "LDAPS-Zertifikatsprüfung darf nur mit expliziter unsicherer Ausnahme deaktiviert werden.":
        "LDAPS certificate validation may only be disabled with an explicit insecure exception.",
    "Für Entra ID muss ein Client-Secret hinterlegt sein.": "Entra ID requires a stored client secret.",
    "AD-Server-URLs dürfen höchstens 1024 Zeichen lang sein.": "AD server URLs must not exceed 1024 characters.",
    "Zu viele fehlgeschlagene Anmeldungen. Bitte später erneut versuchen.":
        "Too many failed sign-in attempts. Please try again later.",
    # VLAN tab (switches/vlans.py, service, Cisco driver)
    "Ungültiger VLAN-Name: 1–32 Zeichen, erlaubt sind Buchstaben, Ziffern, Punkt, Unterstrich und Bindestrich "
    "(nicht nur Ziffern).":
        "Invalid VLAN name: 1–32 characters; letters, digits, dot, underscore and hyphen are allowed (not only digits).",
    "Standard-VLAN des Switches; kann nicht gelöscht werden.": "Default VLAN of the switch; it cannot be deleted.",
    "Reserviertes VLAN; kann nicht gelöscht werden.": "Reserved VLAN; it cannot be deleted.",
    "Primary VLAN des Switches; kann nicht gelöscht werden.": "Primary VLAN of the switch; it cannot be deleted.",
    "Management-VLAN des Switches; kann nicht gelöscht werden.": "Management VLAN of the switch; it cannot be deleted.",
    "Automatisch erzeugtes VLAN (PVID oder VLAN-Interface); kann nicht gelöscht werden.":
        "Automatically created VLAN (PVID or VLAN interface); it cannot be deleted.",
    "Für dieses VLAN existiert ein Layer-3-Interface; Löschen ist gesperrt.":
        "A layer 3 interface exists for this VLAN; deleting is blocked.",
    "Layer-3-Interfaces konnten nicht gelesen werden; Löschen ist gesperrt.":
        "Layer 3 interfaces could not be read; deleting is blocked.",
    "Das VLAN wird noch von Ports verwendet: {ports}": "The VLAN is still used by ports: {ports}",
    "Die VLAN-Konfiguration von {ports} konnte nicht gelesen werden; Löschen ist gesperrt.":
        "The VLAN configuration of {ports} could not be read; deleting is blocked.",
    "VLAN {vlan} angelegt (noch nicht dauerhaft gespeichert).": "VLAN {vlan} created (not yet saved permanently).",
    "VLAN {vlan} angelegt.": "VLAN {vlan} created.",
    "VLAN {vlan} umbenannt (noch nicht dauerhaft gespeichert).": "VLAN {vlan} renamed (not yet saved permanently).",
    "VLAN {vlan} umbenannt.": "VLAN {vlan} renamed.",
    "VLAN {vlan} gelöscht (noch nicht dauerhaft gespeichert).": "VLAN {vlan} deleted (not yet saved permanently).",
    "VLAN {vlan} gelöscht.": "VLAN {vlan} deleted.",
    "Der Switch hat keinen Fehler gemeldet, die VLAN-Änderung ist aber nicht sichtbar.":
        "The switch reported no error, but the VLAN change is not visible.",
    "VLAN-ID außerhalb des gültigen Bereichs 1-{max}: {value}": "VLAN ID outside the valid range 1-{max}: {value}",
    "VLAN {vlan} existiert bereits.": "VLAN {vlan} already exists.",
    "Die maximale Anzahl von {count} VLANs ist erreicht.": "The maximum number of {count} VLANs has been reached.",
    # Shared driver messages (all new drivers)
    "VLAN {vlan} existiert auf dem Switch nicht.": "VLAN {vlan} does not exist on the switch.",
    "Bei Speed auto muss Duplex auto sein.": "With speed auto, duplex must be auto.",
    "Bei fester Geschwindigkeit muss Duplex half oder full sein.": "With a fixed speed, duplex must be half or full.",
    "1000 Mbit/s ist nur mit Vollduplex möglich.": "1000 Mbit/s is only possible with full duplex.",
    "Interface-Konfiguration übernommen (noch nicht dauerhaft gespeichert)":
        "Interface configuration applied (not yet saved permanently)",
    "Der Switch hat Teile der Konfiguration abgelehnt: {errors}": "The switch rejected parts of the configuration: {errors}",
    "Der Switch hat den Befehl abgelehnt: {errors}": "The switch rejected the command: {errors}",
    "Port {interface} wurde eingeschaltet (noch nicht dauerhaft gespeichert)":
        "Port {interface} was enabled (not yet saved permanently)",
    "Port {interface} wurde ausgeschaltet (noch nicht dauerhaft gespeichert)":
        "Port {interface} was disabled (not yet saved permanently)",
    "Konfiguration gespeichert": "Configuration saved",
    "Konfiguration konnte nicht gespeichert werden: {errors}": "Configuration could not be saved: {errors}",
    "Der Switch hat das Speichern der Konfiguration nicht bestätigt.":
        "The switch did not confirm saving the configuration.",
    "Ungültiger Interface-Name: {interface}": "Invalid interface name: {interface}",
    "Verbindung erfolgreich, Prompt: {prompt}": "Connection successful, prompt: {prompt}",
    "Authentifizierung fehlgeschlagen (Benutzername/Passwort prüfen)":
        "Authentication failed (check username/password)",
    "Zeitüberschreitung - Switch nicht erreichbar (IP/Port/Firewall prüfen)":
        "Timeout - switch not reachable (check IP/port/firewall)",
    "SSH-Verbindung fehlgeschlagen. Server-Log prüfen.": "SSH connection failed. Check the server log.",
    "Der Switch hat für '{command}' keine Ausgabe geliefert.": "The switch returned no output for '{command}'.",
    "Der Switch hat den Lesebefehl '{command}' abgelehnt: {errors}":
        "The switch rejected the read command '{command}': {errors}",
    "Die Ausgabe von '{command}' hat ein unbekanntes Format.": "The output of '{command}' has an unknown format.",
    "PoE-Daten konnten nicht gelesen werden; PoE-Status unbekannt.":
        "PoE data could not be read; PoE state unknown.",
    "Das PoE-Gesamtbudget ist nicht verfügbar.": "The total PoE budget is not available.",
    "'{command}' lief in ein Zeitlimit; weitere Abfragen dieser Sitzung entfallen.":
        "'{command}' timed out; further queries in this session are skipped.",
    "'{command}' ist fehlgeschlagen; die Daten können unvollständig sein.":
        "'{command}' failed; the data may be incomplete.",
    "Nachbarn konnten nicht gelesen werden.": "Neighbors could not be read.",
    "Herstellerangabe (nicht an Hardware verifiziert): {model}": "Vendor naming (not verified on hardware): {model}",
    # aruba_aoscx
    "AOS-CX bietet keine PoE-Leistungsgrenze je Port in Watt.": "AOS-CX offers no per-port PoE power limit in watts.",
    "Mindestens eine relevante Zeile der MAC-Tabelle hatte ein unbekanntes Format; "
    "die Client-Erkennung kann unvollständig sein.":
        "At least one relevant line of the MAC table had an unknown format; client detection may be incomplete.",
    "Für den Wechsel in den Access-Modus ist ein Access VLAN erforderlich.":
        "Switching to access mode requires an access VLAN.",
    "Für den Wechsel in den Trunk-Modus ist ein Native VLAN erforderlich.":
        "Switching to trunk mode requires a native VLAN.",
    "Der Portmodus ist unbekannt; bitte Access oder Trunk ausdrücklich wählen.":
        "The port mode is unknown; please choose access or trunk explicitly.",
    "PoE hängt von den eingesetzten Line-Cards ab.": "PoE depends on the installed line cards.",
    # mikrotik_routeros
    "RouterOS übernimmt Änderungen sofort dauerhaft.": "RouterOS applies changes permanently right away.",
    "RouterOS meldet kein PoE-Gesamtbudget.": "RouterOS does not report a total PoE budget.",
    "RouterOS kennt kein Voice-VLAN.": "RouterOS has no voice VLAN.",
    "PoE-Leistungsprofile werden für RouterOS nicht unterstützt.": "PoE power profiles are not supported for RouterOS.",
    "Der Port ist keiner Bridge zugeordnet.": "The port is not a member of a bridge.",
    "Auf der Bridge ist die VLAN-Filterung (vlan-filtering) nicht aktiviert.":
        "VLAN filtering (vlan-filtering) is not enabled on the bridge.",
    "Speed/Duplex-Einstellungen erfordern RouterOS 7.12 oder neuer.": "Speed/duplex settings require RouterOS 7.12 or newer.",
    "Die RouterOS-Version ist unbekannt; Speed/Duplex bleiben gesperrt.":
        "The RouterOS version is unknown; speed/duplex remain locked.",
    "Der Switch hat einen Eintrag ohne gültige .id geliefert.": "The switch returned an entry without a valid .id.",
    "Die Antwort des Switches überschreitet die zulässige Größe.": "The switch response exceeds the permitted size.",
    "REST-Verbindung zum Switch fehlgeschlagen ({error}). Adresse, Port und TLS-Zertifikat prüfen.":
        "REST connection to the switch failed ({error}). Check address, port and TLS certificate.",
    "Dem REST-Benutzer fehlt die Berechtigung für {path}.": "The REST user lacks permission for {path}.",
    "Der Switch hat die Anfrage abgelehnt: {detail}": "The switch rejected the request: {detail}",
    "Der Switch hat die REST-Anfrage {path} mit HTTP {status} beantwortet.":
        "The switch answered the REST request {path} with HTTP {status}.",
    "Der Switch hat keine gültige JSON-Antwort geliefert ({path}).": "The switch did not return valid JSON ({path}).",
    "Der Switch hat für {path} keine lesbaren Daten geliefert.": "The switch returned no readable data for {path}.",
    "Interface {interface} ist kein Ethernet-Interface dieses Switches.":
        "Interface {interface} is not an Ethernet interface of this switch.",
    "REST-Verbindung fehlgeschlagen. Server-Log prüfen.": "REST connection failed. Check the server log.",
    "Verbindung erfolgreich: {name} (RouterOS {version})": "Connection successful: {name} (RouterOS {version})",
    "Die PoE-Messwerte konnten nicht gelesen werden.": "The PoE measurements could not be read.",
    "{label} konnte nicht gelesen werden; die Client-Daten können unvollständig sein.":
        "{label} could not be read; the client data may be incomplete.",
    "Die ARP-Tabelle": "The ARP table",
    "Die Nachbarliste": "The neighbor list",
    "Erlaubte VLANs können nur für Trunk-Ports gesetzt werden.": "Allowed VLANs can only be set on trunk ports.",
    "Der VLAN-Eintrag {ids} umfasst mehrere VLANs; bitte auf dem Gerät aufteilen.":
        "The VLAN entry {ids} covers several VLANs; please split it on the device.",
    "VLANs können nur angelegt werden, wenn genau eine Bridge mit VLAN-Filterung existiert.":
        "VLANs can only be created when exactly one bridge with VLAN filtering exists.",
    "Der Name kann nur für VLANs mit genau einem eigenen statischen Bridge-Eintrag gesetzt werden.":
        "The name can only be set for VLANs with exactly one dedicated static bridge entry.",
    "Interface {interface} unterstützt kein PoE.": "Interface {interface} does not support PoE.",
    "Interface-Konfiguration übernommen (RouterOS speichert sofort dauerhaft).":
        "Interface configuration applied (RouterOS saves it permanently right away).",
    "Port {interface} wurde eingeschaltet.": "Port {interface} was enabled.",
    "Port {interface} wurde ausgeschaltet.": "Port {interface} was disabled.",
    # netgear_prosafe
    "Die Description darf keine Anführungszeichen enthalten.": "The description must not contain double quotes.",
    "Für den Access-Modus wird ein Access-VLAN benötigt.": "Access mode needs an access VLAN.",
    "Der VLAN-Modus von Interface {interface} ist nicht eindeutig (General-Modus); bitte den Modus mit angeben.":
        "The VLAN mode of interface {interface} is ambiguous (general mode); please specify the mode as well.",
    "Switchport-Details wurden nur für {count} Ports gelesen.": "Switchport details were only read for {count} ports.",
    "Die ARP-Tabelle ist auf diesem Switch nicht verfügbar (Routing deaktiviert?); IP-Adressen fehlen.":
        "The ARP table is not available on this switch (routing disabled?); IP addresses are missing.",
    # aruba_osswitch
    "PoE-Leistungsprofile werden für AOS-S nicht unterstützt.": "PoE power profiles are not supported for AOS-S.",
    "Der Port ist Mitglied einer Link-Aggregation (Trk); VLANs und Edge-Port werden an der "
    "Trk-Schnittstelle konfiguriert.":
        "The port is a member of a link aggregation (Trk); VLANs and edge port are configured on the Trk interface.",
    "Der Manager-Modus (enable) konnte nicht aktiviert werden. Enable-Zugangsdaten prüfen.":
        "Manager mode (enable) could not be entered. Check the enable credentials.",
    "Interface {interface} existiert auf dem Switch nicht.": "Interface {interface} does not exist on the switch.",
    "Mehr als {limit} Ports mit LLDP-Nachbarn; Details werden nur für die ersten {limit} Ports gelesen.":
        "More than {limit} ports with LLDP neighbors; details are only read for the first {limit} ports.",
    "Mehr als {limit} VLANs; die MAC-Tabelle wird nur für die ersten {limit} VLANs gelesen.":
        "More than {limit} VLANs; the MAC table is only read for the first {limit} VLANs.",
    "Die MAC-Adresstabelle konnte nicht gelesen werden.": "The MAC address table could not be read.",
    "Ein Access-VLAN kann nur im Access-Modus gesetzt werden.": "An access VLAN can only be set in access mode.",
    "Native-VLAN und erlaubte VLANs können nur im Trunk-Modus gesetzt werden.":
        "Native VLAN and allowed VLANs can only be set in trunk mode.",
    "PoE hängt von den eingesetzten Modulen ab.": "PoE depends on the installed modules.",
    # setup.py, config.py, updates.py, system_routes.py, application.py, security.py
    "Host muss eine IP-Adresse oder ein DNS-Name ohne URL/Port sein.":
        "Host must be an IP address or DNS name without URL or port.",
    "Der Datenbankpfad existiert bereits. Für die Ersteinrichtung eine neue Datei wählen.":
        "The database path already exists. Choose a new file for the initial setup.",
    "Der Verschlüsselungsschlüssel fehlt in der Konfiguration.": "The encryption key is missing from the configuration.",
    "Der vorhandene Session-Schlüssel muss mindestens 32 Byte lang sein.":
        "The existing session key must be at least 32 bytes long.",
    "Die Datenbank benötigt einen eigenen Pfad, getrennt von Host-Schlüsseln und TLS-Dateien.":
        "The database needs its own path, separate from host key and TLS files.",
    "SSH-Benutzername und Passwort müssen gemeinsam angegeben werden.":
        "SSH username and password must be given together.",
    "Ein Enable-Passwort benötigt SSH-Zugangsdaten.": "An enable password requires SSH credentials.",
    "Für HTTPS müssen Zertifikat und privater Schlüssel angegeben werden.":
        "HTTPS requires a certificate and a private key.",
    "TLS-Zertifikat und Schlüssel müssen vorhandene Dateien sein.": "TLS certificate and key must be existing files.",
    "Im konfigurierten Frontend-Verzeichnis fehlt {asset}.": "The configured frontend directory lacks {asset}.",
    "Ungültiges Einrichtungstoken. Die Seite neu laden.": "Invalid setup token. Reload the page.",
    "Für einen Reverse Proxy ist die öffentliche HTTPS-Adresse erforderlich.":
        "A reverse proxy requires the public HTTPS address.",
    "Die öffentliche Adresse muss eine HTTPS-URL ohne Pfad oder Zugangsdaten sein.":
        "The public address must be an HTTPS URL without path or credentials.",
    "Die Anfrage enthält kein gültiges JSON.": "The request does not contain valid JSON.",
    "Die Ersteinrichtung wurde bereits abgeschlossen.": "The initial setup has already been completed.",
    "Die Ersteinrichtung ist nur auf diesem Rechner erreichbar.": "The initial setup is only reachable on this computer.",
    "Unzulässiger Anfrage-Ursprung.": "Request origin not allowed.",
    "Die Einrichtung konnte nicht gespeichert werden: {error}": "The setup could not be saved: {error}",
    "Der Einrichtungsstatus kann nicht gelesen werden.": "The setup status cannot be read.",
    "Die Anfrage ist zu groß.": "The request is too large.",
    "Konfigurationsdatei nicht gefunden: {path}. Der konfigurierte Pfad muss eine JSON-Datei sein.":
        "Configuration file not found: {path}. The configured path must be a JSON file.",
    "Konfigurationsdatei kann nicht gelesen werden: {path}: {error}": "Configuration file cannot be read: {path}: {error}",
    "Die Konfigurationsdatei muss ein JSON-Objekt enthalten.": "The configuration file must contain a JSON object.",
    "Konfigurationseintrag fehlt: {path}": "Configuration entry missing: {path}",
    "Konfigurationsabschnitt für {path} muss ein JSON-Objekt sein.":
        "The configuration section for {path} must be a JSON object.",
    "{path} muss eine Zeichenkette oder null sein.": "{path} must be a string or null.",
    "{path} muss eine Zeichenkette sein.": "{path} must be a string.",
    "{path} darf nicht leer sein.": "{path} must not be empty.",
    "{path} muss true oder false sein.": "{path} must be true or false.",
    "{path} muss eine ganze Zahl sein.": "{path} must be an integer.",
    "{path} muss zwischen {minimum} und {maximum} liegen.": "{path} must be between {minimum} and {maximum}.",
    "{path} muss einen der folgenden Werte haben: {choices}.": "{path} must have one of the following values: {choices}.",
    "application.frontend_dir ist kein lesbares Verzeichnis: {path}":
        "application.frontend_dir is not a readable directory: {path}",
    "{name} verweist auf keine lesbare Datei: {path}": "{name} does not point to a readable file: {path}",
    "Bei server.tls.enabled=true müssen cert_file und key_file gesetzt sein.":
        "With server.tls.enabled=true, cert_file and key_file must be set.",
    "Ungültiger Archivpfad. Bitte das gebaute SwitchSteward Release-Archiv verwenden.":
        "Invalid archive path. Please use the built SwitchSteward release archive.",
    "Das Archiv enthält einen reservierten Dateipfad.": "The archive contains a reserved file path.",
    "Nicht erlaubte Release-Datei: {path}": "Release file not allowed: {path}",
    "Das entpackte tar-Archiv überschreitet die Größenbegrenzung.": "The unpacked tar archive exceeds the size limit.",
    "Updates sind bei verlinkten Anwendungsdateien nicht möglich.": "Updates are not possible with linked application files.",
    "Ein Update-Pfad liegt außerhalb der Installation.": "An update path lies outside the installation.",
    "Ungültiges Update-Arbeitsverzeichnis.": "Invalid update working directory.",
    "Ein Update wird bereits verarbeitet.": "An update is already being processed.",
    "Der Update-Status ist beschädigt. Das Verzeichnis .updates prüfen.":
        "The update state is corrupted. Check the .updates directory.",
    "Das Archiv enthält doppelte Dateipfade.": "The archive contains duplicate file paths.",
    "Das entpackte Release überschreitet die Größenbegrenzung.": "The unpacked release exceeds the size limit.",
    "Ungültige Dateigröße im Archiv.": "Invalid file size in the archive.",
    "Das Release-Archiv ist unvollständig.": "The release archive is incomplete.",
    "Ungültiges ZIP-Verzeichnis.": "Invalid ZIP directory.",
    "Das ZIP-Archiv enthält zu viele Dateien oder verwendet ein nicht unterstütztes Format.":
        "The ZIP archive contains too many files or uses an unsupported format.",
    "Das Release darf nur reguläre, unverschlüsselte Dateien enthalten.":
        "The release may only contain regular, unencrypted files.",
    "Das Release darf keine Links oder Spezialdateien enthalten.": "The release must not contain links or special files.",
    "Ungültiges oder beschädigtes ZIP-/tar.gz-Release-Archiv.": "Invalid or corrupted ZIP/tar.gz release archive.",
    "Unvollständiges Release: {files}": "Incomplete release: {files}",
    "Python-Datei ist mit dieser Python-Version nicht kompatibel: {name}":
        "Python file is not compatible with this Python version: {name}",
    "Web-Updates benötigen einen Start über backend/start.sh, start.ps1 oder python -m app.run.":
        "Web updates require starting via backend/start.sh, start.ps1 or python -m app.run.",
    "Das Release-Archiv darf maximal 50 MiB groß sein.": "The release archive may be at most 50 MiB.",
    "Eine Installation läuft bereits.": "An installation is already running.",
    "Für ein Update werden mindestens 250 MiB freier Speicher benötigt.":
        "An update requires at least 250 MiB of free disk space.",
    "Das Release enthält keine gültige VERSION.": "The release does not contain a valid VERSION.",
    "Diese Version ist bereits installiert.": "This version is already installed.",
    "Der Server unterstützt keinen automatischen Neustart; bitte app.run verwenden.":
        "The server does not support automatic restarts; please use app.run.",
    "Dieses Release ist nicht mehr zur Installation vorgemerkt. Erneut hochladen.":
        "This release is no longer staged for installation. Upload it again.",
    "Ungültige Update-ID.": "Invalid update ID.",
    "Ungültige Update-Dateiliste.": "Invalid update file list.",
    "Die vorgemerkten Release-Dateien wurden verändert. Erneut hochladen.":
        "The staged release files were modified. Upload again.",
    "Web-Updates benötigen das frontend-Verzeichnis dieser Installation; die Konfiguration verweist auf ein "
    "anderes Verzeichnis.":
        "Web updates require the frontend directory of this installation; the configuration points to a "
        "different directory.",
    "Eine konfigurierte Laufzeitdatei liegt in einem vom Update verwalteten Pfad. Speicherort vor dem Update ändern.":
        "A configured runtime file lies in a path managed by the update. Change its location before updating.",
    "Die virtuelle Update-Umgebung fehlt; .updates/python.json prüfen.":
        "The virtual update environment is missing; check .updates/python.json.",
    "Abhängigkeiten oder Startprüfung fehlgeschlagen; Details stehen in .updates/update.log.":
        "Dependencies or startup check failed; details are in .updates/update.log.",
    "Ungültige Wiederherstellungs-ID.": "Invalid restore ID.",
    "Ungültige Wiederherstellungsdatei.": "Invalid restore file.",
    "Die Update-Sicherung ist unvollständig. Manuelle Wiederherstellung erforderlich.":
        "The update backup is incomplete. Manual restore required.",
    "Eine Anwendungsdatei ist kein regulärer Dateipfad.": "An application file is not a regular file path.",
    "Release installiert und Startprüfung erfolgreich. Server wird neu gestartet.":
        "Release installed and startup check successful. Server is restarting.",
    "Update fehlgeschlagen; bisherige Version wurde beibehalten. Details: .updates/update.log.":
        "Update failed; the previous version was kept. Details: .updates/update.log.",
    "Unterbrochenes Update: bisherige Version wurde wiederhergestellt.":
        "Interrupted update: the previous version was restored.",
    "Das Release-Archiv muss als ZIP- oder tar.gz-Datei hochgeladen werden.":
        "The release archive must be uploaded as a ZIP or tar.gz file.",
    "Update-Archiv fehlt.": "Update archive missing.",
    "Interner Fehler (Request-ID {request_id}).": "Internal error (request ID {request_id}).",
    "Ungültiger Content-Length-Header.": "Invalid Content-Length header.",
    "Anfrage ist zu groß.": "Request is too large.",
    "Update-Archiv ist zu groß.": "Update archive is too large.",
    # wlan/adapters (base.py, catalyst_9800.py, catalyst_9800_netconf.py, netconf_config.py)
    "Dieser Controlleradapter unterstützt keine Konfigurationsänderungen.":
        "This controller adapter does not support configuration changes.",
    "Gerätekonfiguration steht für diesen Transport nicht zur Verfügung. NETCONF verwenden.":
        "Device configuration is not available for this transport. Use NETCONF.",
    "Die RESTCONF-Antwort enthält nicht den erwarteten YANG-Schlüssel {subtree}.":
        "The RESTCONF response does not contain the expected YANG key {subtree}.",
    "Der YANG-Schlüssel {subtree} enthält keine gültige Liste.":
        "The YANG key {subtree} does not contain a valid list.",
    "Die YANG-Antwort enthält keine Access-Point-Daten.":
        "The YANG response contains no access point data.",
    "{count} CAPWAP-Datensätze konnten nicht eindeutig zugeordnet werden.":
        "{count} CAPWAP records could not be matched unambiguously.",
    "{count} optionale AP-Datensätze gehörten zu keinem aktuellen CAPWAP-AP.":
        "{count} optional AP records did not belong to any current CAPWAP AP.",
    "{count} Radio-Datensätze besaßen keine gültige Slot-ID.":
        "{count} radio records had no valid slot ID.",
    "Die YANG-Antwort enthält keine Client-Daten.":
        "The YANG response contains no client data.",
    "{count} Common-Client-Datensätze enthielten keine gültige MAC-Adresse.":
        "{count} common client records contained no valid MAC address.",
    "{count} optionale Client-Datensätze gehörten zu keinem aktuell verbundenen Client.":
        "{count} optional client records did not belong to any currently connected client.",
    "Der WLAN-Controller hat keine gültige YANG-JSON-Antwort geliefert.":
        "The wireless controller did not return a valid YANG JSON response.",
    "Die RESTCONF-JSON-Struktur überschreitet das Sicherheitslimit.":
        "The RESTCONF JSON structure exceeds the safety limit.",
    "Access Point {name} besitzt im YANG-Datensatz keinen Namen.":
        "Access point {name} has no name in the YANG record.",
    "Für den WLAN-Controller ist kein Host konfiguriert.":
        "No host is configured for the wireless controller.",
    "Der konfigurierte WLAN-Controller-Host ist ungültig.":
        "The configured wireless controller host is invalid.",
    "Der WLAN-Controller-Host darf weder Schema, Pfad noch Zugangsdaten enthalten.":
        "The wireless controller host must not contain a scheme, path or credentials.",
    "Der RESTCONF-Port muss zwischen 1 und 65535 liegen.":
        "The RESTCONF port must be between 1 and 65535.",
    "Für den WLAN-Controller sind keine vollständigen Zugangsdaten hinterlegt.":
        "No complete credentials are stored for the wireless controller.",
    "Die Zugangsdaten des WLAN-Controllers konnten nicht entschlüsselt werden.":
        "The wireless controller credentials could not be decrypted.",
    "Die konfigurierte CA-Datei für RESTCONF ist nicht lesbar.":
        "The configured CA file for RESTCONF is not readable.",
    "Die konfigurierte CA-Datei für RESTCONF ist ungültig.":
        "The configured CA file for RESTCONF is invalid.",
    "Die RESTCONF-Laufzeitparameter sind ungültig.": "The RESTCONF runtime parameters are invalid.",
    "Interner RESTCONF-Pfad ist ungültig.": "Internal RESTCONF path is invalid.",
    "RESTCONF-Authentifizierung oder Leseberechtigung fehlgeschlagen.":
        "RESTCONF authentication or read authorization failed.",
    "Der WLAN-Controller hat einen nicht erlaubten HTTP-Redirect geliefert.":
        "The wireless controller returned a disallowed HTTP redirect.",
    "Der RESTCONF-Endpunkt hat keinen Antwortinhalt geliefert.":
        "The RESTCONF endpoint returned no response content.",
    "Der RESTCONF-Dienst des WLAN-Controllers meldet einen Serverfehler.":
        "The wireless controller's RESTCONF service reports a server error.",
    "Der RESTCONF-Dienst hat HTTP-Status {status} geliefert.":
        "The RESTCONF service returned HTTP status {status}.",
    "Die RESTCONF-Antwort überschreitet das konfigurierte Größenlimit.":
        "The RESTCONF response exceeds the configured size limit.",
    "Zeitüberschreitung beim Lesen der RESTCONF-Antwort.":
        "Timed out while reading the RESTCONF response.",
    "Die bekannte RESTCONF-Collection enthält keine Daten.":
        "The known RESTCONF collection contains no data.",
    "Der RESTCONF-Endpunkt ist nicht verfügbar oder durch Leserechte verborgen.":
        "The RESTCONF endpoint is unavailable or hidden by read permissions.",
    "Zeitüberschreitung bei der RESTCONF-Verbindung zum WLAN-Controller.":
        "Timed out connecting to the wireless controller via RESTCONF.",
    "Der TLS-Verbindungsaufbau zum WLAN-Controller ist fehlgeschlagen.":
        "The TLS connection to the wireless controller failed.",
    "Der RESTCONF-Dienst des WLAN-Controllers ist nicht erreichbar.":
        "The wireless controller's RESTCONF service is unreachable.",
    "Die RESTCONF-Kommunikation mit dem WLAN-Controller ist fehlgeschlagen.":
        "RESTCONF communication with the wireless controller failed.",
    "Der WLAN-Controller hat eine leere RESTCONF-Antwort geliefert.":
        "The wireless controller returned an empty RESTCONF response.",
    "Die YANG-JSON-Antwort besitzt kein gültiges Wurzelobjekt.":
        "The YANG JSON response has no valid root object.",
    "Die YANG-Library des Controllers enthält keine lesbaren Module.":
        "The controller's YANG library contains no readable modules.",
    "Der Controller stellt das benötigte YANG-Modul {module} nicht bereit.":
        "The controller does not provide the required YANG module {module}.",
    "Der erforderliche YANG-Teilbaum {subtree} konnte nicht gelesen werden.":
        "The required YANG subtree {subtree} could not be read.",
    "Der erforderliche YANG-Teilbaum {subtree} hat keine Daten geliefert.":
        "The required YANG subtree {subtree} returned no data.",
    "Der erforderliche YANG-Teilbaum {subtree} wird nicht unterstützt.":
        "The required YANG subtree {subtree} is not supported.",
    "Der optionale YANG-Teilbaum {subtree} konnte nicht gelesen werden.":
        "The optional YANG subtree {subtree} could not be read.",
    "Der optionale YANG-Teilbaum {subtree} hat keine Daten geliefert.":
        "The optional YANG subtree {subtree} returned no data.",
    "Der optionale YANG-Teilbaum {subtree} wird nicht unterstützt.":
        "The optional YANG subtree {subtree} is not supported.",
    "Dem Controller fehlen benötigte WLAN-YANG-Module: {modules}":
        "The controller is missing required wireless YANG modules: {modules}",
    "RESTCONF, WLAN-YANG-Module und Pflichtendpunkte sind verfügbar.":
        "RESTCONF, wireless YANG modules and required endpoints are available.",
    "RESTCONF und WLAN-YANG-Module sind verfügbar; mindestens eine Pflicht-Collection war leer "
    "oder nicht als Ressource sichtbar.":
        "RESTCONF and wireless YANG modules are available; at least one required collection was empty "
        "or not visible as a resource.",
    "Die NETCONF-XML-Struktur überschreitet das Sicherheitslimit.":
        "The NETCONF XML structure exceeds the safety limit.",
    "Der WLAN-Controller hat keine gültige UTF-8-codierte NETCONF-Antwort geliefert.":
        "The wireless controller did not return a valid UTF-8 encoded NETCONF response.",
    "Die NETCONF-Antwort enthält unzulässige XML-Deklarationen.":
        "The NETCONF response contains disallowed XML declarations.",
    "Der WLAN-Controller hat keine gültige NETCONF-XML-Antwort geliefert.":
        "The wireless controller did not return a valid NETCONF XML response.",
    "Die NETCONF-Antwort enthält kein erwartetes {expected}-Element.":
        "The NETCONF response does not contain the expected {expected} element.",
    "Die NETCONF-RPC-Antwort enthält kein data-Element.":
        "The NETCONF RPC reply contains no data element.",
    "Die Running-Konfiguration ist durch eine andere Sitzung gesperrt.":
        "The running configuration is locked by another session.",
    "Der Controller meldet eine unvollständige Änderung; aktuelle Werte erneut prüfen.":
        "The controller reports an incomplete change; check the current values again.",
    "Der NETCONF-Benutzer besitzt keine Berechtigung für diese Änderung.":
        "The NETCONF user is not authorized to make this change.",
    "Der Controller hat die Änderung abgelehnt. Eingaben und Abhängigkeiten prüfen.":
        "The controller rejected the change. Check inputs and dependencies.",
    "NETCONF-Authentifizierung oder Leseberechtigung fehlgeschlagen.":
        "NETCONF authentication or read authorization failed.",
    "Der Controller unterstützt den angeforderten NETCONF/YANG-Teilbaum nicht.":
        "The controller does not support the requested NETCONF/YANG subtree.",
    "Der WLAN-Controller hat einen NETCONF-RPC-Fehler geliefert.":
        "The wireless controller returned a NETCONF RPC error.",
    "Zeitüberschreitung beim Lesen der NETCONF-Antwort.": "Timed out while reading the NETCONF response.",
    "Die NETCONF-Antwort überschreitet das konfigurierte Größenlimit.":
        "The NETCONF response exceeds the configured size limit.",
    "Der WLAN-Controller hat eine leere NETCONF-Antwort geliefert.":
        "The wireless controller returned an empty NETCONF response.",
    "Die NETCONF-SSH-Verbindung wurde beim Lesen unterbrochen.":
        "The NETCONF SSH connection was interrupted while reading.",
    "Die NETCONF-SSH-Verbindung wurde vorzeitig geschlossen.":
        "The NETCONF SSH connection was closed prematurely.",
    "Die NETCONF-SSH-Verbindung wurde beim Senden unterbrochen.":
        "The NETCONF SSH connection was interrupted while sending.",
    "Der WLAN-Controller bietet NETCONF base:1.0 nicht an.":
        "The wireless controller does not offer NETCONF base:1.0.",
    "Die NETCONF-Antwort besitzt eine unerwartete message-id.":
        "The NETCONF response has an unexpected message-id.",
    "Die Änderung wurde gesendet, ihr Ausgang ist unbekannt. "
    "Vor einer erneuten Aktion die aktuellen Gerätewerte prüfen.":
        "The change was sent, but its outcome is unknown. "
        "Check the current device values before trying again.",
    "Die YANG-Modulkennung ist ungültig.": "The YANG module identifier is invalid.",
    "Der Controller hat kein lesbares YANG-Schema geliefert.":
        "The controller did not return a readable YANG schema.",
    "Der Controller hat den Schreibvorgang nicht eindeutig bestätigt.":
        "The controller did not clearly confirm the write operation.",
    "Dieser Ablauf unterstützt ausschließlich den Running-Datastore.":
        "This workflow supports only the running datastore.",
    "Der Controller bietet keinen beschreibbaren Running-Datastore an.":
        "The controller does not offer a writable running datastore.",
    "Die Änderung besitzt keinen gültigen NETCONF-Konfigurationsknoten.":
        "The change has no valid NETCONF configuration node.",
    "Sicheres Bearbeiten erfordert NETCONF rollback-on-error.":
        "Safe editing requires NETCONF rollback-on-error.",
    "Der NETCONF-Port muss zwischen 1 und 65535 liegen.":
        "The NETCONF port must be between 1 and 65535.",
    "Die NETCONF-Laufzeitparameter sind ungültig.": "The NETCONF runtime parameters are invalid.",
    "Zeitüberschreitung beim Aktivieren des NETCONF-SSH-Subsystems.":
        "Timed out while activating the NETCONF SSH subsystem.",
    "Das NETCONF-SSH-Subsystem konnte nicht aktiviert werden.":
        "The NETCONF SSH subsystem could not be activated.",
    "Die konfigurierte Known-Hosts-Datei für NETCONF ist nicht lesbar.":
        "The configured known hosts file for NETCONF is not readable.",
    "Die konfigurierte Known-Hosts-Datei für NETCONF ist ungültig.":
        "The configured known hosts file for NETCONF is invalid.",
    "Der WLAN-Controller hat keinen aktiven NETCONF-SSH-Transport bereitgestellt.":
        "The wireless controller did not provide an active NETCONF SSH transport.",
    "NETCONF-Authentifizierung am WLAN-Controller fehlgeschlagen.":
        "NETCONF authentication on the wireless controller failed.",
    "Der SSH-Host-Key des WLAN-Controllers stimmt nicht mit Known Hosts überein.":
        "The wireless controller's SSH host key does not match known hosts.",
    "Zeitüberschreitung bei der NETCONF-Verbindung zum WLAN-Controller.":
        "Timed out connecting to the wireless controller via NETCONF.",
    "Der SSH-Host-Key des WLAN-Controllers konnte nicht verifiziert werden.":
        "The wireless controller's SSH host key could not be verified.",
    "Der NETCONF-Dienst des WLAN-Controllers ist nicht erreichbar.":
        "The wireless controller's NETCONF service is unreachable.",
    "NETCONF, WLAN-YANG-Module und Pflichtendpunkte sind verfügbar.":
        "NETCONF, wireless YANG modules and required endpoints are available.",
    "NETCONF und WLAN-YANG-Module sind verfügbar; mindestens eine Pflicht-Collection war leer.":
        "NETCONF and wireless YANG modules are available; at least one required collection was empty.",
    "Modell und Softwareversion konnten nicht gelesen werden.":
        "Model and software version could not be read.",
    "Das Modul wird nur als Schemaimport angeboten, nicht als implementierte Konfiguration.":
        "The module is offered only as a schema import, not as implemented configuration.",
    "Das Gerät meldet Modellabweichungen; diese Ressource ist bis zur Prüfung nur lesbar.":
        "The device reports model deviations; this resource is read-only until reviewed.",
    "Optionale Schemafunktionen sind für dieses Modul nicht vollständig nachgewiesen.":
        "Optional schema features are not fully confirmed for this module.",
    "Das benötigte YANG-Modul fehlt auf diesem Controller.":
        "The required YANG module is missing on this controller.",
    "Die Konfiguration ist mit diesem Konto nicht lesbar.":
        "The configuration is not readable with this account.",
    "Das Konfigurationsmodul {module} konnte nicht gelesen werden.":
        "The configuration module {module} could not be read.",
    "Das Geräteschema {module} konnte nicht geprüft werden; Bearbeitung ist gesperrt.":
        "The device schema {module} could not be checked; editing is locked.",
    "Die aktuellen AP-Werte konnten nicht gelesen werden; AP-Aktionen sind gesperrt.":
        "The current AP values could not be read; AP actions are locked.",
    "Das benötigte YANG-Modul wird nicht angeboten.": "The required YANG module is not offered.",
    "Das aktuelle Geräteschema konnte nicht geprüft werden.":
        "The current device schema could not be checked.",
    "Das vom AP-Join-Profil verwendete AP-Typschema konnte nicht geprüft werden.":
        "The AP type schema used by the AP join profile could not be checked.",
    "Keine eindeutig identifizierbaren aktuellen Access Points verfügbar.":
        "No uniquely identifiable current access points available.",
    "Der Controller bietet kein rollback-on-error für sichere Änderungen an.":
        "The controller does not offer rollback-on-error for safe changes.",
    "Der benötigte RPC ist im aktuellen Geräteschema nicht enthalten.":
        "The required RPC is not included in the current device schema.",
    "Die Aktion ist im aktuellen Geräteschema nicht nachgewiesen.":
        "The action is not confirmed in the current device schema.",
    "Ein angefordertes Konfigurationsfeld ist im aktuellen Geräteschema nicht nachgewiesen.":
        "A requested configuration field is not confirmed in the current device schema.",
    "Der Controller hat das dauerhafte Speichern abgelehnt.":
        "The controller rejected saving the configuration permanently.",
    "Das Ergebnis des dauerhaften Speicherns konnte nicht eindeutig bestätigt werden.":
        "The result of saving the configuration permanently could not be clearly confirmed.",
    "{message} Die aktuellen AP-Werte wurden erneut gelesen; der Aktionsabschluss bleibt unbestätigt.":
        "{message} The current AP values were read again; completion of the action remains unconfirmed.",
    "{message} Die gewünschten Werte sind jetzt am Gerät sichtbar; "
    "die ursprüngliche Ausführung bleibt unbestätigt.":
        "{message} The requested values are now visible on the device; "
        "the original execution remains unconfirmed.",
    "{message} Die erneut gelesenen Gerätewerte bestätigen die Änderung nicht vollständig.":
        "{message} The device values read again do not fully confirm the change.",
    "Die Gerätekonfiguration hat sich seit der Vorschau geändert. Vorschau neu erstellen.":
        "The device configuration has changed since the preview. Create a new preview.",
    "Diese Funktion wird nicht unterstützt.": "This function is not supported.",
    "Konfigurationsänderung und Betriebsaktion müssen getrennt ausgeführt werden.":
        "Configuration changes and operational actions must be executed separately.",
    "Eine Vorschau darf genau eine Betriebsaktion ausführen.":
        "A preview may execute exactly one operational action.",
    "Die Änderung wurde vom Controller bestätigt.": "The change was confirmed by the controller.",
    "Die gesamte Running-Konfiguration wurde dauerhaft gespeichert.":
        "The entire running configuration was saved permanently.",
    "Die Betriebsaktion wurde bestätigt. Abschluss und Persistenz am AP erneut prüfen.":
        "The operational action was confirmed. Check completion and persistence on the AP again.",
    "Die Änderung und die lesbaren Werte wurden bestätigt. Geheime Schlüssel sind nicht rücklesbar.":
        "The change and the readable values were confirmed. Secret keys cannot be read back.",
    "Die Änderung wurde bestätigt, aber die aktuellen Gerätewerte weichen von der Vorschau ab. "
    "Erneut prüfen.":
        "The change was confirmed, but the current device values differ from the preview. Check again.",
    "Die Aktion wurde bestätigt; aktuelle Werte und Abschluss konnten danach nicht geprüft werden.":
        "The action was confirmed; current values and completion could not be checked afterwards.",
    "Die Sperre wird durch das Schließen der NETCONF-Sitzung freigegeben.":
        "The lock is released by closing the NETCONF session.",
    # Switches backend (Cisco driver, validation, transport, clients, routes, inventory)
    "'{command}' lief in ein Zeitlimit.": "'{command}' timed out.",
    "'{command}' wurde nach einem Zeitlimit nicht mehr abgefragt.": "'{command}' was skipped after a timeout.",
    "ARP-Tabelle": "ARP table",
    "Am verbundenen Edge-Port ist aktuell keine MAC-Adresse sichtbar.":
        "No MAC address is currently visible on the connected edge port.",
    "Authentifizierungssitzungen": "Authentication sessions",
    "Bei globalen Zugangsdaten dürfen keine eigenen Geheimnisse gesetzt werden.":
        "Custom secrets cannot be set when global credentials are used.",
    "Bitte die Interface-Details neu laden.": "Please reload the interface details.",
    "CDP-Nachbarn": "CDP neighbors",
    "Cisco UPOE – max. 60 W": "Cisco UPOE – max. 60 W",
    "Cisco-Hardwaredokumentation: {model}, Port {port}": "Cisco hardware documentation: {model}, port {port}",
    "Cisco-Hardwaredokumentation: {model}, Stack-Mitglied {member}, Port {port}":
        "Cisco hardware documentation: {model}, stack member {member}, port {port}",
    "Das Bulk-Switchport-Ausgabeformat ist unbekannt.": "The bulk switchport output format is unknown.",
    "Das Hardwaremodell ist für dieses Interface nicht eindeutig belegt.":
        "The hardware model of this interface cannot be determined unambiguously.",
    "Das Hardwaremodell konnte nicht vom Switch ausgelesen werden.":
        "The hardware model could not be read from the switch.",
    "Das Hardwaremodell von Stack-Mitglied {member} ist nicht eindeutig belegt.":
        "The hardware model of stack member {member} cannot be determined unambiguously.",
    "Das Interface lässt sich keinem eindeutigen Stack-Mitglied zuordnen.":
        "The interface cannot be assigned to a single stack member.",
    "Das PoE-Limit darf hoechstens drei Nachkommastellen haben.":
        "The PoE limit may have at most three decimal places.",
    "Das PoE-Limit muss 0 (Geraetestandard) oder 4 bis 90 Watt betragen.":
        "The PoE limit must be 0 (device default) or 4 to 90 watts.",
    "Das PoE-Limit muss als Zahl in Watt angegeben werden.": "The PoE limit must be a number in watts.",
    "Das Switch-Modell konnte nicht gelesen werden; die unterstuetzten PoE-Standards sind unbekannt.":
        "The switch model could not be read; the supported PoE standards are unknown.",
    "Der Einzelport-Fallback ist auf {limit} Ports begrenzt; weitere Switchport-Details bleiben unbekannt.":
        "The per-port fallback is limited to {limit} ports; further switchport details remain unknown.",
    "Der Einzelport-Fallback lief in ein Zeitlimit; verbleibende Switchport-Details sind unbekannt.":
        "The per-port fallback timed out; remaining switchport details are unknown.",
    "Der Konfigurationsmodus konnte nicht sicher aktiviert werden.":
        "Configuration mode could not be entered reliably.",
    "Der Konfigurationsmodus konnte nicht sicher verlassen werden.": "Configuration mode could not be exited reliably.",
    "Der MAC-Tabellentyp belegt keine aktuelle Client-Zuordnung.":
        "The MAC table entry type does not prove a current client assignment.",
    "Der PVLAN-Promiscuous-Port liegt ausserhalb der lokalen Client-Erkennung.":
        "The PVLAN promiscuous port is outside local client detection.",
    "Der Port arbeitet als Layer-3-Port und liegt ausserhalb der Client-Erkennung.":
        "The port operates as a layer 3 port and is outside client detection.",
    "Der Port arbeitet als Trunk und liegt ausserhalb der lokalen Client-Erkennung.":
        "The port operates as a trunk and is outside local client detection.",
    "Der Port liegt außerhalb der dokumentierten PoE-Downlink-Ports.":
        "The port is outside the documented PoE downlink ports.",
    "Der Suchbegriff muss mindestens zwei Zeichen enthalten.": "The search term must contain at least two characters.",
    "Der Switch hat das Speichern der Konfiguration nicht bestaetigt.":
        "The switch did not confirm saving the configuration.",
    "Der Switch hat die Konfigurationsaenderung nicht bestaetigt.":
        "The switch did not confirm the configuration change.",
    "Der Switch liefert kein PoE-Gesamtbudget. Befehlsunterstützung und SSH-Berechtigungen prüfen.":
        "The switch reports no total PoE budget. Check command support and SSH permissions.",
    "Der ausgewaehlte PoE-Standard ist fuer Interface {interface} nicht bestaetigt. {reason}":
        "The selected PoE standard is not confirmed for interface {interface}. {reason}",
    "Der lokale Switchport-Modus ist nicht eindeutig.": "The local switchport mode is ambiguous.",
    "Der privilegierte Modus (Enable) konnte nicht aktiviert werden.":
        "Privileged mode (enable) could not be activated.",
    "Device Tracking": "Device tracking",
    "Die Ausgabe von 'show interfaces status' enthaelt keine erkennbare Tabellenkopfzeile.":
        "The output of 'show interfaces status' contains no recognizable table header.",
    "Die Ausgabe von 'show interfaces switchport' enthaelt keine Interface-Bloecke.":
        "The output of 'show interfaces switchport' contains no interface blocks.",
    "Die Ausgabe von 'show power inline' hat ein unbekanntes Tabellenformat.":
        "The output of 'show power inline' has an unknown table format.",
    "Die Ausgabe von 'show vlan brief' enthaelt keine erkennbare Tabellenkopfzeile.":
        "The output of 'show vlan brief' contains no recognizable table header.",
    "Die Description darf höchstens {max_length} Zeichen und keine Steuerzeichen enthalten.":
        "The description may contain at most {max_length} characters and no control characters.",
    "Die Firmware unterstuetzt die Bulk-Switchport-Abfrage nicht.":
        "The firmware does not support the bulk switchport query.",
    "Die Firmware unterstuetzt die PoE-Abfrage nicht.": "The firmware does not support the PoE query.",
    "Die Geräteadresse ist für HTTPS ungültig.": "The device address is not valid for HTTPS.",
    "Die Interface-Status-Tabelle enthaelt keine lesbaren Ports.":
        "The interface status table contains no readable ports.",
    "Die Interface-Status-Tabelle hat ein unbekanntes Spaltenformat.":
        "The interface status table has an unknown column format.",
    "Die Interface-Status-Tabelle hat ungueltige Spaltengrenzen.":
        "The interface status table has invalid column boundaries.",
    "Die PoE-Abfrage ist fehlgeschlagen; das Gesamtbudget ist nicht verfügbar.":
        "The PoE query failed; the total budget is not available.",
    "Die PoE-Abfrage lief in ein Zeitlimit; PoE-Werte bleiben unbekannt.":
        "The PoE query timed out; PoE values remain unknown.",
    "Die PoE-Abfrage lief in ein Zeitlimit; das Gesamtbudget ist nicht verfügbar.":
        "The PoE query timed out; the total budget is not available.",
    "Die PoE-Tabelle enthaelt eine unvollstaendige Portzeile.": "The PoE table contains an incomplete port row.",
    "Die PoE-Tabelle enthaelt einen Port mehrfach.": "The PoE table contains a port more than once.",
    "Die PoE-Tabelle enthaelt einen unbekannten Administrationsmodus.": "The PoE table contains an unknown admin mode.",
    "Die PoE-Tabelle enthaelt einen unlesbaren Leistungswert.": "The PoE table contains an unreadable power value.",
    "Die PoE-Werte konnten nicht sicher gelesen werden.": "The PoE values could not be read reliably.",
    "Die Portnummer lässt sich für dieses Hardwaremodell nicht sicher zuordnen.":
        "The port number cannot be mapped reliably for this hardware model.",
    "Die System-MAC ist kein angeschlossener Client.": "The system MAC is not a connected client.",
    "Die VLAN-Liste ist zu lang oder enthaelt ungueltige Zeichen.":
        "The VLAN list is too long or contains invalid characters.",
    "Die VLAN-Tabelle enthaelt keine lesbaren VLANs.": "The VLAN table contains no readable VLANs.",
    "Die VLAN-Tabelle hat ein unbekanntes Spaltenformat.": "The VLAN table has an unknown column format.",
    "Die VLAN-Tabelle hat ungueltige Spaltengrenzen.": "The VLAN table has invalid column boundaries.",
    "Die gelernte VLAN-ID weicht von den erkannten Port-VLANs ab.":
        "The learned VLAN ID differs from the detected port VLANs.",
    "Die konfigurierte CA-Datei für die Switch-API ist nicht lesbar.":
        "The configured CA file for the switch API is not readable.",
    "Die konfigurierte PoE-Leistungsgrenze konnte nicht sicher gelesen werden.":
        "The configured PoE power limit could not be read reliably.",
    "Die konfigurierte Secure-MAC belegt keine aktuelle Zuordnung.":
        "The configured secure MAC does not prove a current assignment.",
    "Die laufende Konfiguration passt nicht zum angefragten Interface {interface}.":
        "The running configuration does not match the requested interface {interface}.",
    "Die optionale Bulk-Switchport-Abfrage lief in ein Zeitlimit; Einzelport-Fallback wird verwendet.":
        "The optional bulk switchport query timed out; using the per-port fallback.",
    "Die optionale Bulk-Switchport-Abfrage wurde abgelehnt.": "The optional bulk switchport query was rejected.",
    "Die optionale Fallback-Verbindung war nicht erreichbar; Switchport-Details sind unbekannt.":
        "The optional fallback connection could not be established; switchport details are unknown.",
    "Die statische MAC besitzt keine aktuelle Authentifizierungs- oder Port-Security-Zuordnung.":
        "The static MAC has no current authentication or port security assignment.",
    "Dieser Interface-Typ ist kein dokumentierter PoE-Downlink des Modells.":
        "This interface type is not a documented PoE downlink of the model.",
    "Dieses Hardwaremodell unterstützt kein PoE.": "This hardware model does not support PoE.",
    "Dieses Modell hat nur acht PoE-Ports; deren Portzuordnung ist noch nicht verifiziert.":
        "This model has only eight PoE ports; their port mapping is not yet verified.",
    "Ein PoE-Leistungsprofil erfordert den PoE-Modus auto oder static.":
        "A PoE power profile requires PoE mode auto or static.",
    "Ein PoE-Standard erfordert den PoE-Modus auto oder static.": "A PoE standard requires PoE mode auto or static.",
    "Ein Switch mit diesem Namen existiert bereits.": "A switch with this name already exists.",
    "Ein Switchport-Block enthaelt keinen gueltigen Interface-Namen.":
        "A switchport block contains no valid interface name.",
    "Eine Gruppe mit diesem Namen existiert bereits.": "A group with this name already exists.",
    "Eine persistente MAC besitzt keinen aktuellen, portgenauen Sitzungs- oder Binding-Nachweis.":
        "A persistent MAC has no current port-specific session or binding evidence.",
    "Enable-Secret kann nicht gleichzeitig gesetzt und entfernt werden.":
        "The enable secret cannot be set and removed at the same time.",
    "Es muss eine gültige IPv4- oder IPv6-Adresse angegeben werden.": "A valid IPv4 or IPv6 address is required.",
    "Für diesen Switch fehlen Zugangsdaten für die gewählte Quelle (global/eigen).":
        "This switch has no credentials for the selected source (global/custom).",
    "Für diesen Switch fehlen Zugangsdaten.": "This switch has no credentials.",
    "Für dieses Hardwaremodell sind keine PoE-Standards verifiziert.":
        "No PoE standards are verified for this hardware model.",
    "Für eigene Zugangsdaten ist ein Benutzername erforderlich.": "Custom credentials require a username.",
    "Für neue eigene Zugangsdaten ist ein Passwort erforderlich.": "New custom credentials require a password.",
    "Gemeldetes PoE-Budget widerspricht den dokumentierten Hardwarefähigkeiten.":
        "The reported PoE budget contradicts the documented hardware capabilities.",
    "Geraetestandard": "Device default",
    "Gruppe nicht gefunden": "Group not found",
    "Gruppenname darf nicht leer sein.": "Group name must not be empty.",
    "IEEE 802.3bt Typ 3 benötigt auf diesem UPOE-Modell passende Firmware und einen aktivierten 802.3bt-Modus. Dieser Modus ist nicht verifiziert; Cisco UPOE mit maximal 60 W bleibt auswählbar. Die Auswahl schaltet keinen Protokollmodus um.":
        "IEEE 802.3bt Type 3 on this UPOE model requires suitable firmware and an enabled 802.3bt mode. This mode is not verified; Cisco UPOE with up to 60 W remains selectable. The selection does not switch any protocol mode.",
    "Interface {interface} kommt mehrfach in der Switchport-Ausgabe vor.":
        "Interface {interface} appears more than once in the switchport output.",
    "Interface {interface} unterstuetzt kein PoE.": "Interface {interface} does not support PoE.",
    "Interface-Status konnte fuer folgende Ports nicht sicher gelesen werden: {ports}":
        "Interface status could not be read reliably for these ports: {ports}",
    "Kein auswertbares Gesamt-PoE-Budget gemeldet.": "No usable total PoE budget reported.",
    "Kein unterstütztes physisches PoE-Interface.": "Not a supported physical PoE interface.",
    "Keine Berechtigung fuer den Lesebefehl '{command}': {errors}":
        "No permission for the read command '{command}': {errors}",
    "Keine Switchport-Details fuer: {ports}.": "No switchport details for: {ports}.",
    "LLDP-Nachbarn": "LLDP neighbors",
    "Mindestens ein ungueltiger Portname aus der Status-Tabelle wurde beim Fallback uebersprungen.":
        "At least one invalid port name from the status table was skipped during the fallback.",
    "Mindestens eine Einzelport-Switchport-Abfrage wurde von der Firmware nicht unterstuetzt.":
        "At least one per-port switchport query was not supported by the firmware.",
    "Mindestens eine Einzelport-Switchport-Ausgabe konnte nicht sicher gelesen werden.":
        "At least one per-port switchport output could not be read reliably.",
    "Mindestens eine Einzelport-Switchport-Ausgabe passte nicht zum angefragten Port.":
        "At least one per-port switchport output did not match the requested port.",
    "Mindestens eine lokale MAC wurde in einem unerwarteten VLAN gelernt; die Eintraege bleiben sichtbar und sind als VLAN-Abweichung markiert.":
        "At least one local MAC was learned in an unexpected VLAN; the entries remain visible and are marked as VLAN mismatch.",
    "Mindestens eine relevante Zeile der MAC-Tabelle hatte ein unbekanntes Format; die Client-Erkennung kann unvollstaendig sein.":
        "At least one relevant MAC table line had an unknown format; client detection may be incomplete.",
    "Multicast-, Broadcast- und Null-MACs sind keine lokalen Clients.":
        "Multicast, broadcast and null MACs are not local clients.",
    "Nachbarn konnten nicht gelesen werden: {failures}": "Neighbors could not be read: {failures}",
    "Name darf nicht leer sein.": "Name must not be empty.",
    "PoE (IEEE 802.3af) – max. 15,4 W": "PoE (IEEE 802.3af) – max. 15.4 W",
    "PoE+ (IEEE 802.3at) – max. 30 W": "PoE+ (IEEE 802.3at) – max. 30 W",
    "PoE++ (IEEE 802.3bt Typ 3) – max. 60 W": "PoE++ (IEEE 802.3bt Type 3) – max. 60 W",
    "PoE++ (IEEE 802.3bt Typ 4) – max. 90 W": "PoE++ (IEEE 802.3bt Type 4) – max. 90 W",
    "PoE-Budget enthält ein unbekanntes Tabellenformat.": "The PoE budget has an unknown table format.",
    "PoE-Budget enthält fehlende oder ungültige Werte.": "The PoE budget contains missing or invalid values.",
    "PoE-Budget ist für den erkannten Switch-Stack unvollständig.":
        "The PoE budget is incomplete for the detected switch stack.",
    "PoE-Budget ist widersprüchlich; die Leistungswerte bleiben unbekannt.":
        "The PoE budget is contradictory; power values remain unknown.",
    "PoE-Budget konnte nicht ausgelesen werden.": "The PoE budget could not be read.",
    "PoE-Modus": "PoE mode",
    "Port-Security-Adressen": "Port security addresses",
    "SSH-Kommunikation fehlgeschlagen. Server-Log prüfen.": "SSH communication failed. Check the server log.",
    "Switch nicht gefunden": "Switch not found",
    "Switch oder Zugangsdaten wurden geändert. Bitte den Dialog neu öffnen.":
        "The switch or its credentials were changed. Please reopen the dialog.",
    "Switch wurde zwischenzeitlich entfernt.": "The switch has been removed in the meantime.",
    "Switchport-Details fuer {interface} fehlen in der Switch-Ausgabe.":
        "Switchport details for {interface} are missing from the switch output.",
    "Switchport-Details konnten nicht sicher ermittelt werden.": "Switchport details could not be determined reliably.",
    "Unbekannter PoE-Standard.": "Unknown PoE standard.",
    "Ungueltiger PoE-Modus.": "Invalid PoE mode.",
    "Ungültige VLAN-ID: {value}": "Invalid VLAN ID: {value}",
    "Ungültige VLAN-Liste: {value} (erlaubt: 'all', 'none' oder z.B. '10,20,30-40')":
        "Invalid VLAN list: {value} (allowed: 'all', 'none' or e.g. '10,20,30-40')",
    "Ungültiger VLAN-Bereich: {value}": "Invalid VLAN range: {value}",
    "Ungültiger Wert für {label}: {value}": "Invalid value for {label}: {value}",
    "Unterstützte PoE-Versionen sind nicht für alle erkannten Hardwaremodelle verifiziert.":
        "Supported PoE versions are not verified for all detected hardware models.",
    "Uplink-, Modul- und Management-Ports erhalten kein PoE-Leistungsprofil.":
        "Uplink, module and management ports get no PoE power profile.",
    "VLAN-Daten konnten fuer folgende IDs nicht sicher gelesen werden: {ids}":
        "VLAN data could not be read reliably for these IDs: {ids}",
    "VLAN-ID außerhalb des gültigen Bereichs 1-4094: {value}": "VLAN ID outside the valid range 1-4094: {value}",
    "Widersprüchliche wiederholte PoE-Budgetangaben bleiben unbekannt.":
        "Contradictory repeated PoE budget values remain unknown.",
    "{label} ist auf diesem Switch nicht verfuegbar; IP-Zuordnungen koennen unvollstaendig sein.":
        "{label} is not available on this switch; IP assignments may be incomplete.",
    "{label} konnte nicht gelesen werden.": "{label} could not be read.",
    "{label} lief in ein Zeitlimit; die lokale MAC-Liste bleibt verfuegbar.":
        "{label} timed out; the local MAC list remains available.",
    "{label} lieferte keine lesbare Ausgabe.": "{label} returned no readable output.",
    "{label} werden von dieser Firmware nicht unterstuetzt.": "{label} are not supported by this firmware.",
    "{label} wird von dieser Firmware nicht unterstuetzt.": "{label} is not supported by this firmware.",
    "{label} wurde nach einem Zeitlimit der Verbindung nicht mehr abgefragt.":
        "{label} was skipped after a connection timeout.",
    # wlan config_catalog, config_service, routes, service
    "Unzulässige oder zu große Konfigurationsantwort.": "Invalid or oversized configuration response.",
    "Eine eindeutige MAC-Adresse in Doppelpunktnotation ist erforderlich.":
        "A unique MAC address in colon notation is required.",
    "Referenz {key} ist in {collection} nicht nachgewiesen. Konfiguration neu laden.":
        "Reference {key} is not confirmed in {collection}. Reload the configuration.",
    "AP-Radio-MAC ist nicht eindeutig aus aktuellen Gerätedaten nachgewiesen.":
        "The AP radio MAC is not uniquely confirmed by current device data.",
    "Radio-Slot und Funkband stimmen nicht mit den aktuellen AP-Daten überein.":
        "Radio slot and band do not match the current AP data.",
    "Ungültiger Änderungsauftrag.": "Invalid change request.",
    "Ressource oder Operation wird nicht unterstützt.": "Resource or operation is not supported.",
    "Änderungswerte müssen ein Objekt sein.": "Change values must be an object.",
    "Der Änderungsauftrag enthält unbekannte oder nicht bearbeitbare Felder.":
        "The change request contains unknown or non-editable fields.",
    "Das Zielobjekt existiert nicht mehr. Konfiguration neu laden.":
        "The target object no longer exists. Reload the configuration.",
    "Unter diesem Namen existiert bereits ein Objekt.": "An object with this name already exists.",
    "Der Tag wird von mindestens einem AP verwendet.": "The tag is used by at least one AP.",
    "Das Objekt besitzt weitere Referenzen in der Controllerkonfiguration.":
        "The object has further references in the controller configuration.",
    "Löschen benötigt eine vollständige, aktuelle Referenzübersicht.":
        "Deleting requires a complete, current reference overview.",
    "{label}: Wahrheitswert erforderlich.": "{label}: boolean value required.",
    "Speichern betrifft die gesamte Running-Konfiguration; das Ziel muss ausdrücklich der Controller sein.":
        "Saving affects the entire running configuration; the target must explicitly be the controller.",
    "AP-Name/Standort erlaubt nur druckbares ASCII; der AP-Name darf keine Leerzeichen enthalten.":
        "AP name/location allows printable ASCII only; the AP name must not contain spaces.",
    "Betriebsmodus und bestehender Site-Tag passen nicht zusammen; zuerst Site-/FlexConnect-Design prüfen.":
        "Operating mode and existing site tag do not match; check the site/FlexConnect design first.",
    "Diese Band-/Slot-Kombination ist im angebotenen Cisco-RPC nicht erlaubt.":
        "This band/slot combination is not allowed by the offered Cisco RPC.",
    "Der Kanal ist für dieses Radio / diese Regulierungsdomäne nicht nachgewiesen.":
        "The channel is not confirmed for this radio / regulatory domain.",
    "Diese Leistungsstufe ist für das konkrete Radio nicht nachgewiesen.":
        "This power level is not confirmed for this radio.",
    "2,4 GHz unterstützt diese Kanalbreite nicht.": "2.4 GHz does not support this channel width.",
    "Die gewünschte Kanalbreite ist für dieses AP-Radio nicht nachgewiesen.":
        "The requested channel width is not confirmed for this AP radio.",
    "AP-Tagzuweisung benötigt eine nachgewiesene Ethernet-MAC; die Radio-MAC genügt nicht.":
        "AP tag assignment requires a confirmed Ethernet MAC; the radio MAC is not sufficient.",
    "Profil-/Tagname muss 1–32 druckbare ASCII-Zeichen ohne äußere Leerzeichen enthalten.":
        "Profile/tag name must contain 1–32 printable ASCII characters without leading or trailing spaces.",
    "Löschen darf keine Feldänderungen enthalten.": "Deleting must not include field changes.",
    "Standardprofile und Standardtags können nicht gelöscht werden.": "Default profiles and default tags cannot be deleted.",
    "Die Ableitungsvorlage existiert nicht.": "The source template does not exist.",
    "Keine Änderungen angegeben.": "No changes specified.",
    "Keine Logdateien vorhanden.": "No log files available.",
    "Eine SSID darf maximal 32 UTF-8-Bytes belegen.": "An SSID may use at most 32 UTF-8 bytes.",
    "Die WLAN-ID wird bereits verwendet.": "The WLAN ID is already in use.",
    "Neue WLANs benötigen eine ausdrückliche Sicherheitsvorlage.": "New WLANs require an explicit security template.",
    "WLAN-Schlüssel benötigen 8–63 druckbare ASCII-Zeichen und eine Personal-Vorlage.":
        "WLAN keys require 8–63 printable ASCII characters and a Personal template.",
    "6 GHz benötigt eine WPA3-Sicherheitsvorlage mit PMF.": "6 GHz requires a WPA3 security template with PMF.",
    "Ein ausschließliches 6-GHz-WLAN muss WPA2 deaktivieren.": "A 6 GHz-only WLAN must disable WPA2.",
    "Reservierte Preauth-ACLs können nicht als Policy-ACL verwendet werden.":
        "Reserved preauth ACLs cannot be used as policy ACLs.",
    "{label}: ganze Zahl erforderlich.": "{label}: integer required.",
    "{label}: Wert außerhalb des erlaubten Bereichs.": "{label}: value out of the allowed range.",
    "{label} fehlt.": "{label} is missing.",
    "{label} fehlt für das neue Objekt.": "{label} is missing for the new object.",
    "{label} ist unveränderlich; ein neues Profil ableiten.": "{label} is immutable; derive a new profile.",
    "{label}: Das referenzierte Profil hat ein anderes Funkband.": "{label}: the referenced profile uses a different band.",
    "Local Switching benötigt bei allen betroffenen APs einen nachgewiesenen FlexConnect-Site-Tag.":
        "Local switching requires a confirmed FlexConnect site tag on all affected APs.",
    "Das FlexConnect-Profil eines betroffenen APs ist nicht nachgewiesen.":
        "The FlexConnect profile of an affected AP is not confirmed.",
    "Das benannte VLAN muss im FlexConnect-Profil jedes betroffenen APs einer VLAN-ID zugeordnet sein.":
        "The named VLAN must be mapped to a VLAN ID in the FlexConnect profile of every affected AP.",
    "Eine Personal-Sicherheitsvorlage benötigt einen neu angegebenen WLAN-Schlüssel.":
        "A Personal security template requires a newly entered WLAN key.",
    "Enterprise benötigt eine vorhandene 802.1X-Authentifizierungsliste.":
        "Enterprise requires an existing 802.1X authentication list.",
    "WLAN- und RLAN-Zuordnungen dürfen zusammen höchstens 16 Einträge enthalten.":
        "WLAN and RLAN mappings may contain at most 16 entries combined.",
    "{label}: ungültige Liste.": "{label}: invalid list.",
    "{label}: ungültiger Text.": "{label}: invalid text.",
    "{label}: ungültige Länge.": "{label}: invalid length.",
    "{label}: ungültige Auswahl.": "{label}: invalid selection.",
    "Das Objekt wird von {resource} / {key} verwendet.": "The object is used by {resource} / {key}.",
    "Das Objekt wird in einer WLAN-/Policy-Zuordnung verwendet.": "The object is used in a WLAN/policy mapping.",
    "Jede Zuordnung benötigt WLAN-Profil und Policy-Profil.": "Each mapping requires a WLAN profile and a policy profile.",
    "Profilreferenzen müssen Namen sein.": "Profile references must be names.",
    "Ein WLAN darf im Tag nur einmal zugeordnet sein.": "A WLAN may be mapped only once in the tag.",
    "Ein Local-Site-Tag darf kein FlexConnect-Profil verwenden.": "A local site tag must not use a FlexConnect profile.",
    "Ein FlexConnect-Site-Tag benötigt ein vorhandenes Flex-Profil.": "A FlexConnect site tag requires an existing Flex profile.",
    "{label}: ungültige oder doppelte Auswahl.": "{label}: invalid or duplicate selection.",
    "{label}: gültige, eindeutige Kanalnummern erforderlich.": "{label}: valid, unique channel numbers required.",
    "Die minimale Sendeleistung darf die maximale nicht überschreiten.":
        "The minimum transmit power must not exceed the maximum.",
    "Diese Kanalbreite ist für 2,4 GHz nicht geeignet.": "This channel width is not suitable for 2.4 GHz.",
    "{label}: gültige IP-Adresse erforderlich.": "{label}: valid IP address required.",
    "Kanalauswahl benötigt bekannte erlaubte Kanäle der Radios in diesem Funkband.":
        "Channel selection requires known allowed channels of the radios in this band.",
    "Mindestens ein AP unterstützt die gewählte Kanalliste nicht.":
        "At least one AP does not support the selected channel list.",
    "Eine Backup-Controller-IP benötigt den zugehörigen Controllernamen.":
        "A backup controller IP requires the corresponding controller name.",
    "VLAN-Zuordnungen benötigen interface_name und vlan_id.": "VLAN mappings require interface_name and vlan_id.",
    "VLAN-Namen dürfen nur einmal vorkommen.": "VLAN names may occur only once.",
    "[verborgen]": "[hidden]",
    "Der globale Speicherstand ist unbekannt. Noch keine Änderungen über diese Anwendung erfasst.":
        "The global save state is unknown. No changes made through this application have been recorded yet.",
    "Der Controller ist nicht mehr im Inventar vorhanden.": "The controller is no longer in the inventory.",
    "Für diesen Controller fehlen Zugangsdaten.": "Credentials are missing for this controller.",
    "Für diesen Controller wird bereits eine Änderung ausgeführt.": "A change is already running for this controller.",
    "Über diese Anwendung vorgenommene Änderungen wurden noch nicht am WLC gespeichert.":
        "Changes made through this application have not been saved on the WLC yet.",
    "Speichert die gesamte Running-Konfiguration einschließlich Änderungen anderer Administratoren.":
        "Saves the entire running configuration, including changes by other administrators.",
    "Die Auswirkungen sind nicht vollständig eingrenzbar; angezeigt werden vorsorglich alle bekannten APs.":
        "The impact cannot be fully narrowed down; all known APs are shown as a precaution.",
    "Das gesamte Konfigurationsobjekt einschließlich hier nicht dargestellter Eigenschaften wird entfernt.":
        "The entire configuration object, including properties not shown here, will be removed.",
    "Die Sicherheitsvorlage setzt AKM, Verschlüsselung, PMF und FT gemeinsam; weitere bisherige Sicherheitsoptionen werden zurückgesetzt.":
        "The security template sets AKM, encryption, PMF and FT together; other existing security options are reset.",
    "Die Rückkehr zu DCA hebt auch einen individuell konfigurierten Kanal auf.":
        "Returning to DCA also removes an individually configured channel.",
    "Gerätekonfiguration erfordert Administratorrechte.": "Device configuration requires administrator rights.",
    "Diese Änderung wird von den verfügbaren Controller-Fähigkeiten nicht unterstützt.":
        "This change is not supported by the available controller capabilities.",
    "Es ist keine belastbare Konfigurationsbaseline verfügbar.": "No reliable configuration baseline is available.",
    "Die Running-Konfiguration wurde zuletzt über diese Anwendung gespeichert. Fremdänderungen sind nicht erfasst.":
        "The running configuration was last saved through this application. Changes made elsewhere are not tracked.",
    "Die Änderung kann AP-Verbindungen neu aufbauen und verbundene Clients unterbrechen.":
        "The change may re-establish AP connections and interrupt connected clients.",
    "Die Ableitung übernimmt nur die hier verwalteten Felder.": "The derived object only takes over the fields managed here.",
    "Ein anderer Serverprozess bearbeitet diesen Controller.": "Another server process is working on this controller.",
    "Der letzte Änderungsausgang oder Speicherstand ist unklar. Gerätewerte vor weiteren Aktionen prüfen.":
        "The outcome of the last change or the save state is unclear. Check device values before further actions.",
    "Speicherstand unbekannt.": "Save state unknown.",
    "Gemeinsam verwendete WLAN-/Funk-Einstellungen können die Verbindung betroffener Clients unterbrechen.":
        "Shared WLAN/radio settings may interrupt the connection of affected clients.",
    "Die Vorschau ist abgelaufen oder gehört zu einer anderen Sitzung. Bitte erneut prüfen.":
        "The preview has expired or belongs to another session. Please review again.",
    "Diese Vorschau wurde bereits verwendet. Gerätewerte neu laden.":
        "This preview has already been used. Reload the device values.",
    "Controller oder Zugangsdaten wurden seit der Vorschau geändert.":
        "Controller or credentials have changed since the preview.",
    "Der Änderungsausgang ist nicht eindeutig.": "The outcome of the change is unclear.",
    "Die Ausführung wurde unerwartet unterbrochen. Gerätewerte neu lesen.":
        "Execution was interrupted unexpectedly. Re-read the device values.",
    "WLAN-Controller nicht gefunden": "WLAN controller not found",
    "Für diesen WLAN-Controller sind noch keine Zugangsdaten hinterlegt.":
        "No credentials have been stored for this WLAN controller yet.",
    "Beim erstmaligen Hinterlegen der Zugangsdaten ist ein Passwort erforderlich.":
        "A password is required when storing credentials for the first time.",
    "Controller oder Zugangsdaten wurden zwischenzeitlich geändert. Bitte den Dialog schließen und neu öffnen.":
        "Controller or credentials have changed in the meantime. Please close and reopen the dialog.",
    "Das Verbindungsziel wurde parallel geändert. Zugangsdaten wurden nicht gespeichert.":
        "The connection target was changed concurrently. Credentials were not saved.",
    "Die bestehenden Zugangsdaten wurden parallel entfernt. Bitte erneut öffnen.":
        "The existing credentials were removed concurrently. Please reopen.",
    "WLAN-Controller wurde zwischenzeitlich entfernt.": "The WLAN controller has been removed in the meantime.",
    "Ungültige AP-Kennung.": "Invalid AP identifier.",
    "Access Point nicht eindeutig gefunden.": "Access point not found unambiguously.",
    "Der Host darf keine Steuerzeichen enthalten.": "The host must not contain control characters.",
    "Es muss eine gültige IP-Adresse oder ein gültiger DNS-Name angegeben werden.":
        "A valid IP address or DNS name must be specified.",
    "Ein WLAN-Controller mit diesem Namen existiert bereits.": "A WLAN controller with this name already exists.",
    "Der Controller wurde zwischenzeitlich geändert. Bitte neu laden und erneut öffnen.":
        "The controller has changed in the meantime. Please reload and open it again.",
    "Die WLAN-Cache-Laufzeit ist ungültig.": "The WLAN cache lifetime is invalid.",
    "Die WLAN-Cache-Laufzeit muss größer als null sein.": "The WLAN cache lifetime must be greater than zero.",
    "Für den WLAN-Controller ist keine Plattform hinterlegt.": "No platform is configured for the WLAN controller.",
    "Für den WLAN-Controller ist kein Transport hinterlegt.": "No transport is configured for the WLAN controller.",
    "Der WLAN-Transport {transport} wird nicht unterstützt.": "The WLAN transport {transport} is not supported.",
    "Die WLAN-Controller-Plattform {platform} wird mit {transport} noch nicht unterstützt.":
        "The WLAN controller platform {platform} is not yet supported with {transport}.",
    "Der WLAN-Controller besitzt keine gültige ID.": "The WLAN controller has no valid ID.",
    "offset muss eine nichtnegative ganze Zahl sein.": "offset must be a non-negative integer.",
    "limit muss zwischen 1 und {max} liegen.": "limit must be between 1 and {max}.",
    "{name} muss eine Zeichenkette sein.": "{name} must be a string.",
    # wlan config_catalog labels/help (config_catalog.catalog_labels())
    "802.1X-Authentifizierungsliste": "802.1X authentication list",
    "AP aktiviert": "AP enabled",
    "AP neu starten": "Restart AP",
    "AP umbenennen": "Rename AP",
    "AP-Adminstatus": "AP admin state",
    "AP-Betriebsmodus": "AP operating mode",
    "AP-Join-Profil": "AP join profile",
    "AP-Join-Profile": "AP join profiles",
    "AP-LED aktiviert": "AP LED enabled",
    "AP-Name": "AP name",
    "AP-Radio-MAC": "AP radio MAC",
    "AP-Standort": "AP location",
    "AP-Tagzuweisung": "AP tag assignment",
    "ARP-Cache": "ARP cache",
    "Ableitung der hier verwalteten Felder. Weitere Eigenschaften erhalten Geräte-Defaults; "
    "Sicherheit und Schlüssel müssen für das neue WLAN ausdrücklich angegeben werden.":
        "Derives the fields managed here. Other properties get device defaults; "
        "security and keys must be specified explicitly for the new WLAN.",
    "Aus Site-Tag übernehmen": "Inherit from site tag",
    "Automatisch / RRM": "Automatic / RRM",
    "Automatisch stellt DCA wieder her; die Breite folgt dem RF-Profil.":
        "Automatic restores DCA; the width follows the RF profile.",
    "Beschreibung": "Description",
    "Betriebsmodus": "Operating mode",
    "CAPWAP-Heartbeat (s)": "CAPWAP heartbeat (s)",
    "CAPWAP-IP-Protokoll": "CAPWAP IP protocol",
    "Controller": "Controller",
    "Controller-Fallback": "Controller fallback",
    "DCA-Kanalbreite": "DCA channel width",
    "DCA-Kanäle": "DCA channels",
    "DHCP-Broadcast (Local Switching)": "DHCP broadcast (local switching)",
    "Discovery-Timeout (s)": "Discovery timeout (s)",
    "Ein Moduswechsel kann den AP neu verbinden oder neu starten. FlexConnect benötigt einen passenden Site-Tag.":
        "A mode change may reconnect or restart the AP. FlexConnect requires a matching site tag.",
    "Eine Vorlage setzt AKM, AES, PMF und FT gemeinsam; Enterprise benötigt eine vorhandene AAA-Liste.":
        "A template sets AKM, AES, PMF and FT together; Enterprise requires an existing AAA list.",
    "Ethernet-MAC": "Ethernet MAC",
    "FlexConnect": "FlexConnect",
    "FlexConnect-Profil": "FlexConnect profile",
    "FlexConnect-Profile": "FlexConnect profiles",
    "Funkband": "Band",
    "Funkbänder": "Bands",
    "IPv4-ACL": "IPv4 ACL",
    "IPv6-ACL": "IPv6 ACL",
    "Kanal": "Channel",
    "Kanalbreite": "Channel width",
    "Leistungsstufe (modellabhängig)": "Power level (model-dependent)",
    "Local": "Local",
    "Local-Site (kein FlexConnect)": "Local site (no FlexConnect)",
    "Lokaler Override": "Local override",
    "Monitor (keine Clients)": "Monitor (no clients)",
    "Name": "Name",
    "Native VLAN": "Native VLAN",
    "Neuer WLAN-Schlüssel": "New WLAN key",
    "Nur Kanäle, die alle betroffenen Radios unterstützen; bei unbekannter Regulierungsdomäne gesperrt.":
        "Only channels supported by all affected radios; locked if the regulatory domain is unknown.",
    "Nur für nicht lokale Sites. Der Site-Wechsel kann einen AP-Rejoin auslösen.":
        "Only for non-local sites. Changing the site may trigger an AP rejoin.",
    "Nur schreibbar; leer lassen behält den vorhandenen Schlüssel. Ableitungen benötigen einen neuen Schlüssel.":
        "Write-only; leave empty to keep the existing key. Derived WLANs require a new key.",
    "Policy-Profile": "Policy profiles",
    "Policy-Tag": "Policy tag",
    "Policy-Tags": "Policy tags",
    "Primärer Backup-Controller: IP": "Primary backup controller: IP",
    "Primärer Backup-Controller: Name": "Primary backup controller: name",
    "Profil aktiviert": "Profile enabled",
    "QoS ausgehend (SSID)": "QoS egress (SSID)",
    "QoS eingehend (SSID)": "QoS ingress (SSID)",
    "RF-Profil 2,4 GHz": "RF profile 2.4 GHz",
    "RF-Profil 5 GHz": "RF profile 5 GHz",
    "RF-Profil 6 GHz": "RF profile 6 GHz",
    "RF-Profile": "RF profiles",
    "RF-Tag": "RF tag",
    "RF-Tags": "RF tags",
    "Radio aktiviert": "Radio enabled",
    "Radio-Adminstatus": "Radio admin state",
    "Radio-Kanal": "Radio channel",
    "Radio-Kanalbreite": "Radio channel width",
    "Radio-Sendeleistung": "Radio transmit power",
    "Radio-Slot": "Radio slot",
    "Radios beim Fallback deaktivieren": "Disable radios on fallback",
    "Running-Konfiguration speichern": "Save running configuration",
    "SSID": "SSID",
    "SSID sichtbar": "SSID visible",
    "Sekundärer Backup-Controller: IP": "Secondary backup controller: IP",
    "Sekundärer Backup-Controller: Name": "Secondary backup controller: name",
    "Sicherheitsvorlage": "Security template",
    "Site-Tag": "Site tag",
    "Site-Tags": "Site tags",
    "Standort": "Location",
    "Steuerung": "Control",
    "Syslog-Server": "Syslog server",
    "Syslog-Stufe": "Syslog level",
    "TPC-Obergrenze (dBm)": "TPC maximum (dBm)",
    "TPC-Untergrenze (dBm)": "TPC minimum (dBm)",
    "Tags auf AP speichern": "Save tags on AP",
    "VLAN / Interface": "VLAN / interface",
    "VLAN-ID": "VLAN ID",
    "VLAN-Name": "VLAN name",
    "VLAN-Namen → IDs": "VLAN names → IDs",
    "VLAN-Tagging": "VLAN tagging",
    "WLAN aktiviert": "WLAN enabled",
    "WLAN → Policy-Profil": "WLAN → policy profile",
    "WLAN-ID": "WLAN ID",
    "WLANs": "WLANs",
    "Zentrale Authentifizierung": "Central authentication",
    "Zentrales DHCP": "Central DHCP",
    "Zentrales Switching": "Central switching",
    # Rolle Operator
    "Operator- oder Administratorrechte erforderlich": "Operator or administrator rights required",
    # Treiber-Gründe
    "Voice-VLAN ist auf dieser Plattform eine Port-Eigenschaft.": "On this platform the voice VLAN is a port setting.",
    "RouterOS kennt kein Voice-VLAN-Objekt.": "RouterOS has no voice VLAN object.",
    "RouterOS hat keine Startup-Konfiguration.": "RouterOS has no startup configuration.",
    "Ein RouterOS-Export enthält keine Zertifikatsschlüssel; nach dem Zurücksetzen wäre die REST-API nicht erreichbar.":
        "A RouterOS export contains no certificate keys; after the reset the REST API would be unreachable.",
    "Zeitgesteuertes Rollback ist unter IOS 15.2 nicht zuverlässig verfügbar.":
        "Timed rollback is not reliably available on IOS 15.2.",
    "Die Plattform hat kein zeitgesteuertes Rollback.": "The platform has no timed rollback.",
    "CRS3xx kennt keine MAC-Begrenzung pro Port.": "CRS3xx has no per-port MAC limit.",
    "RouterOS kennt keine 802.1X-Host-Modi und Ersatz-VLANs.": "RouterOS has no 802.1X host modes or fallback VLANs.",
    "RouterOS kennt keine Dynamic ARP Inspection.": "RouterOS has no Dynamic ARP Inspection.",
    "RouterOS kennt kein IP Source Guard.": "RouterOS has no IP Source Guard.",
    "AOS-S hat keine QoS-Trust-Einstellung pro Port.": "AOS-S has no per-port QoS trust setting.",
    "RouterOS bietet keine Voice-QoS-Vorlage pro Port.": "RouterOS offers no per-port voice QoS preset.",
    "CRS3xx unterstützt keinen Kabeltest.": "CRS3xx does not support a cable test.",
    "AOS-CX bietet kein Zurücksetzen der Port-Zähler.": "AOS-CX offers no way to reset the port counters.",
    "QoS-Hardware-Offloading ist auf diesem Gerät nicht aktiv.": "QoS hardware offloading is not active on this device.",
    "Netgear-Treiber setzt keine PoE-Leistungsprofile.": "The Netgear driver does not set PoE power profiles.",
    # Änderungspläne ausführen
    "Der Switch hat einen Befehl abgelehnt: {errors}": "The switch rejected a command: {errors}",
    "Änderung übernommen.": "Change applied.",
    "Unerwartete Rückfrage des Switches: {prompt}": "Unexpected question from the switch: {prompt}",
    "Der Switch hat den Befehl nicht rechtzeitig abgeschlossen: {command}":
        "The switch did not finish the command in time: {command}",
    "Der Switch hat den Befehl nicht bestätigt: {command}": "The switch did not confirm the command: {command}",
    # Betrieb (Einstellungen, Backups, Aufgaben)
    "Bitte ein Verzeichnis angeben.": "Please enter a directory.",
    "Die Transfer-Adresse muss eine http://- oder https://-URL ohne Pfad, Query oder abschließenden "
    "Schrägstrich sein.":
        "The transfer address must be an http:// or https:// URL without path, query or trailing slash.",
    "Ungültiger Hostname oder ungültige IPv4-Adresse: {value}": "Invalid host name or IPv4 address: {value}",
    "Die SFTP-Bind-Adresse muss eine IPv4-Adresse sein.": "The SFTP bind address must be an IPv4 address.",
    "Dieses Verzeichnis ist nicht erlaubt: {path}": "This directory is not allowed: {path}",
    "Verzeichnis ist nicht beschreibbar: {path}": "Directory is not writable: {path}",
    "Die Datei ist kein gültiges verschlüsseltes Backup.": "The file is not a valid encrypted backup.",
    "Backup kann mit dem hinterlegten Passwort nicht entschlüsselt werden.":
        "The backup cannot be decrypted with the stored password.",
    "Für die Backup-Verschlüsselung ist kein Passwort hinterlegt.": "No password is stored for backup encryption.",
    "Für die Backup-Verschlüsselung ist ein Passwort erforderlich.": "Backup encryption requires a password.",
    "Backup nicht gefunden.": "Backup not found.",
    "Backup-Datei fehlt oder ist nicht lesbar: {file}": "Backup file is missing or unreadable: {file}",
    "Backup {file} konnte nicht umgewandelt werden: {error}": "Backup {file} could not be converted: {error}",
    "Unbekannte Aufgabe: {kind}": "Unknown job: {kind}",
    "Server-Neustart während der Ausführung.": "Server restart during execution.",
    "Termin verpasst (Server war nicht erreichbar).": "Scheduled time missed (server was not reachable).",
    "Aufgabe nicht gefunden.": "Job not found.",
    "Nur geplante Aufgaben, die noch nicht laufen, können abgebrochen werden.":
        "Only scheduled jobs that are not running yet can be cancelled.",
    # Änderungs-Framework (Vorschau, Anwenden, Uplinks, Speicherstand)
    "Die Vorschau ist abgelaufen oder gehört zu einer anderen Sitzung. Bitte neu erstellen.":
        "The preview has expired or belongs to another session. Please create it again.",
    "Der Switch-Zustand hat sich seit der Vorschau geändert. Bitte Vorschau neu erstellen.":
        "The switch state has changed since the preview. Please create a new preview.",
    "Diese Änderung muss ausdrücklich bestätigt werden: {reason}": "This change must be confirmed explicitly: {reason}",
    "Erst die laufende Änderung bestätigen oder zurücksetzen.": "Confirm or revert the pending change first.",
    "Für diesen Switch wird bereits eine Änderung ausgeführt.": "A change is already running on this switch.",
    "Ein anderer Serverprozess bearbeitet diesen Switch.": "Another server process is changing this switch.",
    "Operatoren dürfen diese Änderung nicht ausführen: {reason}": "Operators may not make this change: {reason}",
    "Operatoren dürfen nur Access-Ports ändern.": "Operators may only change access ports.",
    "Für diese Änderung ist kein automatisches Rollback möglich.": "Automatic rollback is not available for this change.",
    "Das automatische Rollback konnte nicht aktiviert werden: {error}": "Automatic rollback could not be armed: {error}",
    "Zusatzschritt fehlgeschlagen: {error}": "Additional step failed: {error}",
    "Auftrag wurde angelegt.": "Job created.",
    "Management-Verbindung von SwitchSteward läuft über diesen Port.":
        "SwitchSteward's management connection runs through this port.",
    "Nachbar {name} ist ein Switch/Router.": "Neighbor {name} is a switch/router.",
    "Gehört zur Link-Aggregation {lag} mit einem Uplink.": "Belongs to link aggregation {lag} with an uplink.",
    "Uplinks konnten nicht vollständig erkannt werden: {source}": "Uplinks could not be fully detected: {source}",
    "Management-Pfad": "management path",
    "Nachbarn": "neighbors",
    "Link-Aggregation": "link aggregation",
    "VLAN {vlan} ist das Management-VLAN; SwitchSteward kann den Switch danach eventuell nicht mehr erreichen.":
        "VLAN {vlan} is the management VLAN; SwitchSteward may no longer reach the switch afterwards.",
    "Das Management-VLAN konnte nicht ermittelt werden.": "The management VLAN could not be determined.",
    "Die Verbindung zum Switch ist nach einem Zeitlimit nicht mehr sicher nutzbar; es wurde nichts gesendet. "
    "Bitte erneut versuchen.":
        "The connection to the switch is no longer safe to use after a timeout; nothing was sent. Please try again.",
    # Link-Aggregation und Spanning Tree
    "Bitte eine VLAN-Liste wie 10,20-30 angeben.": "Please enter a VLAN list such as 10,20-30.",
    "Diese Einstellung wird vom Switch nicht unterstützt: {value}": "The switch does not support this setting: {value}",
    "LAG-ID außerhalb des gültigen Bereichs 1-{max}: {value}": "LAG ID outside the valid range 1-{max}: {value}",
    "Nur physische Ports können LAG-Mitglied sein: {port}": "Only physical ports can be LAG members: {port}",
    "Port {port} ist doppelt angegeben.": "Port {port} is listed twice.",
    "Port {port} ist bereits Mitglied von LAG {lag}.": "Port {port} is already a member of LAG {lag}.",
    "Port {port} ist kein Mitglied von LAG {lag}.": "Port {port} is not a member of LAG {lag}.",
    "Die Link-Aggregation betrifft Uplink-Ports: {ports}": "The link aggregation affects uplink ports: {ports}",
    "LAG {lag} existiert auf dem Switch nicht.": "LAG {lag} does not exist on the switch.",
    "LAG {lag} existiert bereits.": "LAG {lag} already exists.",
    "Ein LAG braucht mindestens ein Mitglied; zum Entfernen bitte löschen.":
        "A LAG needs at least one member; delete it to remove it.",
    "Ein LAG hat höchstens {count} Mitglieder.": "A LAG has at most {count} members.",
    "Spanning-Tree-Änderungen können das Netz kurzzeitig unterbrechen.":
        "Spanning tree changes can briefly interrupt the network.",
    "Die Priorität muss ein Vielfaches von 4096 sein.": "The priority must be a multiple of 4096.",
    "Bitte entweder VLANs oder eine Instanz angeben.": "Please enter either VLANs or an instance.",
    "MST-Instanz {id} ist doppelt angegeben.": "MST instance {id} is listed twice.",
    "VLAN {vlan} ist mehreren MST-Instanzen zugeordnet ({first}, {second}).":
        "VLAN {vlan} is mapped to several MST instances ({first}, {second}).",
    "Die Port-Priorität muss ein Vielfaches von 16 sein.": "The port priority must be a multiple of 16.",
    # Port-Sicherheit und Port-Profile
    "Port-Security ist nur an Access-Ports möglich.": "Port security is only possible on access ports.",
    "Dynamic ARP Inspection kann den Management-Verkehr blockieren, wenn Uplinks nicht vertrauenswürdig sind.":
        "Dynamic ARP Inspection can block management traffic if uplinks are not trusted.",
    "Für 802.1X muss zuerst ein RADIUS-Server konfiguriert werden.":
        "A RADIUS server must be configured before enabling 802.1X.",
    "Nicht übernommen (inkompatibel): {fields}.": "Not applied (incompatible): {fields}.",
    "Das Port-Profil existiert nicht.": "The port profile does not exist.",
    "Kein Feld des Profils wird von diesem Switch unterstützt.": "This switch supports none of the profile's fields.",
    "Bitte konkrete VLANs angeben.": "Please enter specific VLANs.",
    "Der Profilname darf 1–64 Zeichen aus Buchstaben, Ziffern, Leerzeichen, Punkt, Unterstrich und Bindestrich enthalten.":
        "The profile name may contain 1–64 letters, digits, spaces, dots, underscores and hyphens.",
    "Ein Port-Profil benötigt Port- oder Sicherheitseinstellungen.": "A port profile needs port or security settings.",
    "Ein Port-Profil darf das Feld {field} nicht enthalten.": "A port profile must not contain the field {field}.",
    "Die Beschreibung enthält ungültige Zeichen.": "The description contains invalid characters.",
    "Ein Port-Profil mit diesem Namen existiert bereits.": "A port profile with this name already exists.",
    # Geräteeinstellungen und VLAN-Rollout
    'ACL {name} existiert auf dem Switch nicht.':
        'ACL {name} does not exist on the switch.',
    'ACL {name} existiert bereits.':
        'ACL {name} already exists.',
    'Benutzer {name} existiert auf dem Switch nicht.':
        'User {name} does not exist on the switch.',
    'Das Ende des Portbereichs muss größer oder gleich dem Anfang sein.':
        'The end of the port range must be greater than or equal to its start.',
    'Das Konto, mit dem SwitchSteward sich anmeldet, kann hier nicht geändert werden.':
        'The account SwitchSteward signs in with cannot be changed here.',
    'Der Banner darf höchstens 1000 druckbare ASCII-Zeichen enthalten, aber keines von ^ # ".':
        'The banner may contain at most 1000 printable ASCII characters, but none of ^ # ".',
    'Der Eintrag {seq} existiert bereits.':
        'Entry {seq} already exists.',
    'Der Eintrag {seq} existiert nicht.':
        'Entry {seq} does not exist.',
    'Der Text darf keine Anführungszeichen enthalten.':
        'The text must not contain quotation marks.',
    'Die ACL ist noch an {interfaces} gebunden.':
        'The ACL is still bound to {interfaces}.',
    'Die ACL wird an das Management-Interface gebunden und kann SwitchSteward aussperren.':
        'The ACL is bound to the management interface and can lock out SwitchSteward.',
    'Die lokale Anmeldung muss als Rückfallebene erhalten bleiben.':
        'Local login must remain as a fallback.',
    'Die Änderung betrifft die Management-Adresse oder das Routing des Switches; SwitchSteward kann den Switch danach eventuell nicht mehr erreichen.':
        "The change affects the switch's management address or routing; SwitchSteward may no longer reach the switch afterwards.",
    'Ein Portbereich braucht den Vergleich range.':
        'A port range needs the comparison range.',
    'Ein Verschlüsselungsschlüssel braucht ein Verschlüsselungsverfahren.':
        'An encryption key needs an encryption method.',
    'Ein Zielport braucht einen Vergleich (eq oder range).':
        'A destination port needs a comparison (eq or range).',
    'Eine Standard-ACL prüft nur die Quelladresse.':
        'A standard ACL only matches the source address.',
    'Es fehlt der Zielport.':
        'The destination port is missing.',
    'Für den neuen Server {host} ist ein Schlüssel erforderlich.':
        'A key is required for the new server {host}.',
    'Für die Verschlüsselung ist ein Schlüssel erforderlich.':
        'A key is required for encryption.',
    'Für einen neuen Benutzer ist ein Passwort erforderlich.':
        'A password is required for a new user.',
    'Jeder Server darf nur einmal angegeben werden.':
        'Each server may only be listed once.',
    'Kein Kandidat der Vorschau: {interfaces}':
        'Not a candidate of the preview: {interfaces}',
    'Keine Änderung nötig.':
        'No change needed.',
    'Schlüssel und Passwörter brauchen 8-64 druckbare Zeichen ohne Leerzeichen, ", ? und \\.':
        'Keys and passwords need 8-64 printable characters without spaces, ", ? and \\.',
    'Ungültige Adresse: {value}':
        'Invalid address: {value}',
    'Ungültige IPv4-Adresse: {value}':
        'Invalid IPv4 address: {value}',
    'Ungültiger ACL-Name: {value}':
        'Invalid ACL name: {value}',
    'Ungültiger Benutzername: {value}':
        'Invalid user name: {value}',
    'Ungültiger Hostname: {value}':
        'Invalid hostname: {value}',
    'Ungültiges IPv4-Netz: {value}':
        'Invalid IPv4 network: {value}',
    'Zieladresse und Präfixlänge müssen gemeinsam angegeben werden.':
        'Destination address and prefix length must be given together.',
    'Zielports gibt es nur für TCP und UDP.':
        'Destination ports only exist for TCP and UDP.',
    'Änderungen an der Anmeldung können den Zugang von SwitchSteward sperren.':
        "Changes to the login can lock out SwitchSteward's access.",
    # Cisco-Geräteeinstellungen und Firmware
    "Statische Routen erfordern ip routing; auf diesem Switch ist Routing nicht aktiv.":
        "Static routes require ip routing; routing is not active on this switch.",
    "QoS wird global aktiviert; nicht vertrauenswürdige Ports setzen DSCP auf 0.":
        "QoS is enabled globally; untrusted ports set DSCP to 0.",
    "Ungültige Zeitzone: {value}": "Invalid time zone: {value}",
    "Diese Plattform erlaubt nur einen gemeinsamen Syslog-Schweregrad für alle Ziele.":
        "This platform only allows one common syslog severity for all targets.",
    "Diese Plattform unterstützt für SNMPv3 nur SHA.": "This platform only supports SHA for SNMPv3.",
    "SNMP-Benutzer {name} existiert auf dem Switch nicht.": "SNMP user {name} does not exist on the switch.",
    "Für die Anmeldung über {method} ist kein Server konfiguriert.": "No server is configured for login via {method}.",
    "Das VLAN-Interface {vlan} existiert auf dem Switch nicht.": "VLAN interface {vlan} does not exist on the switch.",
    "Die Route existiert auf dem Switch nicht.": "The route does not exist on the switch.",
    "Das Interface {interface} kann keine ACL tragen.": "Interface {interface} cannot carry an ACL.",
    "Die ACL {name} ist an {interface} nicht gebunden.": "ACL {name} is not bound to {interface}.",
    "Das Image {file} liegt nicht im Flash des Switches; bitte zuerst übertragen.":
        "Image {file} is not in the switch's flash; please transfer it first.",
    "Die aktuelle Konfiguration wird dabei gespeichert (write memory).":
        "The current configuration is saved in the process (write memory).",
    # Firmware, Neustart, Diagnose
    "Firmware-Image ist zu groß.": "Firmware image is too large.",
    "Firmware-Image fehlt.": "Firmware image is missing.",
    "Das Firmware-Image muss als Binärdatei (application/octet-stream) hochgeladen werden.":
        "The firmware image must be uploaded as a binary file (application/octet-stream).",
    "Ungültiger Dateiname: erlaubt sind 1–128 Zeichen A–Z, a–z, 0–9, Punkt, Unterstrich und Bindestrich "
    "(erstes Zeichen Buchstabe oder Ziffer).":
        "Invalid file name: 1–128 characters A–Z, a–z, 0–9, dot, underscore and hyphen are allowed "
        "(first character a letter or digit).",
    "Bitte mindestens eine gültige Plattform wählen (unbekannt: {platforms}).":
        "Please choose at least one valid platform (unknown: {platforms}).",
    "Das Firmware-Image ist leer.": "The firmware image is empty.",
    "Ein Firmware-Image mit diesem Dateinamen existiert bereits.": "A firmware image with this file name already exists.",
    "Firmware-Image nicht gefunden.": "Firmware image not found.",
    "Das Firmware-Image wird von einer geplanten oder laufenden Aufgabe verwendet.":
        "The firmware image is used by a scheduled or running job.",
    "Das Firmware-Image ist für diese Plattform nicht freigegeben.":
        "The firmware image is not released for this platform.",
    "Nicht genug freier Speicher auf dem Switch.": "Not enough free storage on the switch.",
    "Übertragung gestartet.": "Transfer started.",
    "Im Install-Modus startet die Aktivierung den Switch neu; bitte „jetzt“ oder einen Zeitpunkt wählen.":
        "In install mode the activation restarts the switch; please choose “now” or a point in time.",
    "Der Switch startet mit der neuen Firmware; bis zum Neustart bleibt die aktuelle Firmware aktiv.":
        "The switch starts with the new firmware; the current firmware stays active until the restart.",
    "Der Switch startet neu; alle Ports sind kurz offline.": "The switch restarts; all ports are briefly offline.",
    "Ungespeicherte Änderungen gehen beim Neustart verloren.": "Unsaved changes are lost when the switch restarts.",
    "Ungültiger Zeitpunkt: bitte ISO-Format in UTC angeben.": "Invalid point in time: please use ISO format in UTC.",
    "Der Zeitpunkt muss mindestens 2 Minuten und höchstens 30 Tage in der Zukunft liegen.":
        "The point in time must be at least 2 minutes and at most 30 days in the future.",
    "Neustart ist für {run_at} UTC geplant.": "Restart is scheduled for {run_at} UTC.",
    "Neustart geplant für {run_at} UTC.": "Restart scheduled for {run_at} UTC.",
    "Neustart ausgelöst.": "Restart triggered.",
    "Der Kabeltest unterbricht die Verbindung am Port für einige Sekunden.":
        "The cable test interrupts the connection on the port for a few seconds.",
    # Backup, Transfer, Wiederherstellung, Rollback
    "In Administration → Betrieb ist keine Transfer-Adresse hinterlegt.":
        "No transfer address is configured in Administration → Operations.",
    "Der SFTP-Transfer ist in Administration → Betrieb nicht aktiviert.":
        "The SFTP transfer is not enabled in Administration → Operations.",
    "Diese Plattform lädt per SFTP nur von Port 22. Bitte den SFTP-Port in Administration → Betrieb auf 22 setzen.":
        "This platform downloads via SFTP only from port 22. Please set the SFTP port to 22 in "
        "Administration → Operations.",
    "Der Dateiname ist für diese Plattform zu lang (höchstens {limit} Zeichen).":
        "The file name is too long for this platform (at most {limit} characters).",
    "Der SFTP-Server konnte nicht gestartet werden: {error}": "The SFTP server could not be started: {error}",
    "Backup konnte nicht erstellt werden: {error}": "Backup could not be created: {error}",
    "Der Switch übernimmt die Konfiguration aus dem Backup und startet neu.":
        "The switch takes over the configuration from the backup and restarts.",
    "Ungültiger Vergleich: {value}": "Invalid comparison: {value}",
    "Für diesen Switch läuft kein automatisches Rollback.": "No automatic rollback is running for this switch.",
    "Änderung wurde zurückgesetzt.": "Change was reverted.",
    "Änderung wurde bestätigt.": "Change was confirmed.",
    # Cisco-Treiber (Port-Aktionen, Port-Sicherheit, Link-Aggregation)
    "Der Port ist nicht durch eine Schutzfunktion deaktiviert.": "The port is not disabled by a protection feature.",
    "PoE ist an Port {interface} ausgeschaltet; ein PoE-Neustart ist nicht möglich.":
        "PoE is switched off on port {interface}; a PoE restart is not possible.",
    "Root Guard und Loop Guard schließen sich an einem Port aus.":
        "Root guard and loop guard are mutually exclusive on a port.",
    "Ersatz-VLANs werden bei IBNS-2.0-Konfiguration über Richtlinien gesetzt und sind hier nicht einstellbar.":
        "With an IBNS 2.0 configuration, fallback VLANs are set by policies and cannot be set here.",
    "Der Modus von LAG {lag} konnte nicht gelesen werden.": "The mode of LAG {lag} could not be read.",
    # AOS-CX-Geräteeinstellungen und Firmware
    "Diese Plattform stellt Zeitzonen nur in ganzen Stunden ein.": "This platform only sets time zones in whole hours.",
    "Diese Plattform stellt den Timeout nur in ganzen Minuten ein.": "This platform only sets the timeout in whole minutes.",
    "SNMPv3-Schlüssel dürfen auf dieser Plattform höchstens {limit} Zeichen lang sein.":
        "On this platform SNMPv3 keys may be at most {limit} characters long.",
    "Die Voice-Vorlage setzt auf dieser Plattform Trust DSCP voraus.":
        "On this platform the voice preset requires trust DSCP.",
    "Das aktive Image des Switches konnte nicht ermittelt werden.": "The active image of the switch could not be determined.",
    # AOS-CX-Treiber (Voice-VLAN)
    "Ein Voice-VLAN ist nur an Access-Ports möglich.": "A voice VLAN is only possible on access ports.",
    "Voice-VLAN und Access-VLAN müssen verschieden sein.": "The voice VLAN and the access VLAN must differ.",
    # AOS-S-Geräteeinstellungen und Firmware
    "AOS-S erlaubt eine Anmeldemethode vor der lokalen Anmeldung; die lokale Anmeldung muss die letzte sein.":
        "AOS-S allows one login method before local login; local login must be the last one.",
    "AOS-S ändert die Berechtigung eines Benutzers nur zusammen mit dem Passwort.":
        "AOS-S only changes a user's privilege together with the password.",
    "AOS-S kennt nur einen Benutzer pro Stufe; der bisherige {slot}-Zugang wird ersetzt.":
        "AOS-S has only one user per level; the previous {slot} account is replaced.",
    "Der Timeout muss auf dieser Plattform einer dieser Minutenwerte sein: {values}.":
        "On this platform the timeout must be one of these minute values: {values}.",
    # AOS-S-Treiber (Port-Aktionen, Port-Sicherheit)
    "unbekannt": "unknown",
    "AOS-S verwendet ein gemeinsames VLAN für Gäste und fehlgeschlagene Anmeldungen.":
        "AOS-S uses one VLAN for guests and failed authentications.",
    "AOS-S kann einen Port nur bei Broadcast- oder Multicast-Stürmen abschalten.":
        "AOS-S can only shut down a port on broadcast or multicast storms.",
    "Multi-Host ist bei AOS-S nur mit 802.1X ohne MAB möglich.":
        "On AOS-S, multi-host is only possible with 802.1X without MAB.",
    # Netgear-Treiber (Port-Sicherheit, Spanning Tree)
    "Multi-Host ist bei diesem Switch nur mit 802.1X ohne MAB möglich.":
        "On this switch, multi-host is only possible with 802.1X without MAB.",
    "Diese Plattform unterstützt höchstens {count} MST-Instanzen.":
        "This platform supports at most {count} MST instances.",
    # Netgear-Geräteeinstellungen und Firmware
    "Der Text darf auf dieser Plattform höchstens {limit} Zeichen haben.":
        "On this platform the text may have at most {limit} characters.",
    "Der Banner darf auf dieser Plattform nur eine Zeile haben.": "On this platform the banner may only have one line.",
    "Diese Plattform unterstützt höchstens {count} Zeitserver.": "This platform supports at most {count} time servers.",
    "Diese Plattform unterstützt für SNMPv3 nur SHA-512; der Benutzer wird mit SHA-512 angelegt.":
        "This platform only supports SHA-512 for SNMPv3; the user is created with SHA-512.",
    "M5300/M7100 unterstützen für SNMPv3 nur SHA und DES; AES-128 ist nicht möglich.":
        "M5300/M7100 only support SHA and DES for SNMPv3; AES-128 is not possible.",
    "Auf M5300/M7100 ist ein SNMPv3-Benutzer ein lokaler Benutzer; bitte zuerst den lokalen Benutzer {name} anlegen.":
        "On M5300/M7100 an SNMPv3 user is a local user; please create the local user {name} first.",
    "Auf M5300/M7100 ist der SNMPv3-Schlüssel das Anmeldepasswort des lokalen Benutzers; es wird auf den angegebenen "
    "Schlüssel gesetzt.":
        "On M5300/M7100 the SNMPv3 key is the login password of the local user; it is set to the given key.",
    "RADIUS-Schlüssel dürfen auf dieser Plattform höchstens 16 Buchstaben und Ziffern haben.":
        "On this platform RADIUS keys may have at most 16 letters and digits.",
    "Die lokale Anmeldung muss auf dieser Plattform die letzte Methode sein.":
        "On this platform local login must be the last method.",
    "Diese Plattform ändert die Berechtigung eines Benutzers nur zusammen mit dem Passwort.":
        "This platform only changes a user's privilege together with the password.",
    "Zähler wurden nur für {count} Ports gelesen.": "Counters were only read for {count} ports.",
    "Für diesen Port liegt kein Kabeltest-Ergebnis vor; bitte den Kabeltest starten.":
        "There is no cable test result for this port; please start the cable test.",
    # MikroTik-Geräteeinstellungen und Firmware
    "Der Bereich {section} konnte nicht gelesen werden.": "The section {section} could not be read.",
    "RouterOS kennt keinen Domänennamen; das Feld wird nicht unterstützt.":
        "RouterOS has no domain name; the field is not supported.",
    "RouterOS braucht für die Zeitzone den Zeitversatz in Minuten.":
        "RouterOS needs the time zone offset in minutes.",
    "RouterOS speichert nur den Zeitversatz; der Name {name} wird nicht übernommen.":
        "RouterOS only stores the offset; the name {name} is not applied.",
    "Ungültiger Schweregrad: {value}": "Invalid severity: {value}",
    "RouterOS hat keinen TACACS+-Client.": "RouterOS has no TACACS+ client.",
    "RouterOS meldet immer zuerst lokal und danach per RADIUS an.":
        "RouterOS always signs in locally first and then via RADIUS.",
    "Ungültige Berechtigung: {value}": "Invalid privilege: {value}",
    "RouterOS hat keinen einstellbaren SSH-Timeout.": "RouterOS has no configurable SSH timeout.",
    "Diese RouterOS-Version kann WebFig über HTTPS nicht getrennt von der REST-API abschalten; nur HTTP (www) wird "
    "deaktiviert.":
        "This RouterOS version cannot disable WebFig over HTTPS separately from the REST API; only HTTP (www) is "
        "disabled.",
    "Die Route existiert bereits.": "The route already exists.",
    "Ungültiger ACL-Typ: {value}": "Invalid ACL type: {value}",
    "Der Switch-Chip konnte nicht ermittelt werden.": "The switch chip could not be determined.",
    "RouterOS-Switch-Regeln erlauben keine Portbereiche.": "RouterOS switch rules do not allow port ranges.",
    "Änderungen an Switch-Regeln deaktivieren alle Switch-Regeln kurzzeitig.":
        "Changes to switch rules briefly deactivate all switch rules.",
    "Ungültige Sequenznummer: {value}": "Invalid sequence number: {value}",
    "Ungültiger ACL-Eintrag.": "Invalid ACL entry.",
    "Ungültige Richtung: {value}": "Invalid direction: {value}",
    "RouterOS-Switch-Regeln filtern nur eingehenden Verkehr; an Ports ist nur „in“ möglich.":
        "RouterOS switch rules only filter incoming traffic; only “in” is possible on ports.",
    "Die ACL {name} hat keine Einträge.": "ACL {name} has no entries.",
    "Die ACL {name} ist an {interface} bereits gebunden.": "ACL {name} is already bound to {interface}.",
    "An {interface} ist bereits die ACL {other} gebunden.": "ACL {other} is already bound to {interface}.",
    "Bei aktivem L3-Hardware-Offloading umgeht gerouteter Verkehr die Firewall-Regeln.":
        "With L3 hardware offloading active, routed traffic bypasses the firewall rules.",
    "Ungültiger Trust-Modus: {value}": "Invalid trust mode: {value}",
    "RouterOS installiert nur .npk-Pakete.": "RouterOS only installs .npk packages.",
    "RouterOS lädt Firmware nur per HTTP(S).": "RouterOS only downloads firmware via HTTP(S).",
    "RouterOS hat keine Prüfsummenfunktion; die Prüfsumme wird nur auf dem Server geprüft, die Paketsignatur prüft "
    "RouterOS bei der Installation.":
        "RouterOS has no checksum function; the checksum is only verified on the server, RouterOS verifies the "
        "package signature during installation.",
    "RouterOS installiert {file} beim nächsten Neustart.": "RouterOS installs {file} at the next restart.",
    "Ein Downgrade startet den Switch sofort neu; bitte „jetzt“ wählen.":
        "A downgrade restarts the switch immediately; please choose “now”.",
    "Die Datei {file} auf dem Switch ist größer als das Image.": "The file {file} on the switch is larger than the image.",
    "Die Übertragung von {file} wurde nicht abgeschlossen ({size} von {total} Bytes).":
        "The transfer of {file} did not complete ({size} of {total} bytes).",
    # MikroTik-Treiber (Port-Aktionen, Port-Sicherheit, LAG, Spanning Tree)
    "Telefone erfahren das Voice-VLAN nur per LLDP-MED; diese globale Einstellung wird nicht geändert.":
        "Phones only learn the voice VLAN via LLDP-MED; this global setting is not changed.",
    "RouterOS erlaubt nur einen gemeinsamen Grenzwert pro Port.": "RouterOS only allows one shared limit per port.",
    "RouterOS wendet DHCP-Snooping auf die ganze Bridge an; die VLAN-Liste muss leer sein.":
        "RouterOS applies DHCP snooping to the whole bridge; the VLAN list must be empty.",
    "RouterOS bietet Loop Guard nicht pro Port an.": "RouterOS does not offer loop guard per port.",
    "RouterOS kann bei Stürmen nur verwerfen, nicht abschalten.": "RouterOS can only drop on storms, not shut down.",
    "RouterOS kennt keine Priorität pro VLAN; bitte MST-Instanzen verwenden.":
        "RouterOS has no per-VLAN priority; please use MST instances.",
    "Spanning Tree ist nur mit genau einer Bridge mit VLAN-Filterung einstellbar.":
        "Spanning tree can only be configured with exactly one bridge with VLAN filtering.",
    "Interface {interface} ist kein aktiver Bridge-Port.": "Interface {interface} is not an active bridge port.",
    "MST-Instanz {instance} existiert auf dem Switch nicht.": "MST instance {instance} does not exist on the switch.",
    "Port {interface} ist ausgeschaltet; ein Neustart des Ports ist nicht möglich.":
        "Port {interface} is switched off; the port cannot be restarted.",
    "Speed/Duplex werden an den Mitgliedern eines LAG eingestellt.":
        "Speed/duplex are set on the members of a LAG.",
    "Der 802.1X-Status konnte nicht gelesen werden.": "The 802.1X status could not be read.",
    "Der Zustand der Bridge-Ports konnte nicht gelesen werden.": "The state of the bridge ports could not be read.",
    "Der Spanning-Tree-Zustand konnte nicht gelesen werden.": "The spanning tree state could not be read.",
    "Spanning-Tree-Modus": "spanning tree mode",
    # VTP
    "VTP ist ein Cisco-Protokoll und wird von diesem Switch-Typ nicht unterstützt.":
        "VTP is a Cisco protocol and is not supported by this switch type.",
    "VTP-Modus": "VTP mode",
    "VTP-Version": "VTP version",
    "Das VTP-Passwort darf höchstens 32 Zeichen lang sein.": "The VTP password may be at most 32 characters long.",
    "Ungültiger VTP-Domänenname: 1–32 Zeichen, erlaubt sind Buchstaben, Ziffern, Punkt, Unterstrich und Bindestrich.":
        "Invalid VTP domain name: 1–32 characters; letters, digits, dot, underscore and hyphen are allowed.",
    "VTP-Einstellungen übernommen (noch nicht dauerhaft gespeichert).":
        "VTP settings applied (not yet saved permanently).",
    "VTP-Version 3 benötigt einen VTP-Domänennamen.": "VTP version 3 requires a VTP domain name.",
    "Der Modus Server benötigt einen VTP-Domänennamen.": "Server mode requires a VTP domain name.",
    "'hidden' ist nur mit VTP-Version 3 möglich.": "'hidden' is only possible with VTP version 3.",
    "Der Switch ist jetzt VTP Primary Server.": "The switch is now the VTP primary server.",
    "Passwort setzen und entfernen schließen sich aus.": "Setting and removing the password are mutually exclusive.",
    "'hidden' braucht ein neues Passwort.": "'hidden' requires a new password.",
    "Mindestens eine VTP-Einstellung muss geändert werden.": "At least one VTP setting must be changed.",
    "VTP-Änderungen wirken auf die ganze Domäne: Ein Server oder Client mit höherer Konfigurationsrevision "
    "überschreibt die VLAN-Datenbank aller Switches der Domäne; fehlende VLANs legen Ports still.":
        "VTP changes affect the whole domain: a server or client with a higher configuration revision overwrites "
        "the VLAN database of every switch in the domain; missing VLANs shut down ports.",
    "Ein neuer Domänenname setzt die Konfigurationsrevision auf 0.":
        "A new domain name resets the configuration revision to 0.",
    "Im Modus Transparent oder Aus übernimmt der Switch keine VLAN-Änderungen der Domäne mehr.":
        "In transparent or off mode the switch no longer takes over VLAN changes of the domain.",
    "Ein abweichendes VTP-Passwort trennt den Switch von der VTP-Synchronisation der Domäne.":
        "A different VTP password disconnects the switch from the domain's VTP synchronization.",
    "VTP-Pruning ändert domänenweit, welche VLANs über Trunks weitergeleitet werden.":
        "VTP pruning changes domain-wide which VLANs are forwarded over trunks.",
    "Der Switch wird Primary Server: Seine VLAN-Datenbank (Revision {revision}) wird an alle Switches der "
    "Domäne {domain} verteilt und ersetzt dort die bestehenden VLANs.":
        "The switch becomes the primary server: its VLAN database (revision {revision}) is distributed to every "
        "switch in domain {domain} and replaces the existing VLANs there.",
    "Der Switch hat keinen Fehler gemeldet, die VTP-Änderung ist aber nicht sichtbar: {fields}":
        "The switch reported no error, but the VTP change is not visible: {fields}",
    "'Primary übernehmen' gibt es nur mit VTP-Version 3.": "'Take over primary' only exists with VTP version 3.",
    "Nur ein VTPv3-Server kann Primary Server werden.": "Only a VTPv3 server can become the primary server.",
    "Der Switch ist bereits Primary Server.": "The switch already is the primary server.",
    "Der Switch hat keinen Fehler gemeldet, ist aber nicht Primary Server geworden.":
        "The switch reported no error, but did not become the primary server.",
    "VTP-Client: Die VLANs dieses Switches kommen per VTP aus der Domäne {domain}; Änderungen nur am VTP-Server "
    "bzw. Primary Server ({primary}).":
        "VTP client: the VLANs of this switch come via VTP from domain {domain}; change them only on the VTP "
        "server or primary server ({primary}).",
    "VTPv3-Secondary-Server: VLAN-Änderungen nimmt nur der Primary Server an (zuletzt {primary}). "
    "'Primary übernehmen' macht diesen Switch zum Primary Server.":
        "VTPv3 secondary server: only the primary server accepts VLAN changes (last {primary}). "
        "'Take over primary' makes this switch the primary server.",
    "Mit VTP-Version {version} im Modus {mode} sind erweiterte VLANs (1006–4094) nicht möglich; dafür Modus "
    "Transparent/Aus oder VTP-Version 3 verwenden.":
        "With VTP version {version} in {mode} mode, extended VLANs (1006–4094) are not possible; use transparent/off "
        "mode or VTP version 3 for them.",
    "Switches im Modus Server/Client ohne VTP-Domäne: {names}.":
        "Switches in server/client mode without a VTP domain: {names}.",
    "Unterschiedliche VTP-Versionen im Modus Server/Client: {details}.":
        "Different VTP versions in server/client mode: {details}.",
    "Die Server/Clients sind nicht synchron (Revision/MD5 unterschiedlich): {details}.":
        "The servers/clients are not in sync (revision/MD5 differ): {details}.",
    "VTP-Passwort nur auf einem Teil der Switches gesetzt: {names}.":
        "VTP password set on only some of the switches: {names}.",
    "Die Switches melden unterschiedliche Primary Server: {ids}.": "The switches report different primary servers: {ids}.",
    "Mehrere Switches sind Primary Server: {names}.": "Several switches are primary servers: {names}.",
    "Kein Switch ist aktuell Primary Server (zuletzt {name}); VLAN-Änderungen sind erst nach "
    "'Primary übernehmen' möglich.":
        "No switch is currently the primary server (last {name}); VLAN changes are only possible after "
        "'Take over primary'.",
    "Der Primary Server {description} ({id}) wird nicht von SwitchSteward verwaltet; sein Status kann nicht "
    "geprüft werden.":
        "The primary server {description} ({id}) is not managed by SwitchSteward; its status cannot be checked.",
    "Die Domäne hat keinen Primary Server; VLAN-Änderungen sind erst nach 'Primary übernehmen' möglich.":
        "The domain has no primary server; VLAN changes are only possible after 'Take over primary'.",
    "Kein verwalteter VTP-Server in der Domäne; die Clients erhalten ihre VLANs von einem nicht verwalteten Switch.":
        "No managed VTP server in the domain; the clients receive their VLANs from an unmanaged switch.",
}
