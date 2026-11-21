"""ASGI-Einstieg: Erstinstallation oder konfigurierte Anwendung."""

from . import config

if config.settings.setup_completed:
    from .application import app as app
else:
    from .setup import create_setup_app

    app = create_setup_app()
