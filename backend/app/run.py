"""Startet Uvicorn ausschließlich mit Werten aus der zentralen Konfiguration."""

import os
import sys

from .updates import update_manager


def _restart(python: str) -> None:
    os.execv(python, [python, "-m", "app.run"])  # noqa: S606 - fixed launcher, validated virtual environment


def main() -> None:
    # Recovery must precede importing application code or third-party packages:
    # either could have changed in an interrupted update.
    recovered = update_manager.recover_interrupted()
    python = update_manager.selected_python()
    if recovered or os.path.normcase(os.path.abspath(python)) != os.path.normcase(os.path.abspath(sys.executable)):
        _restart(python)
        return
    if update_manager.apply_pending():
        _restart(update_manager.selected_python())
        return

    import uvicorn

    from . import config
    from .logging_setup import configure_logging
    from .runtime_files import prepare_runtime_files

    configure_logging(config.settings)
    if not config.settings.setup_completed:
        from .setup import create_setup_app

        setup_app = create_setup_app()
        setup_port = config.settings.server_port
        server = uvicorn.Server(uvicorn.Config(
            setup_app,
            host="127.0.0.1",
            port=setup_port,
            log_level=config.settings.server_log_level,
            proxy_headers=False,
            log_config=None,
            access_log=False,
        ))

        def finish_setup() -> None:
            server.should_exit = True

        setup_app.state.on_complete = finish_setup
        print(f"Erstinstallation im Browser öffnen: http://127.0.0.1:{setup_port}", flush=True)
        server.run()
        if not config.reload_settings().setup_completed:
            return

    settings = config.settings
    configure_logging(settings)
    prepare_runtime_files(settings)
    config.validate_server_settings()
    options = {
        "host": settings.server_host,
        "port": settings.server_port,
        "log_level": settings.server_log_level,
        # Logging is configured by configure_logging; request lines come from switchsteward.http.
        "log_config": None,
        "access_log": False,
    }
    if settings.tls_enabled:
        options["ssl_certfile"] = str(settings.tls_cert_file)
        options["ssl_keyfile"] = str(settings.tls_key_file)
    server = uvicorn.Server(uvicorn.Config("app.main:app", **options))

    def restart_for_update() -> None:
        server.should_exit = True

    update_manager.register_shutdown(restart_for_update)
    try:
        server.run()
    finally:
        update_manager.register_shutdown(None)
    if update_manager.apply_pending():
        _restart(update_manager.selected_python())


if __name__ == "__main__":
    main()
