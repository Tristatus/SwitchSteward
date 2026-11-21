"""Shared branding for the application and setup wizard.

The artwork lives in an application module, so the SVG, ICO and touch-icon variants are
served without static image files and without an imaging dependency at runtime.
"""

from base64 import b64decode

from fastapi import APIRouter, Response

router = APIRouter()

SVG = b'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <title>SwitchSteward</title>
  <rect width="32" height="32" rx="7" fill="#0d1117"/>
  <rect x="4" y="7" width="24" height="18" rx="3" fill="#5fd4a0"/>
  <g fill="#0d1117">
    <rect x="7" y="12" width="4" height="6"/>
    <rect x="14" y="12" width="4" height="6"/>
    <rect x="21" y="12" width="4" height="6"/>
    <rect x="7" y="21" width="4" height="1"/>
    <rect x="14" y="21" width="4" height="1"/>
    <rect x="21" y="21" width="4" height="1"/>
  </g>
</svg>'''

# Raster variants (ICO, PNG) rendered from the SVG geometry above.
ICO = b64decode(
    "AAABAAMAEBAAAAEAIACwAAAANgAAACAgAAABACAA7AAAAOYAAAAwMAAAAQAgAFsBAADSAQAAiVBORw0KGgoAAAANSUhEUgAAABAA"
    "AAAQCAYAAAAf8/9hAAAAd0lEQVR42mNgAAJeQfEAIL4PxP+JxCC1AQxImv+TiQMYSLQZwyUMMI64psZ/s6IYojBILUwf3IDQPf3/"
    "468sIAqD1GIYQKxmGMZqAMh5IDaIRlaET26QGUBxGHgtrgPbAKJhtsJsRJejfjRSkpAoTsqUZSZKszMAWGayPMV+0XAAAAAASUVO"
    "RK5CYIKJUE5HDQoaCgAAAA1JSERSAAAAIAAAACAIBgAAAHN6evQAAACzSURBVHjaY2BAAryC4gpA3A/E54H4P5XxeajZCgzYAFAi"
    "AYjf08BidAyyIwGb5f/pjBOQg/39ADjgPTg6oPHyf4BwPwONEhzRCZNhAC0HY6wOsK5P+R91Yvr/+CsLqIJBZoHMJMoBIIXUshgd"
    "Y3MEhgOo6XNsIUHQAbSyHIaHlgPoITfqgFEHDG4HjJYDI7MgGvDKaMCr4wFvkAxEk2zAG6UD3iwf2I7JgHfNBkXndCC75wBmxsfj"
    "TeC6fgAAAABJRU5ErkJggolQTkcNChoKAAAADUlIRFIAAAAwAAAAMAgGAAAAVwL5hwAAASJJREFUeNpjYMABeAXFDYC4H4j3A/H/"
    "AcL7oW4wYCAWABUrDLCj8XlGgZDjE4D4/SB0PAyD3JaAz/H/hwhOwJZs3g8hD7xHSU6DNM0TzBPIpc3/IYoNGKDF1FD1QP9QTT6I"
    "ZDSEHQ/GBD0gJKvwXyfK679ZUQxdMchOkN0UeQBkSNSJ6f/jrywYEAyyG+QGsjyg5GQ5YA5HxyC3kOwB1+mlg8YDILeQ7IHB4ngY"
    "HvXAqAcG2gOgshmbOpA4sZbRwsxRD4x6YNQDox4Y9cCoB0abEqMeGPUAER7wWlyHtfMNEseWObFhSswcLYWGXBIa8p36IT+sMuQH"
    "tobF0OJQGdwd8sPrQ36CY2hPMQ35Sb5hMc065Ce6h8VSg2Gx2GMoLrcBAGzOPwID9S5FAAAAAElFTkSuQmCC"
)
TOUCH_ICON = b64decode(
    "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"
)


@router.get("/favicon.svg", include_in_schema=False)
def favicon_svg():
    return Response(SVG, media_type="image/svg+xml")


@router.get("/favicon.ico", include_in_schema=False)
def favicon_ico():
    return Response(ICO, media_type="image/x-icon")


@router.get("/apple-touch-icon.png", include_in_schema=False)
def apple_touch_icon():
    return Response(TOUCH_ICON, media_type="image/png")
