"""Run itch-dl, tolerating game-page infobox rows it doesn't know yet.

itch.io adds new rows to the info panel from time to time (e.g. "Jams"), and itch-dl 1.0.0 raises
NotImplementedError on any row it doesn't recognise, which aborts the whole jam download. Those rows are
page metadata only, so an unknown or malformed row is skipped instead. Usage: same arguments as itch-dl.
"""
from __future__ import annotations

import sys

from itch_dl import infobox

_parse_tr = infobox.parse_tr


def _tolerant_parse_tr(name, content):
    try:
        return _parse_tr(name, content)
    except NotImplementedError:
        return None                     # a row itch-dl doesn't know: metadata only
    except (IndexError, KeyError, ValueError):
        return None                     # a known row in an unexpected shape


infobox.parse_tr = _tolerant_parse_tr   # parse_infobox looks parse_tr up in the module at call time


def main() -> int:
    from itch_dl.cli import run
    return run() or 0


if __name__ == "__main__":
    sys.exit(main())
