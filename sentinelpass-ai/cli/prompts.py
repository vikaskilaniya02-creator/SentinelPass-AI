"""Terminal input/output helpers (no security logic lives here)."""
from __future__ import annotations

import getpass

LINE = "=" * 44


def banner(title: str, subtitle: str = "") -> None:
    print(f"\n{LINE}\n{title}\n{subtitle}\n{LINE}" if subtitle else f"\n{LINE}\n{title}\n{LINE}")


def ask(label: str) -> str:
    return input(label).strip()


def ask_secret(label: str) -> str:
    return getpass.getpass(label)  # not echoed to the screen


def info(msg: str) -> None:
    print(f"  {msg}")


def error(msg: str) -> None:
    print(f"  [!] {msg}")


def table(rows: list[list], headers: list[str]) -> None:
    if not rows:
        info("(nothing to show)")
        return
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
    print("  " + " | ".join(str(h).ljust(w) for h, w in zip(headers, widths)))
    print("  " + "-+-".join("-" * w for w in widths))
    for r in rows:
        print("  " + " | ".join(str(c).ljust(w) for c, w in zip(r, widths)))
