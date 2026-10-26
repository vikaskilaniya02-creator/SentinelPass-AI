"""CLI entry point:  python app.py"""
from __future__ import annotations

import logging
from pathlib import Path

from app_context import build_context
from cli.menu import Menu
from config.settings import load_settings


def main() -> None:
    settings = load_settings()
    Path("data").mkdir(exist_ok=True)
    logging.basicConfig(filename="data/errors.log", level=logging.ERROR,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    Menu(build_context(settings)).run()


if __name__ == "__main__":
    main()
