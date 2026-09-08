"""Real GUI smoke test.

Creates the actual Tk window, verifies the widgets come up, the logo loads and
a synthetic result can be rendered into the tree, then closes. Intended to run
under a virtual display in CI (`xvfb-run -a python tests/gui_smoke.py`).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import tkinter as tk  # noqa: E402

from domainscan import app as app_module  # noqa: E402


def main():
    root = tk.Tk()
    try:
        app = app_module.DomainScanApp(root)
        root.update_idletasks()

        assert app_module.APP_TITLE in root.title(), "window title missing app name"
        assert app.logo_image is not None, "logo did not load"

        # Render a synthetic result end-to-end without any network.
        result = {
            "target": {"host": "example.com"},
            "sections": {
                "Target": [("Host", "example.com")],
                "DNS": [("A record 1", "93.184.216.34")],
                "Grade": [("Security grade", "A (98/100)")],
            },
            "meta": {
                "version": app_module.__version__,
                "duration_seconds": 0.5,
                "scanned_at": "smoke",
                "findings": 3,
            },
        }
        app.finish_scan(result)
        root.update_idletasks()

        rows = app.tree.get_children()
        assert rows, "tree did not render any rows"
        print("GUI smoke OK:", len(rows), "tree rows, title:", root.title())
    finally:
        root.destroy()


if __name__ == "__main__":
    main()
