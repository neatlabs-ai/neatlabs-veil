#!/usr/bin/env python3
"""
VEIL 3.0 — Network Traffic Exposer
Every connection. Every tracker. Every byte. Exposed.

Usage:
    python main.py                    # Launch GUI
    python main.py --key YOUR_KEY     # Launch with OpenAI API key

NEATLABS™ Intelligence Technology
Open Source — github.com/neatlabs-ai
"""

import sys
import os
import argparse
import logging

# ---------------------------------------------------------------------------
# Path resolution — works whether files are in proper tree or flat folder
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def ensure_project_structure():
    """
    If all .py files are in one flat folder (e.g. after downloading from Claude),
    automatically create the correct directory structure and copy them in.
    """
    if os.path.isdir(os.path.join(SCRIPT_DIR, "core")) and \
       os.path.isdir(os.path.join(SCRIPT_DIR, "ui")):
        # Check if core/ has actual files
        if os.path.exists(os.path.join(SCRIPT_DIR, "core", "sniffer.py")):
            return  # Already correct

    file_map = {
        "sniffer.py": "core",
        "ai_analyzer.py": "core",
        "ip_intel.py": "core",
        "app.py": "ui",
        "panels.py": "ui",
        "widgets.py": "ui",
        "styles.py": "ui",
        "globe.html": "assets",
        "trackers.json": "data",
    }

    needs_move = False
    for filename, subdir in file_map.items():
        flat_path = os.path.join(SCRIPT_DIR, filename)
        if os.path.exists(flat_path):
            needs_move = True
            break

    if not needs_move:
        return

    print("\n  [SETUP] Organizing files into project structure...")
    import shutil

    for subdir in ["core", "ui", "assets", "data"]:
        os.makedirs(os.path.join(SCRIPT_DIR, subdir), exist_ok=True)

    for subdir in ["core", "ui"]:
        init_path = os.path.join(SCRIPT_DIR, subdir, "__init__.py")
        if not os.path.exists(init_path):
            with open(init_path, "w") as f:
                f.write("")

    moved = 0
    for filename, subdir in file_map.items():
        flat_path = os.path.join(SCRIPT_DIR, filename)
        target_path = os.path.join(SCRIPT_DIR, subdir, filename)
        if os.path.exists(flat_path):
            shutil.copy2(flat_path, target_path)
            moved += 1
            print(f"    {filename} -> {subdir}/{filename}")

    if moved > 0:
        print(f"  [SETUP] Organized {moved} files. Ready.\n")


def main():
    parser = argparse.ArgumentParser(
        description="VEIL 3.0 — Network Traffic Exposer | NEATLABS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    Launch the VEIL dashboard
  python main.py --key sk-abc123    Launch with OpenAI API key
  python main.py --debug            Enable debug logging

For full packet capture, run as Administrator (Windows) or sudo (Linux/macOS).
        """
    )
    parser.add_argument("--key", "-k", default="", help="OpenAI API key")
    parser.add_argument("--debug", "-d", action="store_true", help="Debug logging")
    args = parser.parse_args()

    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s", datefmt="%H:%M:%S")
    logger = logging.getLogger("veil")

    api_key = args.key or os.environ.get("OPENAI_API_KEY", "")

    logger.info("=" * 60)
    logger.info("  VEIL 3.0 — Network Traffic Exposer")
    logger.info("  NEATLABS Intelligence Technology")
    logger.info("=" * 60)

    # Auto-organize if files are in a flat folder
    ensure_project_structure()

    # Ensure project root is on Python path
    if SCRIPT_DIR not in sys.path:
        sys.path.insert(0, SCRIPT_DIR)

    try:
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        print("\n[ERROR] PyQt6 is required:")
        print("  pip install PyQt6 PyQt6-WebEngine psutil")
        sys.exit(1)

    deps = []
    try:
        import scapy; deps.append("scapy (full capture)")
    except ImportError:
        logger.warning("scapy not found — will use psutil fallback")
    try:
        import psutil; deps.append("psutil (process mapping)")
    except ImportError:
        logger.warning("psutil not found")
    try:
        import openai; deps.append("openai (AI analysis)")
    except ImportError:
        pass
    try:
        from PyQt6.QtWebEngineWidgets import QWebEngineView; deps.append("WebEngine (3D globe)")
    except ImportError:
        logger.warning("PyQt6-WebEngine not found — globe will show fallback")
    if deps:
        logger.info(f"Available: {', '.join(deps)}")

    try:
        from ui.styles import CYBERPUNK_STYLESHEET
        from ui.app import VeilMainWindow
    except ModuleNotFoundError as e:
        print(f"\n[ERROR] {e}")
        print("\nFile structure needed:")
        print("  veil/")
        print("  +-- main.py")
        print("  +-- core/  (sniffer.py, ai_analyzer.py, ip_intel.py)")
        print("  +-- ui/    (app.py, panels.py, widgets.py, styles.py)")
        print("  +-- assets/(globe.html)")
        print("  +-- data/  (trackers.json)")
        print("\nTIP: Put all files in ONE folder with main.py and re-run.")
        print("     VEIL will auto-organize them.")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setApplicationName("VEIL")
    app.setOrganizationName("NEATLABS")
    app.setStyleSheet(CYBERPUNK_STYLESHEET)

    window = VeilMainWindow(openai_key=api_key)
    window.show()

    logger.info("VEIL 3.0 dashboard launched")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
