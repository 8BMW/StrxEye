# PyInstaller build for the desktop app and CLI.
#
#   cd apps/desktop && npm ci && npm run bundle   # UI must be built first
#   pyinstaller packaging/strxeye.spec --noconfirm
#
# Produces dist/STRX EYE/ with "STRX EYE" (windowed) and "strxeye" (console)
# sharing one set of libraries. A folder build starts much faster than a
# one-file build, which unpacks itself to a temp folder on every launch.
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).parent  # noqa: F821 - provided by PyInstaller
ICON = str(ROOT / "packaging" / "strxeye.ico")

if not (ROOT / "src" / "strxeye" / "web" / "index.html").exists():
    raise SystemExit("UI not built: run `npm run bundle` in apps/desktop first")

datas = collect_data_files("strxeye")  # bundled UI and report templates
# dnspython loads record type modules dynamically; uvicorn picks its event
# loop and protocol implementations at runtime.
hidden = (collect_submodules("dns") + collect_submodules("uvicorn")
          + collect_submodules("strxeye"))
if sys.platform == "win32":
    hidden += ["keyring.backends.Windows"]
elif sys.platform == "darwin":
    hidden += ["keyring.backends.macOS"]
else:
    hidden += ["keyring.backends.SecretService"]

common = dict(pathex=[str(ROOT / "src")], datas=datas, hiddenimports=hidden,
              excludes=["tkinter", "pytest", "respx", "ruff", "stix2"])

gui = Analysis([str(ROOT / "packaging" / "entry_desktop.py")], **common)  # noqa: F821
cli = Analysis([str(ROOT / "packaging" / "entry_cli.py")], **common)  # noqa: F821

gui_exe = EXE(  # noqa: F821
    PYZ(gui.pure), gui.scripts, [], exclude_binaries=True,  # noqa: F821
    name="STRX EYE", console=False, icon=ICON,
)
cli_exe = EXE(  # noqa: F821
    PYZ(cli.pure), cli.scripts, [], exclude_binaries=True,  # noqa: F821
    name="strxeye", console=True, icon=ICON,
)
COLLECT(  # noqa: F821
    gui_exe, gui.binaries, gui.datas,
    cli_exe, cli.binaries, cli.datas,
    name="STRX EYE",
)
