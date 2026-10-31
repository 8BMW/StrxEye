# Building and releasing

## Releasing

1. Update the version in `pyproject.toml`, `src/strxeye/__init__.py` and
   `apps/desktop/package.json`.
2. Move the *Unreleased* entries in `CHANGELOG.md` under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading. The release notes are taken from it.
3. Commit, then tag and push:

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

`.github/workflows/release.yml` then:

- refuses to build if the tag does not match `pyproject.toml`;
- builds the UI, runs PyInstaller on Windows, Linux and macOS, and runs each
  built app's `--self-test` (starts the engine, calls the API, loads the UI);
- builds the Windows installer with Inno Setup and a portable zip;
- builds the wheel and sdist;
- writes `SHA256SUMS.txt` over every file and publishes the GitHub release.

The desktop app's updater looks for an asset named
`STRX-EYE-Setup-<version>.exe` and the `SHA256SUMS.txt` file in the latest
release. Keep those names.

## Building locally

Windows (PowerShell), from the repository root:

```powershell
cd apps/desktop; npm ci; npm run bundle; cd ../..
pip install ".[desktop]" pyinstaller pillow
pyinstaller packaging/strxeye.spec --noconfirm --distpath build/dist --workpath build/work
& "build/dist/STRX EYE/STRX EYE.exe" --self-test
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" /DAppVersion=1.0.0 packaging/installer.iss
```

The installer is written to `build/installer/`. Builds are not bit-for-bit
reproducible yet (PyInstaller embeds timestamps), but they are reproducible
from the tagged source with the commands above.

## Code signing

Releases are not signed yet. Windows SmartScreen and macOS Gatekeeper warn on
first launch. Signing needs a certificate held outside the repository; when
one is available, add a signing step after PyInstaller (Windows `signtool`,
macOS `codesign` + notarisation) and sign the installer.
