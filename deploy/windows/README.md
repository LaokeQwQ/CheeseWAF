# Windows packaging (CLI zip + GUI/NSIS)

CheeseWAF ships two Windows shapes:

| Shape | Audience | Contents |
| --- | --- | --- |
| **CLI / zip** | Operators who prefer nginx-style folders | `cheesewaf.exe`, optional `waf-cli.exe`, config template, data dirs |
| **GUI + NSIS** | Desktop install | Controller GUI + service registration + Start Menu + uninstaller |

## CLI / zip (manual)

```powershell
# build
go build -o bin/cheesewaf.exe ./cmd/cheesewaf
copy bin\cheesewaf.exe bin\waf-cli.exe

# run
.\bin\cheesewaf.exe serve --config .\data\cheesewaf.yaml --data-dir .\data
.\bin\cheesewaf.exe status
.\bin\cheesewaf.exe stop
```

Do **not** commit secrets into the zip. Ship only a YAML template.

## GUI controller

`cheesewaf-gui` is a **local service controller**, not a second admin console:

- start / stop / restart via CLI process semantics
- show PID / running state
- open Web console URL
- open config directory
- optional login autostart (HKCU Run on Windows)

It binds **loopback only** (default `127.0.0.1:17943`).

```powershell
go build -o bin/cheesewaf-gui.exe ./cmd/cheesewaf-gui
.\bin\cheesewaf-gui.exe --config .\data\cheesewaf.yaml --data-dir .\data
# browser opens http://127.0.0.1:17943/
```

## NSIS installer

Script: `deploy/windows/nsis/cheesewaf.nsi`

```text
makensis /DVERSION=0.1.0 /DSOURCE_DIR=path\to\payload cheesewaf.nsi
```

Installer guarantees:

- no API keys / private keys / default weak passwords in the package
- user data under `data\` is preserved on uninstall by default
- service registration is best-effort (`sc.exe create CheeseWAF …`)

## Makefile helpers

```text
make build-windows-gui
make package-windows-cli
```
