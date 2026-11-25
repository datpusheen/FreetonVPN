# Mozilla AMO source submission — Freeton Browser VPN 0.1.7

This archive contains the source files and reproducible build inputs for the Firefox extension package submitted to AMO.

## Build environment used

- Windows 11, x64
- PowerShell 7.6.5
- Node.js 24.15.0
- npm 11.14.1

The JavaScript dependencies are pinned in `browser-extension/package-lock.json`. This source archive also includes the exact public npm package directories used by the build: `bcryptjs` 3.0.3 and `openpgp` 6.3.2.

## Rebuild

From the root of this archive, run:

```powershell
.\browser-extension\build.ps1
```

The script creates the Firefox package at `dist\browser-extension\firefox` and the upload archive at `dist\browser-extension\Freeton-Browser-VPN-firefox.zip`. To reinstall dependencies from the public npm registry before building, run:

```powershell
npm ci --prefix .\browser-extension
```

The build script copies the first-party extension source files from `browser-extension\shared` without minifying or bundling them. It copies `browser-extension\node_modules\openpgp\dist\openpgp.min.js` to the package as `openpgp.js` and `browser-extension\node_modules\bcryptjs\umd\index.js` as `bcrypt.js` without modifying either library.

## Third-party library sources

- OpenPGP.js 6.3.2 package: https://registry.npmjs.org/openpgp/-/openpgp-6.3.2.tgz
- OpenPGP.js 6.3.2 readable source: https://github.com/openpgpjs/openpgpjs/tree/v6.3.2
- bcryptjs 3.0.3 package: https://registry.npmjs.org/bcryptjs/-/bcryptjs-3.0.3.tgz
- bcryptjs 3.0.3 readable source: https://github.com/dcodeIO/bcrypt.js/tree/v3.0.3
