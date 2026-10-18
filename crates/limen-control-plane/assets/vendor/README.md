# Vendored: asciinema-player

Plays session recordings (asciicast v3) in the web console (ADR-0017).

| | |
|---|---|
| Package | `asciinema-player` 3.17.0 (npm), https://github.com/asciinema/asciinema-player |
| License | Apache-2.0 (`asciinema-player.LICENSE`) |
| Files | `dist/bundle/asciinema-player.min.js`, `dist/bundle/asciinema-player.css`, unmodified |
| SHA-256 | `asciinema-player.min.js` a13c37632e1b5c49fe9128417b9319a9b5bc64cb457dd5ae52cbba8a3aceb880 |
| | `asciinema-player.css` f619fe17597043564f03b2c6918b3daf890ee8b912fb408542fba11afade4fdb |
| Checked | Released 2026-06-30. npm's advisory endpoint reported none for 3.17.0 on 2026-10-14. |

The bundle is self-contained: no network access, no eval of recording content as markup. Its terminal emulator is WebAssembly, so it needs `'wasm-unsafe-eval'` in `script-src` (this permits compiling WebAssembly, not JS `eval`), plus `worker-src blob:` and `style-src-attr 'unsafe-inline'`. Nothing else is relaxed.

To update: download the new tarball from the npm registry, replace both files, update this table, and play a recording (`demos/demo-phase3.sh` then open any session in the console).

# Vendored: fonts and icons (console look)

| | |
|---|---|
| Inter (variable, latin) | `@fontsource-variable/inter` 5.3.0, SIL OFL 1.1 (`fonts/Inter.OFL.txt`) |
| JetBrains Mono (variable, latin) | `@fontsource-variable/jetbrains-mono` 5.3.0, SIL OFL 1.1 (`fonts/JetBrainsMono.OFL.txt`) |
| Lucide icons | `lucide-static` 1.57.0, ISC (`lucide.LICENSE`). `../icons.svg` is a sprite of the icons the console uses |

Fonts and icons are served from the binary, so the console loads nothing from other origins (CSP `font-src 'self'`).

# Vendored: brand icons for resource kinds

`simple-icons` 16.35.0 (CC0-1.0, `simple-icons.LICENSE`): the PostgreSQL, MySQL, Redis, Kubernetes, MongoDB, OpenSearch, Elasticsearch, RabbitMQ, and Apache Kafka marks, inlined in `../icons.svg` as `k-*` symbols. Product names and logos belong to their owners and are used only to say what a resource is.
