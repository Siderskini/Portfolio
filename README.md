Disclaimer: The vast majority of this project was created with AI agents. Portfolio text and content is hand-created unless specified otherwise. For information about this project, see [about/About.md](about/About.md).

# Portfolio

A Next.js portfolio that links to three live project demos — a Ruby on Rails app, a Node.js multiplayer game, and a Go/WASM game. Each demo can be run locally or deployed to any combination of AWS, Azure, GCP, and OCI cloud providers.

## Quick Start

```bash
./deploy.sh
```

This runs everything locally. No cloud accounts required. See [Hosting.md](Hosting.md) for full local and cloud deployment instructions.

## Projects

| Project | Technology | Repo |
|---|---|---|
| Flowers | Ruby on Rails | [Siderskini/RubyOnRails](https://github.com/Siderskini/RubyOnRails/tree/main/Flowers) |
| Labyrinth | Node.js + Socket.io | [Siderskini/Labyrinth](https://github.com/Siderskini/Labyrinth) |
| Fishing Game | Go/WASM | [Siderskini/LearningGo](https://github.com/Siderskini/LearningGo/tree/main/fishing/web) |

## License Scan

This project has been scanned using `scancode -clpieu --json-pp portfolio.json /home/sidd/Documents/GitHub/Portfolio/src` and the result is available in portfolio.json.

A license scan via `npx license-checker` is available in npmLicenseScan.txt.

Note that the scan shows `@img/sharp-libvips*` as `LGPL-3.0-or-later`, but the repo states `Apache 2.0`. If there are any licensing issues, please open an issue.
