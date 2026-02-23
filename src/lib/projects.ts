export interface Project {
  id: string;
  title: string;
  description: string;
  iframeUrl?: string;
  repoUrl: string;
  tags: string[];
}

// iframeUrls fall back to localhost when a project is hosted locally.
// deploy.sh writes FLOWERS_URL, LABYRINTH_URL, FISHING_URL to .env.local
// when a project is deployed to a cloud provider, overriding the defaults here.
export const projects: Project[] = [
  {
    id: "flowers",
    title: "Flowers",
    description:
      "A flower breeding genetics simulator built with Ruby on Rails. I built this for myself to help strategize for a blue rose in animal crossing for the switch. Original React+Flask project by me, adapted to Ruby on Rails by AI. Hosted on a Google cloud instance.",
    iframeUrl: process.env.FLOWERS_URL ?? "http://localhost:3001",
    repoUrl: "https://github.com/Siderskini/RubyOnRails/tree/main/Flowers",
    tags: ["Ruby on Rails", "SQLite", "Genetics"],
  },
  {
    id: "labyrinth",
    title: "Labyrinth",
    description:
      "A real-time multiplayer desktop maze game powered by WebSockets. Navigate a procedurally generated 48x48 labyrinth, collect items, and face the Minotaur. All code and assets by me. This game requires a keyboard. Hosted on an AWS instance.",
    iframeUrl: process.env.LABYRINTH_URL ?? "https://localhost:4000",
    repoUrl: "https://github.com/Siderskini/Labyrinth",
    tags: ["Node.js", "Socket.io", "WebSockets"],
  },
  {
    id: "fishing",
    title: "Fishing Game",
    description:
      "A 2D fishing game built for the desktop with Go and the Ebiten game engine, compiled to WebAssembly for the browser. Cast your line and see what you catch. Code by me, visual assets by Olga Nam, audio assets by AI. This game requires a mouse, and will not work in mobile browsers. Hosted on an Oracle cloud bucket.",
    iframeUrl: process.env.FISHING_URL ?? "http://localhost:8080",
    repoUrl: "https://github.com/Siderskini/LearningGo/tree/main/fishing",
    tags: ["Go", "WebAssembly", "Ebiten"],
  },
  {
    id: "portfolio",
    title: "This Portfolio",
    description:
      "This Portfolio was created using AI, including deployment, hosting, and the React frontend. Portfolio text and content by me. Hosted on an Azure cloud instance.",
    iframeUrl: process.env.PORTFOLIO_URL ?? "http://localhost:3000",
    repoUrl: "https://github.com/Siderskini/Portfolio",
    tags: ["Next.js", "React", "TypeScript"],
  },
  {
    id: "codexbar",
    title: "CodexBar",
    description:
      "A fork of the macOS CodexBar menu bar app, being ported to a KDE Plasma Panel widget. Removed reliance on local files and ported support for Codex and Claude. Built with Codex (AI).",
    repoUrl: "https://github.com/Siderskini/CodexBar",
    tags: ["Rust", "KDE Plasma", "Swift", "Codex"],
  },
  {
    id: "dqrvcs",
    title: "DQRVCS",
    description:
      "A decentralized, (soon to be) quantum-resistant version control system. Git-compatible CLI built on a gossip-based peer network with democratic consensus for collaboration. Includes a Rust eframe/egui desktop GUI. Built with Codex (AI).",
    repoUrl: "https://github.com/Siderskini/DQRVCS",
    tags: ["Go", "Rust", "Cryptography", "Decentralized"],
  },
];
