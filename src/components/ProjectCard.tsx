import type { Project } from "@/lib/projects";
import GlassPanel from "./GlassPanel";

export default function ProjectCard({ project }: { project: Project }) {
  return (
    <GlassPanel className="flex flex-col">
      <h3 className="text-xl font-semibold mb-2">{project.title}</h3>
      <p className="text-white/70 mb-4">{project.description}</p>
      <div className="flex flex-wrap gap-2 mb-4">
        {project.tags.map((tag) => (
          <span key={tag} className="text-xs bg-white/10 rounded-full px-3 py-1 text-white/70">
            {tag}
          </span>
        ))}
      </div>

      <div className="flex flex-wrap gap-3">
        {project.iframeUrl && (
          <a
            href={project.iframeUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="glass rounded-lg px-4 py-2 text-sm text-white/80 hover:text-white hover:bg-white/15 transition-colors"
          >
            Launch Demo
          </a>
        )}
        <a
          href={project.repoUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="glass rounded-lg px-4 py-2 text-sm text-white/80 hover:text-white hover:bg-white/15 transition-colors"
        >
          View on GitHub
        </a>
      </div>
    </GlassPanel>
  );
}
