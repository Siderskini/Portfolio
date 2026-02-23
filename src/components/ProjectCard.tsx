"use client";

import { useState, useEffect, useRef } from "react";
import type { Project } from "@/lib/projects";
import GlassPanel from "./GlassPanel";

export default function ProjectCard({ project }: { project: Project }) {
  const [showOutput, setShowOutput] = useState(false);
  const [output, setOutput] = useState<string>("");
  const logRef = useRef<HTMLPreElement>(null);

  useEffect(() => {
    if (!showOutput) return;

    const fetch = () => {
      window
        .fetch(`/api/logs/${project.id}`)
        .then((r) => r.text())
        .then((text) => {
          setOutput(text);
          // Auto-scroll to bottom
          if (logRef.current) {
            logRef.current.scrollTop = logRef.current.scrollHeight;
          }
        })
        .catch(() => setOutput("Failed to fetch log."));
    };

    fetch();
    const interval = setInterval(fetch, 5000);
    return () => clearInterval(interval);
  }, [showOutput, project.id]);

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
        {project.iframeUrl && project.id !== "fishing" && (
          <button
            onClick={() => setShowOutput((v) => !v)}
            className="glass rounded-lg px-4 py-2 text-sm text-white/80 hover:text-white hover:bg-white/15 transition-colors cursor-pointer"
          >
            {showOutput ? "Hide Output (5s refresh)" : "Show Output (5s refresh)"}
          </button>
        )}
      </div>

      {showOutput && (
        <pre
          ref={logRef}
          className="mt-4 glass rounded-xl p-4 text-xs text-green-300/90 font-mono overflow-y-auto whitespace-pre-wrap break-all"
        >
          {output || "Loading..."}
        </pre>
      )}
    </GlassPanel>
  );
}
