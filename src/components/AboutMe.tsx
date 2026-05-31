"use client";

import { useState } from "react";
import GlassPanel from "./GlassPanel";
import { skills, type Skill } from "@/lib/skills";

export default function AboutMe() {
  const [selected, setSelected] = useState<Skill | null>(null);

  function handleSkillClick(skill: Skill) {
    setSelected((prev) => (prev?.name === skill.name ? null : skill));
  }

  return (
    <section id="about" className="min-h-screen flex items-center justify-center px-4 py-20">
      <GlassPanel className="max-w-4xl w-full">
        <h2 className="text-3xl md:text-4xl font-bold mb-8 bg-gradient-to-r from-white to-blue-200 bg-clip-text text-transparent">
          About Me
        </h2>
        <div className="space-y-4 text-lg text-white/80 leading-relaxed mb-10">
          <p>
            I am a problem solver with an education in Nuclear Enigneering and Computer Science from the University of Claifornia, Berkeley.
            I also have 5 years of professional experience in natural language processing, AI, cloud infrastructure, distributed computing at scale, and storage technologies.
            Today, I&apos;m focused on the frontier of agentic development — building high quality, meaningful software using agents.
            I am pretty tech-stack agnostic, as highlighted in the Open Source Projects section below, but some technologies I have significant experience with are listed below.
            To see agentic development at work, check out the <a href="https://github.com/Siderskini/Portfolio">&nbsp;source code&nbsp;</a> for this portfolio!
          </p>
        </div>

        <h3 className="text-xl font-semibold mb-4 text-white/90">Skills &amp; Technologies</h3>
        <div className="flex flex-wrap gap-3">
          {skills.map((skill) => {
            const isSelected = selected?.name === skill.name;
            return (
              <button
                key={skill.name}
                onClick={() => handleSkillClick(skill)}
                className={[
                  "glass rounded-full px-4 py-2 text-sm transition-all duration-200 cursor-pointer",
                  isSelected
                    ? "bg-blue-500/30 border-blue-400/50 text-white shadow-[0_0_14px_3px_rgba(96,165,250,0.35)] scale-105"
                    : "text-white/80 hover:text-white hover:bg-white/15",
                ].join(" ")}
              >
                {skill.name}
              </button>
            );
          })}
        </div>

        <div
          className={[
            "overflow-hidden transition-all duration-300 ease-in-out",
            selected ? "max-h-40 opacity-100 mt-5" : "max-h-0 opacity-0 mt-0",
          ].join(" ")}
        >
          {selected && (
            <div className="glass-strong rounded-xl px-5 py-4">
              <p className="text-sm font-semibold text-blue-200 mb-1">{selected.name}</p>
              <p className="text-sm text-white/80 leading-relaxed">{selected.description}</p>
            </div>
          )}
        </div>
      </GlassPanel>
    </section>
  );
}
