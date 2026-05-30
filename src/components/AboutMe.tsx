import GlassPanel from "./GlassPanel";

const skills = [
  "Java", "Python", "JS", "TypeScript", "Go", "Rust", "Bash", "Next.js",
  "SQL", "NoSQL", "AWS", "GCP", "Azure", "AI/ML",
  "NLP", "Agentic Systems", "Distributed Systems", "Data Persistence", "ETL", "Data Flows", "Scrum", "Hosting", "Kubernetes", "Authn/z"
];

export default function AboutMe() {
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
            I am pretty tech-stack agnostic, as highlighted in the Open Source Projects section below, but some technologies I 
            have significant experience with are listed below.
            To see agentic development at work, check out the <a href="https://github.com/Siderskini/Portfolio">&nbsp;source code&nbsp;</a> for this portfolio!
          </p>
        </div>

        <h3 className="text-xl font-semibold mb-4 text-white/90">Skills &amp; Technologies</h3>
        <div className="flex flex-wrap gap-3">
          {skills.map((skill) => (
            <span
              key={skill}
              className="glass rounded-full px-4 py-2 text-sm text-white/80 hover:text-white hover:bg-white/15 transition-colors"
            >
              {skill}
            </span>
          ))}
        </div>

      </GlassPanel>
    </section>
  );
}
