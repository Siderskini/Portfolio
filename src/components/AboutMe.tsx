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
            Senior Software Engineer with 5+ years of experience building platform-scale systems.
            Most recently, I led Team Diablo at C3 AI, where I designed and maintained core platform
            infrastructure — data storage across file, KV, SQL, vector, and search datastores;
            data integration pipelines; serialization frameworks; and distributed task dispatching systems.
          </p>
          <p>
            I hold a patent for a Metadata-Driven Feature Store for Machine Learning Systems and carry a
            Professional Scrum Master I certification. My background spans from nuclear engineering at
            UC Berkeley to machine learning and full-stack development, giving me a unique perspective
            on solving complex engineering challenges.
          </p>
          <p>
            Today, I&apos;m focused on the frontier of agentic software development — building high quality software using agents.
            I am pretty tech-stack agnostic, as highlighted in the Open Source Projects section below, but some technologies I 
            have significant experience with are listed below.
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
