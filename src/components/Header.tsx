import GlassPanel from "./GlassPanel";

export default function Header() {
  return (
    <section id="home" className="min-h-screen flex items-center justify-center px-4">
      <GlassPanel className="max-w-3xl w-full text-center py-16">
        <h1 className="text-5xl md:text-7xl font-bold mb-4 bg-gradient-to-r from-white via-blue-200 to-purple-200 bg-clip-text text-transparent">
          Sidd Viswanathan
        </h1>
        <p className="text-xl md:text-2xl text-white/70 font-light tracking-wide">
          Agentic Software Developer
        </p>
      </GlassPanel>
    </section>
  );
}
