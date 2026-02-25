import FloatingNav from "@/components/FloatingNav";
import Header from "@/components/Header";
import AboutMe from "@/components/AboutMe";
import Projects from "@/components/Projects";
import Contact from "@/components/Contact";

// Force server-side rendering so process.env project URLs (written by deploy.sh
// to .env.local) are read at request time rather than baked in at build time.
export const dynamic = "force-dynamic";

export default function Home() {
  return (
    <>
      <FloatingNav />
      <main className="ml-0 md:ml-16">
        <Header />
        <AboutMe />
        <Projects />
        <Contact />
        <footer className="text-center text-xs text-white/40 py-6">
          &copy; {new Date().getFullYear()} Siddharth Viswanathan. Licensed under the{" "}
          <a
            href="https://github.com/Siderskini/Portfolio/blob/main/LICENSE"
            target="_blank"
            rel="noopener noreferrer"
            className="underline hover:text-white/70 transition-colors"
          >
            MIT License
          </a>
          .
        </footer>
      </main>
    </>
  );
}
