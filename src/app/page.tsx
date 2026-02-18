import FloatingNav from "@/components/FloatingNav";
import Header from "@/components/Header";
import AboutMe from "@/components/AboutMe";
import Projects from "@/components/Projects";
import Contact from "@/components/Contact";

export default function Home() {
  return (
    <>
      <FloatingNav />
      <main className="ml-0 md:ml-16">
        <Header />
        <AboutMe />
        <Projects />
        <Contact />
      </main>
    </>
  );
}
