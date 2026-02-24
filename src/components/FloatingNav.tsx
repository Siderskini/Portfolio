"use client";

import { useEffect, useState } from "react";

const sections = [
  { id: "home", label: "Home", icon: "H" },
  { id: "about", label: "About", icon: "A" },
  { id: "projects", label: "Projects", icon: "P" },
  { id: "contact", label: "Contact", icon: "C" },
];

export default function FloatingNav() {
  const [activeSection, setActiveSection] = useState("home");

  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveSection(entry.target.id);
          }
        });
      },
      { threshold: 0.4 }
    );

    sections.forEach(({ id }) => {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    });

    return () => observer.disconnect();
  }, []);

  const scrollTo = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <nav className="fixed left-4 top-1/2 -translate-y-1/2 z-50 hidden md:flex flex-col gap-3 group/nav">
      <div className="glass-strong rounded-3xl p-2 flex flex-col gap-2">
        {sections.map(({ id, label, icon }) => (
          <button
            key={id}
            onClick={() => scrollTo(id)}
            className={`h-10 rounded-full flex items-center px-2 transition-all duration-300 cursor-pointer ${
              activeSection === id
                ? "bg-white/25 text-white shadow-lg"
                : "text-white/50 hover:text-white/80 hover:bg-white/10"
            }`}
          >
            <span className="w-6 flex-shrink-0 flex items-center justify-center text-sm font-medium">
              {icon}
            </span>
            {/* Label slides in to the right when the nav is hovered */}
            <span className="w-0 group-hover/nav:w-20 overflow-hidden transition-all duration-300 ease-in-out">
              <span className="pl-2 whitespace-nowrap text-sm font-medium">
                {label}
              </span>
            </span>
          </button>
        ))}
      </div>
    </nav>
  );
}
