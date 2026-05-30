"use client";

import { useState } from "react";
import GlassPanel from "./GlassPanel";

const themes = [
  { g1: "#0f0c29", g2: "#302b63", g3: "#24243e", t1: "#ffffff", t2: "#bfdbfe", t3: "#e9d5ff" }, // purple
  { g1: "#080f1f", g2: "#0c3358", g3: "#0a2035", t1: "#ffffff", t2: "#a5f3fc", t3: "#7dd3fc" }, // ocean
  { g1: "#1a0810", g2: "#3d1020", g3: "#280c18", t1: "#ffffff", t2: "#fecdd3", t3: "#fda4af" }, // crimson
  { g1: "#081508", g2: "#173520", g3: "#0f2812", t1: "#ffffff", t2: "#bbf7d0", t3: "#6ee7b7" }, // forest
  { g1: "#140e04", g2: "#382408", g3: "#241a04", t1: "#ffffff", t2: "#fef08a", t3: "#fcd34d" }, // amber
];

export default function Header() {
  const [themeIndex, setThemeIndex] = useState(0);

  const cycleTheme = () => {
    const next = (themeIndex + 1) % themes.length;
    setThemeIndex(next);
    const { g1, g2, g3 } = themes[next];
    const root = document.documentElement;
    root.style.setProperty("--g1", g1);
    root.style.setProperty("--g2", g2);
    root.style.setProperty("--g3", g3);
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", g1);
  };

  const { t1, t2, t3 } = themes[themeIndex];

  return (
    <section id="home" className="min-h-screen flex items-center justify-center px-4">
      <GlassPanel className="max-w-3xl w-full text-center py-16 active:scale-[0.98] transition-transform duration-100" onClick={cycleTheme}>
        <h1
          className="text-5xl md:text-7xl font-bold mb-4 bg-clip-text text-transparent transition-all duration-500"
          style={{ backgroundImage: `linear-gradient(to right, ${t1}, ${t2}, ${t3})` }}
        >
          Sidd Viswanathan
        </h1>
        <p className="text-xl md:text-2xl text-white/70 font-light tracking-wide">
          Agentic Software Developer
        </p>
      </GlassPanel>
    </section>
  );
}
