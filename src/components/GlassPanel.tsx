interface GlassPanelProps {
  children: React.ReactNode;
  className?: string;
  strong?: boolean;
}

export default function GlassPanel({ children, className = "", strong = false }: GlassPanelProps) {
  return (
    <div className={`${strong ? "glass-strong" : "glass"} rounded-2xl p-6 ${className}`}>
      {children}
    </div>
  );
}
