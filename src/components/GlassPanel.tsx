interface GlassPanelProps {
  children: React.ReactNode;
  className?: string;
  strong?: boolean;
  onClick?: () => void;
}

export default function GlassPanel({ children, className = "", strong = false, onClick }: GlassPanelProps) {
  return (
    <div
      className={`${strong ? "glass-strong" : "glass"} rounded-2xl p-6 ${className} ${onClick ? "cursor-pointer" : ""}`}
      onClick={onClick}
    >
      {children}
    </div>
  );
}
