// Simplified mark from docs/assets/logo.png, redrawn as SVG so it stays
// crisp at sidebar size and follows the theme.
export function LogoMark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size * 0.62} viewBox="0 0 160 100" aria-hidden="true">
      <defs>
        <linearGradient id="strx-g" x1="0" x2="1">
          <stop offset="0" stopColor="#06b6d4" />
          <stop offset="1" stopColor="#1d4ed8" />
        </linearGradient>
      </defs>
      <g fill="none" stroke="url(#strx-g)" strokeWidth="7" strokeLinejoin="round">
        <path d="M10 50 L48 18 H112 L150 50 L112 82 H48 Z" />
        <circle cx="80" cy="50" r="22" />
      </g>
      <circle cx="80" cy="50" r="8" fill="#06b6d4" />
      {[[10, 50], [48, 18], [112, 18], [150, 50], [112, 82], [48, 82]].map(([x, y]) => (
        <circle key={`${x}-${y}`} cx={x} cy={y} r="7" fill="rgb(var(--panel))" stroke="url(#strx-g)" strokeWidth="5" />
      ))}
    </svg>
  );
}

export function Wordmark() {
  return (
    <span className="font-mono text-[15px] font-bold tracking-[0.18em]">
      STRX<span className="text-accent">EYE</span>
    </span>
  );
}
