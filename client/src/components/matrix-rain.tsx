import { useEffect, useRef } from "react";

interface MatrixRainProps {
  className?: string;
  opacity?: number;
  color?: string;
}

export function MatrixRain({ className = "", opacity = 0.6, color = "#d4af37" }: MatrixRainProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationId: number;
    let width = 0;
    let height = 0;
    let columns = 0;
    let drops: number[] = [];

    const chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲンAEGISAIDEFENSECYBERSHIELDTHREAT<>{}[]=/\\|@#$%^&*";

    function resize() {
      width = canvas!.offsetWidth;
      height = canvas!.offsetHeight;
      canvas!.width = width;
      canvas!.height = height;
      const fontSize = 14;
      columns = Math.floor(width / fontSize);
      drops = new Array(columns).fill(1).map(() => Math.random() * -100);
    }

    function draw() {
      ctx!.fillStyle = `rgba(5, 8, 22, 0.08)`;
      ctx!.fillRect(0, 0, width, height);

      const fontSize = 14;
      ctx!.font = `${fontSize}px 'JetBrains Mono', monospace`;

      for (let i = 0; i < columns; i++) {
        const charIndex = Math.floor(Math.random() * chars.length);
        const char = chars[charIndex];
        const x = i * fontSize;
        const y = drops[i] * fontSize;

        const brightness = Math.random();
        if (brightness > 0.95) {
          ctx!.fillStyle = `rgba(255, 255, 255, ${opacity * 0.9})`;
        } else if (brightness > 0.8) {
          ctx!.fillStyle = color + Math.floor(opacity * 255).toString(16).padStart(2, "0");
        } else {
          ctx!.fillStyle = color + Math.floor(opacity * 0.4 * 255).toString(16).padStart(2, "0");
        }

        ctx!.fillText(char, x, y);

        if (y > height && Math.random() > 0.975) {
          drops[i] = 0;
        }
        drops[i] += 0.5 + Math.random() * 0.5;
      }

      animationId = requestAnimationFrame(draw);
    }

    resize();
    draw();

    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(canvas);

    return () => {
      cancelAnimationFrame(animationId);
      resizeObserver.disconnect();
    };
  }, [opacity, color]);

  return (
    <canvas
      ref={canvasRef}
      className={`absolute inset-0 w-full h-full pointer-events-none ${className}`}
      style={{ zIndex: 0 }}
    />
  );
}
