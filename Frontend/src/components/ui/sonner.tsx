import { Toaster as Sonner } from "sonner";

export function AppToaster() {
  const theme = document.documentElement.classList.contains("dark")
    ? "dark"
    : "light";

  return (
    <Sonner
      theme={theme}
      className="toaster"
      style={
        {
          "--normal-bg": "#ffffff",
          "--normal-text": "#0f172a",
          "--normal-border": "#e2e8f0",
        } as React.CSSProperties
      }
    />
  );
}