import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Aegis Review Console",
  description:
    "Local review console for exported Aegis-SAST reports and reviewer triage memory.",
};

const htmlClassName = "h-full antialiased";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="vi" className={htmlClassName} suppressHydrationWarning>
      <body
        className="min-h-full bg-background text-foreground"
        suppressHydrationWarning
      >
        {children}
      </body>
    </html>
  );
}
