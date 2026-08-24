import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Navbar } from "./_components/Navbar";
import { Footer } from "./_components/Footer";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Surge - Agentic Network Analysis Dashboard",
  description: "Surge is a cutting-edge dashboard for monitoring and analyzing network security using autonomous agents. It provides real-time insights into vulnerabilities, exploits, and system health across your network.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var t=JSON.parse(localStorage.getItem('surge:theme'));var mq=window.matchMedia('(prefers-color-scheme: light)');if(t==='light'||(t==='system'&&mq.matches))document.documentElement.classList.add('light');}catch(e){}try{var d=JSON.parse(localStorage.getItem('surge:density'));var dm={Compact:'14px',Default:'16px',Comfortable:'18px'};if(dm[d])document.documentElement.style.setProperty('--font-size',dm[d]);}catch(e){}})();`,
          }}
        />
      </head>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased min-h-screen bg-background text-foreground`}
      >
        <Navbar />
        <main className="pt-16 pb-14">
          {children}
        </main>
        <Footer />
      </body>
    </html>
  );
}
