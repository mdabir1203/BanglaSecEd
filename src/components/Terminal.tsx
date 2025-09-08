import { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";

interface TerminalProps {
  isActive?: boolean;
  className?: string;
}

export const Terminal = ({ isActive = false, className = "" }: TerminalProps) => {
  const [currentLine, setCurrentLine] = useState(0);
  
  const terminalLines = [
    "$ subenum-pro --target example.com --mode advanced",
    "[*] Initializing SubEnum Pro v2.0.1",
    "[*] Loading reconnaissance modules...",
    "[+] DNS resolver configured: 8.8.8.8",
    "[+] Rate limiting: 50 concurrent connections", 
    "[*] Starting subdomain enumeration...",
    "[+] Certificate transparency logs: 247 entries found",
    "[+] DNS brute force: 1,832 subdomains validated",
    "[+] Port scanning: 89 services discovered",
    "[!] CORS misconfiguration detected on api.example.com",
    "[!] Potential subdomain takeover: staging.example.com",
    "[*] Attack surface analysis complete",
    "$ _"
  ];

  useEffect(() => {
    if (!isActive) return;
    
    const timer = setInterval(() => {
      setCurrentLine(prev => prev < terminalLines.length - 1 ? prev + 1 : prev);
    }, 800);

    return () => clearInterval(timer);
  }, [isActive, terminalLines.length]);

  return (
    <Card className={`bg-gradient-terminal border-primary/30 ${className}`}>
      <div className="p-6">
        <div className="flex items-center gap-2 mb-4">
          <div className="flex gap-1.5">
            <div className="w-3 h-3 bg-destructive rounded-full"></div>
            <div className="w-3 h-3 bg-warning rounded-full"></div>
            <div className="w-3 h-3 bg-success rounded-full"></div>
          </div>
          <span className="text-sm font-mono text-muted-foreground">terminal</span>
        </div>
        
        <div className="font-mono text-sm space-y-1 h-64 overflow-hidden">
          {terminalLines.slice(0, currentLine + 1).map((line, index) => (
            <div 
              key={index}
              className={`${
                line.startsWith('[+]') ? 'text-success' :
                line.startsWith('[!]') ? 'text-destructive' :
                line.startsWith('[*]') ? 'text-primary' :
                line.startsWith('$') ? 'text-accent' :
                'text-muted-foreground'
              } ${index === currentLine ? 'terminal-glow' : ''}`}
            >
              {line}
              {index === currentLine && line === "$ _" && (
                <span className="animate-pulse">█</span>
              )}
            </div>
          ))}
        </div>
      </div>
    </Card>
  );
};