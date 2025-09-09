import { useState, useEffect } from "react";
import { Card } from "@/components/ui/card";
import { ScanData } from "@/hooks/useScan";

interface TerminalProps {
  isActive?: boolean;
  className?: string;
  scanData?: ScanData | null;
  domain?: string;
}

export const Terminal = ({ isActive = false, className = "", scanData, domain = "example.com" }: TerminalProps) => {
  const [currentLine, setCurrentLine] = useState(0);
  const [terminalLines, setTerminalLines] = useState<string[]>([]);

  // Generate dynamic terminal lines based on scan data
  useEffect(() => {
    if (!scanData) {
      // Default static lines when no scan is running
      setTerminalLines([
        `$ subenum-pro --target ${domain} --mode advanced`,
        "[*] Ready to start subdomain enumeration...",
        "$ _"
      ]);
      setCurrentLine(0);
      return;
    }

    const lines = [
      `$ subenum-pro --target ${scanData.domain} --mode advanced`,
      "[*] Initializing SubEnum Pro v2.0.1",
      "[*] Loading reconnaissance modules...",
      "[+] DNS resolver configured: 8.8.8.8",
      "[+] Rate limiting: 50 concurrent connections",
    ];

    if (scanData.status === 'running' || scanData.status === 'completed') {
      lines.push("[*] Starting subdomain enumeration...");
      
      if (scanData.total_subdomains > 0) {
        lines.push(`[+] Certificate transparency logs: ${scanData.total_subdomains} entries found`);
      }
      
      if (scanData.live_subdomains > 0) {
        lines.push(`[+] DNS validation: ${scanData.live_subdomains} live subdomains confirmed`);
        lines.push(`[*] Port scanning in progress...`);
      }
      
      if (scanData.vulnerabilities > 0) {
        lines.push(`[!] Security issues detected: ${scanData.vulnerabilities} findings`);
      }
      
      if (scanData.high_risk > 0) {
        lines.push(`[!] High-risk vulnerabilities: ${scanData.high_risk} critical findings`);
      }
      
      if (scanData.status === 'completed') {
        lines.push("[*] Attack surface analysis complete");
        lines.push(`[+] Scan completed for ${scanData.domain}`);
      } else {
        lines.push(`[*] Progress: ${Math.round(scanData.progress)}% complete`);
      }
    }
    
    if (scanData.status === 'failed') {
      lines.push("[!] Scan failed - please check configuration");
    }
    
    lines.push("$ _");
    setTerminalLines(lines);
  }, [scanData, domain]);

  useEffect(() => {
    if (!isActive) {
      setCurrentLine(0);
      return;
    }
    
    const timer = setInterval(() => {
      setCurrentLine(prev => prev < terminalLines.length - 1 ? prev + 1 : prev);
    }, 600);

    return () => clearInterval(timer);
  }, [isActive, terminalLines.length]);

  return (
    <Card className={`bg-gradient-terminal border-primary/30 ${className}`}>
      <div className="p-6">
        <div className="flex items-center gap-2 mb-4">
          <div className="flex gap-1.5">
            <div className={`w-3 h-3 rounded-full ${
              scanData?.status === 'failed' ? 'bg-destructive' : 
              scanData?.status === 'completed' ? 'bg-success' :
              scanData?.status === 'running' ? 'bg-warning' :
              'bg-muted'
            }`}></div>
            <div className={`w-3 h-3 rounded-full ${
              scanData?.status === 'running' || scanData?.status === 'completed' ? 'bg-warning' : 'bg-muted'
            }`}></div>
            <div className={`w-3 h-3 rounded-full ${
              scanData?.status === 'completed' ? 'bg-success' : 'bg-muted'
            }`}></div>
          </div>
          <span className="text-sm font-mono text-muted-foreground">
            subenum-pro {scanData?.status ? `[${scanData.status}]` : '[ready]'}
          </span>
        </div>
        
        <div className="font-mono text-sm space-y-1 h-64 overflow-y-auto overflow-x-hidden">
          {terminalLines.slice(0, currentLine + 1).map((line, index) => (
            <div 
              key={index}
              className={`${
                line.startsWith('[+]') ? 'text-success' :
                line.startsWith('[!]') ? 'text-destructive' :
                line.startsWith('[*]') ? 'text-primary' :
                line.startsWith('$') ? 'text-accent' :
                'text-muted-foreground'
              } ${index === currentLine && scanData?.status === 'running' ? 'terminal-glow' : ''}`}
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