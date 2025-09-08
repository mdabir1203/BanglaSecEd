import { useState } from "react";
import { SubdomainForm, type ScanConfig } from "@/components/SubdomainForm";
import { Terminal } from "@/components/Terminal";
import { ResultsDashboard } from "@/components/ResultsDashboard";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Zap, Globe, Eye } from "lucide-react";

// Mock data for demonstration
const mockResults = [
  {
    subdomain: "api.example.com",
    ip: "192.168.1.100",
    httpStatus: 200,
    ports: [80, 443, 8080],
    corsIssues: ["Wildcard CORS allowed", "Allow-Credentials: true"],
    technologies: ["nginx", "nodejs", "react"],
    vulnerabilities: ["CORS misconfiguration allows credential theft", "Exposed API endpoints"],
    risk: "high" as const
  },
  {
    subdomain: "staging.example.com",
    ip: "192.168.1.101",
    httpStatus: 404,
    ports: [80, 443],
    corsIssues: [],
    technologies: ["apache", "php"],
    vulnerabilities: ["Potential subdomain takeover - AWS S3"],
    risk: "critical" as const
  },
  {
    subdomain: "www.example.com",
    ip: "192.168.1.102",
    httpStatus: 200,
    ports: [80, 443],
    corsIssues: [],
    technologies: ["cloudflare", "wordpress"],
    vulnerabilities: [],
    risk: "low" as const
  },
  {
    subdomain: "mail.example.com",
    ip: "192.168.1.103",
    httpStatus: 200,
    ports: [25, 465, 993],
    corsIssues: [],
    technologies: ["postfix", "dovecot"],
    vulnerabilities: [],
    risk: "medium" as const
  }
];

const Index = () => {
  const [isScanning, setIsScanning] = useState(false);
  const [showTerminal, setShowTerminal] = useState(false);
  const [results, setResults] = useState<typeof mockResults>([]);
  const [progress, setProgress] = useState(0);
  const [scanConfig, setScanConfig] = useState<ScanConfig | null>(null);

  const stats = {
    totalFound: results.length,
    liveSubdomains: results.filter(r => r.httpStatus && r.httpStatus < 400).length,
    vulnerabilities: results.reduce((acc, r) => acc + (r.vulnerabilities?.length || 0), 0),
    highRisk: results.filter(r => r.risk === 'high' || r.risk === 'critical').length
  };

  const handleScan = async (config: ScanConfig) => {
    setIsScanning(true);
    setShowTerminal(true);
    setScanConfig(config);
    setResults([]);
    setProgress(0);

    // Simulate scanning progress
    const totalSteps = 100;
    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= totalSteps) {
          clearInterval(interval);
          setIsScanning(false);
          setResults(mockResults);
          return totalSteps;
        }
        return prev + Math.random() * 5;
      });
    }, 200);
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Matrix Background Effect */}
      <div className="matrix-bg"></div>
      
      <div className="container mx-auto p-6 space-y-8">
        {/* Header */}
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center gap-3">
            <Shield className="h-12 w-12 text-primary cyber-glow" />
            <h1 className="text-4xl md:text-6xl font-bold bg-gradient-primary bg-clip-text text-transparent">
              SubEnum Pro
            </h1>
          </div>
          <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
            Advanced subdomain enumeration and attack surface mapping for cloud security professionals
          </p>
          <div className="flex items-center justify-center gap-4 flex-wrap">
            <Badge variant="outline" className="border-primary/50 text-primary">
              <Zap className="h-3 w-3 mr-1" />
              Real-time Analysis
            </Badge>
            <Badge variant="outline" className="border-primary/50 text-primary">
              <Globe className="h-3 w-3 mr-1" />
              DNS Enumeration
            </Badge>
            <Badge variant="outline" className="border-primary/50 text-primary">
              <Shield className="h-3 w-3 mr-1" />
              Security Assessment
            </Badge>
            <Badge variant="outline" className="border-primary/50 text-primary">
              <Eye className="h-3 w-3 mr-1" />
              Attack Surface Mapping
            </Badge>
          </div>
        </div>

        {/* Main Content */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Panel - Configuration */}
          <div className="space-y-6">
            <SubdomainForm onScan={handleScan} isScanning={isScanning} />
            
            {/* Features Card */}
            <Card className="bg-card/50 backdrop-blur-sm border-primary/30">
              <CardHeader>
                <CardTitle className="text-primary">Advanced Features</CardTitle>
                <CardDescription>
                  Professional-grade reconnaissance capabilities
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 bg-success rounded-full animate-pulse"></div>
                  <span className="text-sm">Certificate Transparency Mining</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 bg-success rounded-full animate-pulse"></div>
                  <span className="text-sm">Multi-threaded DNS Resolution</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 bg-success rounded-full animate-pulse"></div>
                  <span className="text-sm">Port & Service Discovery</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 bg-success rounded-full animate-pulse"></div>
                  <span className="text-sm">CORS Vulnerability Detection</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 bg-success rounded-full animate-pulse"></div>
                  <span className="text-sm">Subdomain Takeover Analysis</span>
                </div>
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 bg-success rounded-full animate-pulse"></div>
                  <span className="text-sm">Technology Stack Fingerprinting</span>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Right Panel - Results & Terminal */}
          <div className="lg:col-span-2 space-y-6">
            {/* Terminal */}
            {showTerminal && (
              <Terminal isActive={isScanning} />
            )}

            {/* Results Dashboard */}
            {(results.length > 0 || isScanning) && (
              <ResultsDashboard 
                results={results}
                isScanning={isScanning}
                progress={progress}
                stats={stats}
              />
            )}

            {/* Welcome Card - shown when no scan is active */}
            {!showTerminal && results.length === 0 && (
              <Card className="bg-gradient-cyber border-accent/30 text-center">
                <CardContent className="p-8">
                  <Shield className="h-16 w-16 text-accent mx-auto mb-4 cyber-glow" />
                  <h2 className="text-2xl font-bold text-accent mb-2">Ready for Reconnaissance</h2>
                  <p className="text-accent-foreground/80 mb-4">
                    Configure your scan parameters and start discovering the attack surface of your target domain.
                  </p>
                  <p className="text-sm text-accent-foreground/60">
                    Enter a target domain to begin advanced subdomain enumeration and security analysis.
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="text-center text-sm text-muted-foreground pt-8 border-t border-border">
          <p>SubEnum Pro v2.0.1 - Professional Subdomain Enumeration & Attack Surface Mapping</p>
          <p className="mt-1">Built for cybersecurity professionals and penetration testers</p>
        </div>
      </div>
    </div>
  );
};

export default Index;