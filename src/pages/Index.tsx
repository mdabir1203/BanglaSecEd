import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import { useScan } from "@/hooks/useScan";
import { SubdomainForm, type ScanConfig } from "@/components/SubdomainForm";
import { Terminal } from "@/components/Terminal";
import { ResultsDashboard } from "@/components/ResultsDashboard";
import { ScanHistory } from "@/components/ScanHistory";
import { Header } from "@/components/Header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Shield, Zap, Globe, Eye, Lock } from "lucide-react";

const Index = () => {
  const { isAuthenticated, loading } = useAuth();
  const navigate = useNavigate();
  const { currentScan, results, isScanning, stats, startScan } = useScan();

  // Redirect unauthenticated users to auth page
  useEffect(() => {
    if (!loading && !isAuthenticated) {
      navigate('/auth');
    }
  }, [isAuthenticated, loading, navigate]);

  // Show loading while checking auth
  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="matrix-bg"></div>
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary"></div>
      </div>
    );
  }

  // Don't render anything if not authenticated (will redirect)
  if (!isAuthenticated) {
    return null;
  }

  const handleScan = async (config: ScanConfig) => {
    await startScan(config);
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Matrix Background Effect */}
      <div className="matrix-bg"></div>
      
      <div className="container mx-auto p-6 space-y-8">
        {/* Header with user info and sign out */}
        <Header />
        
        {/* Header */}
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center gap-3">
            <img src="/lovable-uploads/3da5b9b8-0ec3-4f18-9fe2-9ee76f298099.png" alt="ShadowMap Logo" className="h-12 w-12" />
            <h1 className="text-4xl md:text-6xl font-bold bg-gradient-primary bg-clip-text text-transparent">
              ShadowMap
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
            
            {/* Scan History */}
            <ScanHistory />
            
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
            {(isScanning || currentScan) && (
              <Terminal 
                isActive={isScanning} 
                scanData={currentScan}
                domain={currentScan?.domain || "example.com"}
              />
            )}

            {/* Results Dashboard */}
            {(results.length > 0 || isScanning) && (
              <ResultsDashboard 
                results={results}
                isScanning={isScanning}
                progress={currentScan?.progress || 0}
                stats={stats}
              />
            )}

            {/* Welcome Card - shown when no scan is active */}
            {!isScanning && !currentScan && results.length === 0 && (
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
          <p>ShadowMap v2.0.1 - Professional Subdomain Enumeration & Attack Surface Mapping</p>
          <p className="mt-1">Built for cybersecurity professionals and penetration testers</p>
        </div>
      </div>
    </div>
  );
};

export default Index;