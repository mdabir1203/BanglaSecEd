import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Play, Settings, Globe, Shield, Zap } from "lucide-react";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";

interface SubdomainFormProps {
  onScan: (config: ScanConfig) => void;
  isScanning?: boolean;
}

export interface ScanConfig {
  domain: string;
  concurrency: number;
  timeout: number;
  enablePortScan: boolean;
  enableCorsCheck: boolean;
  enableTakeoverCheck: boolean;
  modules: string[];
}

export const SubdomainForm = ({ onScan, isScanning = false }: SubdomainFormProps) => {
  const [domain, setDomain] = useState("");
  const [concurrency, setConcurrency] = useState([50]);
  const [timeout, setTimeout] = useState([10]);
  const [enablePortScan, setEnablePortScan] = useState(true);
  const [enableCorsCheck, setEnableCorsCheck] = useState(true);
  const [enableTakeoverCheck, setEnableTakeoverCheck] = useState(true);

  const activeModules = [
    "Certificate Transparency",
    "DNS Brute Force",
    "Port Scanning",
    "CORS Analysis",
    "Takeover Detection"
  ].filter((module, index) => {
    if (index < 2) return true; // Always include CT and DNS
    if (index === 2) return enablePortScan;
    if (index === 3) return enableCorsCheck;
    if (index === 4) return enableTakeoverCheck;
    return false;
  });

  const handleScan = () => {
    if (!domain.trim()) return;
    
    onScan({
      domain: domain.trim(),
      concurrency: concurrency[0],
      timeout: timeout[0],
      enablePortScan,
      enableCorsCheck,
      enableTakeoverCheck,
      modules: activeModules
    });
  };

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-primary/30">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-primary">
          <Globe className="h-5 w-5" />
          Subdomain Enumeration
        </CardTitle>
        <CardDescription>
          Configure advanced reconnaissance parameters for target domain analysis
        </CardDescription>
      </CardHeader>
      
      <CardContent className="space-y-6">
        {/* Target Domain */}
        <div className="space-y-2">
          <Label htmlFor="domain" className="text-foreground">Target Domain</Label>
          <Input
            id="domain"
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            className="bg-input border-primary/30 focus:border-primary"
            disabled={isScanning}
          />
        </div>

        <Separator className="bg-border" />

        {/* Performance Settings */}
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Settings className="h-4 w-4 text-primary" />
            <Label className="text-foreground font-medium">Performance Settings</Label>
          </div>
          
          <div className="space-y-3">
            <div>
              <Label className="text-sm text-muted-foreground">
                Concurrency: {concurrency[0]} connections
              </Label>
              <Slider
                value={concurrency}
                onValueChange={setConcurrency}
                max={200}
                min={10}
                step={10}
                className="mt-2"
                disabled={isScanning}
              />
            </div>
            
            <div>
              <Label className="text-sm text-muted-foreground">
                Timeout: {timeout[0]} seconds
              </Label>
              <Slider
                value={timeout}
                onValueChange={setTimeout}
                max={60}
                min={5}
                step={5}
                className="mt-2"
                disabled={isScanning}
              />
            </div>
          </div>
        </div>

        <Separator className="bg-border" />

        {/* Security Modules */}
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <Label className="text-foreground font-medium">Security Analysis Modules</Label>
          </div>
          
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <Label htmlFor="port-scan" className="text-sm">Port Scanning</Label>
              <Switch
                id="port-scan"
                checked={enablePortScan}
                onCheckedChange={setEnablePortScan}
                disabled={isScanning}
              />
            </div>
            
            <div className="flex items-center justify-between">
              <Label htmlFor="cors-check" className="text-sm">CORS Misconfiguration</Label>
              <Switch
                id="cors-check"
                checked={enableCorsCheck}
                onCheckedChange={setEnableCorsCheck}
                disabled={isScanning}
              />
            </div>
            
            <div className="flex items-center justify-between">
              <Label htmlFor="takeover-check" className="text-sm">Subdomain Takeover</Label>
              <Switch
                id="takeover-check"
                checked={enableTakeoverCheck}
                onCheckedChange={setEnableTakeoverCheck}
                disabled={isScanning}
              />
            </div>
          </div>
        </div>

        {/* Active Modules Display */}
        <div className="space-y-2">
          <Label className="text-sm text-muted-foreground">Active Modules</Label>
          <div className="flex flex-wrap gap-2">
            {activeModules.map((module) => (
              <Badge key={module} variant="outline" className="border-primary/50 text-primary">
                {module}
              </Badge>
            ))}
          </div>
        </div>

        {/* Scan Button */}
        <Button 
          onClick={handleScan}
          disabled={!domain.trim() || isScanning}
          className="w-full bg-gradient-primary hover:shadow-glow transition-all duration-300"
          size="lg"
        >
          {isScanning ? (
            <>
              <Zap className="h-4 w-4 mr-2 animate-pulse" />
              Scanning in progress...
            </>
          ) : (
            <>
              <Play className="h-4 w-4 mr-2" />
              Start Reconnaissance
            </>
          )}
        </Button>
      </CardContent>
    </Card>
  );
};