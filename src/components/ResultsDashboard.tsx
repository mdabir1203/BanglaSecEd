import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Globe, 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Server, 
  Eye,
  Download,
  ExternalLink,
  TrendingUp
} from "lucide-react";
import { Button } from "@/components/ui/button";

interface SubdomainResult {
  subdomain: string;
  ip?: string;
  httpStatus?: number;
  ports?: number[];
  corsIssues?: string[];
  technologies?: string[];
  vulnerabilities?: string[];
  risk: 'low' | 'medium' | 'high' | 'critical';
}

interface ResultsDashboardProps {
  results: SubdomainResult[];
  isScanning: boolean;
  progress: number;
  stats: {
    totalFound: number;
    liveSubdomains: number;
    vulnerabilities: number;
    highRisk: number;
  };
}

export const ResultsDashboard = ({ 
  results, 
  isScanning, 
  progress,
  stats 
}: ResultsDashboardProps) => {
  
  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'critical': return 'text-destructive';
      case 'high': return 'text-warning';
      case 'medium': return 'text-accent';
      case 'low': return 'text-success';
      default: return 'text-muted-foreground';
    }
  };

  const getRiskBadgeVariant = (risk: string) => {
    switch (risk) {
      case 'critical': return 'destructive';
      case 'high': return 'secondary';
      case 'medium': return 'outline';
      case 'low': return 'secondary';
      default: return 'outline';
    }
  };

  return (
    <div className="space-y-6">
      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="bg-gradient-terminal border-primary/30">
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-primary" />
              <div>
                <p className="text-2xl font-mono font-bold text-primary">{stats.totalFound}</p>
                <p className="text-xs text-muted-foreground">Total Found</p>
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gradient-terminal border-success/30">
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-success" />
              <div>
                <p className="text-2xl font-mono font-bold text-success">{stats.liveSubdomains}</p>
                <p className="text-xs text-muted-foreground">Live Subdomains</p>
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gradient-terminal border-warning/30">
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-warning" />
              <div>
                <p className="text-2xl font-mono font-bold text-warning">{stats.vulnerabilities}</p>
                <p className="text-xs text-muted-foreground">Vulnerabilities</p>
              </div>
            </div>
          </CardContent>
        </Card>
        
        <Card className="bg-gradient-terminal border-destructive/30">
          <CardContent className="p-4">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-destructive" />
              <div>
                <p className="text-2xl font-mono font-bold text-destructive">{stats.highRisk}</p>
                <p className="text-xs text-muted-foreground">High Risk</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Progress Bar */}
      {isScanning && (
        <Card className="bg-card/50 backdrop-blur-sm border-primary/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-mono text-primary">Reconnaissance Progress</span>
              <span className="text-sm font-mono text-muted-foreground">{progress}%</span>
            </div>
            <Progress value={progress} className="h-2" />
          </CardContent>
        </Card>
      )}

      {/* Results Tabs */}
      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="bg-muted/50">
          <TabsTrigger value="overview" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            Overview
          </TabsTrigger>
          <TabsTrigger value="subdomains" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            Subdomains
          </TabsTrigger>
          <TabsTrigger value="vulnerabilities" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            Vulnerabilities
          </TabsTrigger>
          <TabsTrigger value="attack-surface" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            Attack Surface
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <Card className="bg-card/50 backdrop-blur-sm border-primary/30">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <TrendingUp className="h-5 w-5 text-primary" />
                  Reconnaissance Overview
                </span>
                <Button variant="outline" size="sm" className="border-primary/30">
                  <Download className="h-4 w-4 mr-2" />
                  Export Results
                </Button>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h3 className="font-semibold mb-3 text-primary">Risk Distribution</h3>
                  <div className="space-y-2">
                    {['critical', 'high', 'medium', 'low'].map(risk => {
                      const count = results.filter(r => r.risk === risk).length;
                      return (
                        <div key={risk} className="flex items-center justify-between">
                          <Badge variant={getRiskBadgeVariant(risk)} className="w-20 justify-center">
                            {risk}
                          </Badge>
                          <span className={`font-mono ${getRiskColor(risk)}`}>{count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
                
                <div>
                  <h3 className="font-semibold mb-3 text-primary">Common Technologies</h3>
                  <div className="space-y-1">
                    {['nginx', 'apache', 'cloudflare', 'aws'].map(tech => (
                      <div key={tech} className="flex items-center justify-between">
                        <span className="text-sm capitalize">{tech}</span>
                        <Badge variant="outline" className="border-primary/30">
                          {Math.floor(Math.random() * 20) + 1}
                        </Badge>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="subdomains">
          <Card className="bg-card/50 backdrop-blur-sm border-primary/30">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe className="h-5 w-5 text-primary" />
                Discovered Subdomains
              </CardTitle>
              <CardDescription>
                {results.length} subdomains discovered with detailed analysis
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-96">
                <div className="space-y-2">
                  {results.map((result, index) => (
                    <div 
                      key={index}
                      className="flex items-center justify-between p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <Badge variant={getRiskBadgeVariant(result.risk)} className="w-16 justify-center text-xs">
                          {result.risk}
                        </Badge>
                        <div>
                          <p className="font-mono text-sm text-primary">{result.subdomain}</p>
                          <p className="text-xs text-muted-foreground">{result.ip || 'No IP'}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {result.httpStatus && (
                          <Badge variant="outline" className="border-success/30 text-success">
                            HTTP {result.httpStatus}
                          </Badge>
                        )}
                        {result.ports && result.ports.length > 0 && (
                          <Badge variant="outline" className="border-primary/30">
                            {result.ports.length} ports
                          </Badge>
                        )}
                        <Button variant="ghost" size="sm">
                          <ExternalLink className="h-3 w-3" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="vulnerabilities">
          <Card className="bg-card/50 backdrop-blur-sm border-primary/30">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-warning" />
                Security Vulnerabilities
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-96">
                <div className="space-y-3">
                  {results.filter(r => r.vulnerabilities && r.vulnerabilities.length > 0).map((result, index) => (
                    <div key={index} className="p-4 rounded-lg bg-destructive/10 border border-destructive/30">
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-mono text-sm text-primary">{result.subdomain}</span>
                        <Badge variant="destructive">{result.risk}</Badge>
                      </div>
                      <div className="space-y-1">
                        {result.vulnerabilities?.map((vuln, vIndex) => (
                          <p key={vIndex} className="text-sm text-destructive-foreground">• {vuln}</p>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="attack-surface">
          <Card className="bg-card/50 backdrop-blur-sm border-primary/30">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Server className="h-5 w-5 text-primary" />
                Attack Surface Map
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="text-center p-4 rounded-lg bg-muted/30">
                    <p className="text-2xl font-bold text-primary">{results.filter(r => r.ports && r.ports.length > 0).length}</p>
                    <p className="text-sm text-muted-foreground">Exposed Services</p>
                  </div>
                  <div className="text-center p-4 rounded-lg bg-muted/30">
                    <p className="text-2xl font-bold text-warning">{results.filter(r => r.corsIssues && r.corsIssues.length > 0).length}</p>
                    <p className="text-sm text-muted-foreground">CORS Issues</p>
                  </div>
                  <div className="text-center p-4 rounded-lg bg-muted/30">
                    <p className="text-2xl font-bold text-accent">{results.filter(r => r.technologies && r.technologies.length > 0).length}</p>
                    <p className="text-sm text-muted-foreground">Tech Stack</p>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
};