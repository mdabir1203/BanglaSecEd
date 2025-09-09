import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Clock, Shield, AlertTriangle } from "lucide-react";
import { useScan } from "@/hooks/useScan";

export const ScanHistory = () => {
  const { getRecentScans, getScanResults } = useScan();
  const [recentScans, setRecentScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadRecentScans();
  }, []);

  const loadRecentScans = async () => {
    try {
      const scans = await getRecentScans();
      setRecentScans(scans);
    } catch (error) {
      console.error('Error loading recent scans:', error);
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return <Badge variant="success">Completed</Badge>;
      case 'running':
        return <Badge variant="outline">Running</Badge>;
      case 'failed':
        return <Badge variant="destructive">Failed</Badge>;
      default:
        return <Badge variant="secondary">Pending</Badge>;
    }
  };

  const getRiskBadge = (highRisk: number) => {
    if (highRisk > 5) return <Badge variant="destructive">High Risk</Badge>;
    if (highRisk > 0) return <Badge variant="warning">Medium Risk</Badge>;
    return <Badge variant="success">Low Risk</Badge>;
  };

  if (loading) {
    return (
      <Card className="bg-card/50 backdrop-blur-sm border-primary/30">
        <CardContent className="p-6">
          <div className="animate-pulse">Loading scan history...</div>
        </CardContent>
      </Card>
    );
  }

  if (recentScans.length === 0) {
    return (
      <Card className="bg-card/50 backdrop-blur-sm border-primary/30">
        <CardHeader>
          <CardTitle className="text-primary flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Recent Scans
          </CardTitle>
          <CardDescription>No previous scans found</CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-primary/30">
      <CardHeader>
        <CardTitle className="text-primary flex items-center gap-2">
          <Clock className="h-5 w-5" />
          Recent Scans
        </CardTitle>
        <CardDescription>
          Your recent subdomain enumeration scans
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {recentScans.slice(0, 5).map((scan) => (
          <div
            key={scan.id}
            className="flex items-center justify-between p-3 rounded-lg bg-background/50 border border-border/50"
          >
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-1">
                <Shield className="h-4 w-4 text-primary" />
                <span className="font-medium">{scan.domain}</span>
                {getStatusBadge(scan.status)}
              </div>
              <div className="text-sm text-muted-foreground">
                {new Date(scan.created_at).toLocaleDateString()} • 
                {scan.live_subdomains || 0} subdomains • 
                {scan.vulnerabilities || 0} vulnerabilities
              </div>
            </div>
            <div className="flex items-center gap-2">
              {scan.status === 'completed' && getRiskBadge(scan.high_risk || 0)}
              {scan.status === 'running' && (
                <div className="flex items-center gap-1 text-sm text-primary">
                  <div className="w-2 h-2 bg-primary rounded-full animate-pulse"></div>
                  {scan.progress || 0}%
                </div>
              )}
            </div>
          </div>
        ))}
        
        {recentScans.length > 5 && (
          <Button 
            variant="ghost" 
            size="sm" 
            className="w-full text-primary hover:text-primary-foreground"
            onClick={() => {/* TODO: Show all scans */}}
          >
            View All Scans
          </Button>
        )}
      </CardContent>
    </Card>
  );
};