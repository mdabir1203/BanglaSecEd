import { useState, useCallback, useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { toast } from 'sonner';

export interface ScanConfig {
  domain: string;
  concurrency: number;
  timeout: number;
  enablePortScan: boolean;
  enableCorsCheck: boolean;
  enableTakeoverCheck: boolean;
  modules: string[];
}

export interface SubdomainResult {
  subdomain: string;
  ip?: string;
  httpStatus?: number;
  serverHeader?: string;
  openPorts: number[];
  corsIssues: string[];
  technologies: string[];
  vulnerabilities: string[];
  risk: 'low' | 'medium' | 'high' | 'critical';
  fingerprints?: Record<string, string>;
}

export interface ScanData {
  id: string;
  domain: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  progress: number;
  total_subdomains: number;
  live_subdomains: number;
  vulnerabilities: number;
  high_risk: number;
  started_at: string;
  completed_at?: string;
  user_id: string;
}

export const useScan = () => {
  const [currentScan, setCurrentScan] = useState<ScanData | null>(null);
  const [results, setResults] = useState<SubdomainResult[]>([]);
  const [isScanning, setIsScanning] = useState(false);

  const startScan = useCallback(async (config: ScanConfig) => {
    try {
      // Check if user is authenticated
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) {
        toast.error('Please sign in to start a scan');
        return;
      }

      setIsScanning(true);
      setResults([]);
      
      const { data, error } = await supabase.functions.invoke('subdomain-scan', {
        body: { 
          config,
          user_id: user.id
        }
      });

      if (error) {
        throw error;
      }

      const scanId = data.scanId;
      toast.success('Scan started successfully');
      
      // Start polling for scan status
      pollScanStatus(scanId);
      
    } catch (error) {
      console.error('Error starting scan:', error);
      toast.error('Failed to start scan');
      setIsScanning(false);
    }
  }, []);

  const pollScanStatus = useCallback(async (scanId: string) => {
    const pollInterval = setInterval(async () => {
      try {
        // Get scan status
        const { data: scanData, error: scanError } = await supabase
          .from('scans')
          .select('*')
          .eq('id', scanId)
          .single();

        if (scanError) {
          console.error('Error fetching scan status:', scanError);
          return;
        }

        setCurrentScan(scanData as ScanData);

        // If scan is completed, get results and stop polling
        if (scanData.status === 'completed') {
          const { data: resultsData, error: resultsError } = await supabase
            .from('scan_results')
            .select('*')
            .eq('scan_id', scanId);

          if (resultsError) {
            console.error('Error fetching scan results:', resultsError);
          } else {
            // Transform database results to match our interface
            const transformedResults = (resultsData || []).map(result => ({
              subdomain: result.subdomain,
              ip: result.ip,
              httpStatus: result.http_status,
              serverHeader: result.server_header,
              openPorts: result.open_ports || [],
              corsIssues: result.cors_issues || [],
              technologies: result.technologies || [],
              vulnerabilities: result.vulnerabilities || [],
              risk: result.risk as 'low' | 'medium' | 'high' | 'critical',
              fingerprints: result.fingerprints as Record<string, string> || {}
            }));
            setResults(transformedResults);
          }

          setIsScanning(false);
          clearInterval(pollInterval);
          toast.success('Scan completed successfully');
        } else if (scanData.status === 'failed') {
          setIsScanning(false);
          clearInterval(pollInterval);
          toast.error('Scan failed');
        }
      } catch (error) {
        console.error('Error polling scan status:', error);
        clearInterval(pollInterval);
        setIsScanning(false);
      }
    }, 2000); // Poll every 2 seconds

    // Clean up interval after 10 minutes max
    setTimeout(() => {
      clearInterval(pollInterval);
      if (isScanning) {
        setIsScanning(false);
        toast.error('Scan timeout - please try again');
      }
    }, 600000);
  }, [isScanning]);

  const getRecentScans = useCallback(async () => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) {
        return [];
      }

      const { data, error } = await supabase
        .from('scans')
        .select('*')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false })
        .limit(10);

      if (error) {
        throw error;
      }

      return data || [];
    } catch (error) {
      console.error('Error fetching recent scans:', error);
      return [];
    }
  }, []);

  const getScanResults = useCallback(async (scanId: string) => {
    try {
      const { data: { user } } = await supabase.auth.getUser();
      if (!user) {
        return [];
      }

      const { data, error } = await supabase
        .from('scan_results')
        .select('*')
        .eq('scan_id', scanId)
        .eq('user_id', user.id);

      if (error) {
        throw error;
      }

      // Transform database results  
      return (data || []).map(result => ({
        subdomain: result.subdomain,
        ip: result.ip,
        httpStatus: result.http_status,
        serverHeader: result.server_header,
        openPorts: result.open_ports || [],
        corsIssues: result.cors_issues || [],
        technologies: result.technologies || [],
        vulnerabilities: result.vulnerabilities || [],
        risk: result.risk as 'low' | 'medium' | 'high' | 'critical',
        fingerprints: result.fingerprints as Record<string, string> || {}
      }));
    } catch (error) {
      console.error('Error fetching scan results:', error);
      return [];
    }
  }, []);

  // Stats calculation
  const stats = {
    totalFound: results.length,
    liveSubdomains: results.filter(r => r.httpStatus && r.httpStatus < 400).length,
    vulnerabilities: results.reduce((acc, r) => acc + (r.vulnerabilities?.length || 0), 0),
    highRisk: results.filter(r => r.risk === 'high' || r.risk === 'critical').length
  };

  return {
    currentScan,
    results,
    isScanning,
    stats,
    startScan,
    getRecentScans,
    getScanResults
  };
};