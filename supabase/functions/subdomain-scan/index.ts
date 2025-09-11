import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
const supabaseKey = Deno.env.get('SUPABASE_ANON_KEY')!;

interface ScanConfig {
  domain: string;
  concurrency: number;
  timeout: number;
  enablePortScan: boolean;
  enableCorsCheck: boolean;
  enableTakeoverCheck: boolean;
  modules: string[];
}

interface SubdomainResult {
  subdomain: string;
  ip?: string;
  httpStatus?: number;
  serverHeader?: string;
  openPorts: number[];
  corsIssues: string[];
  technologies: string[];
  vulnerabilities: string[];
  risk: 'low' | 'medium' | 'high' | 'critical';
  fingerprints: Record<string, string>;
}

const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
];

const COMMON_PORTS = [21, 22, 25, 80, 443, 3306, 8080, 8443, 3389, 5432, 27017, 9200, 9300];

const SUBDOMAIN_REGEX = /^[a-z0-9][-a-z0-9.]*[a-z0-9]\.([a-z0-9-]+\.)*[a-z0-9]+$/;
const IP_REGEX = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const supabase = createClient(supabaseUrl, supabaseKey);
    const { config, user_id }: { config: ScanConfig; user_id: string } = await req.json();
    
    if (!user_id) {
      return new Response(JSON.stringify({ error: 'Authentication required' }), {
        status: 401,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }
    
    console.log(`Starting subdomain scan for ${config.domain} (user: ${user_id})`);

    // Create scan record
    const { data: scan, error: scanError } = await supabase
      .from('scans')
      .insert({
        domain: config.domain,
        status: 'running',
        config: config,
        user_id: user_id,
        started_at: new Date().toISOString()
      })
      .select()
      .single();

    if (scanError) {
      throw new Error(`Failed to create scan: ${scanError.message}`);
    }

    // Start background scan  
    performScan(scan.id, config, user_id, supabase).catch(error => {
      console.error('Background scan failed:', error);
    });

    return new Response(JSON.stringify({ 
      scanId: scan.id,
      message: 'Scan started successfully' 
    }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });

  } catch (error) {
    console.error('Error in subdomain-scan function:', error);
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});

async function performScan(scanId: string, config: ScanConfig, userId: string, supabase: any) {
  try {
    // Update scan status
    await updateScanProgress(supabase, scanId, 10, 'Enumerating subdomains...');

    // 1. CRT.sh Enumeration
    const crtSubdomains = await crtshEnumeration(config.domain);
    console.log(`CRT.sh found ${crtSubdomains.size} potential subdomains`);

    // 2. Validate and normalize subdomains
    const validatedSubdomains = validateSubdomains(crtSubdomains, config.domain);
    console.log(`Validated ${validatedSubdomains.size} subdomains`);

    await updateScanProgress(supabase, scanId, 30, 'Checking DNS resolution...');

    // 3. DNS resolution check
    const liveSubdomains = await checkDnsLive(validatedSubdomains, config.concurrency);
    console.log(`${liveSubdomains.size} live subdomains detected`);

    await updateScanProgress(supabase, scanId, 50, 'Analyzing subdomains...');

    // 4. Analyze each live subdomain
    const results: SubdomainResult[] = [];
    const subdomainArray = Array.from(liveSubdomains);
    
    for (let i = 0; i < subdomainArray.length; i += config.concurrency) {
      const batch = subdomainArray.slice(i, i + config.concurrency);
      const batchPromises = batch.map(subdomain => analyzeSubdomain(subdomain, config));
      const batchResults = await Promise.allSettled(batchPromises);
      
      batchResults.forEach((result, index) => {
        if (result.status === 'fulfilled' && result.value) {
          results.push(result.value);
        }
      });

      const progress = 50 + Math.floor((i / subdomainArray.length) * 40);
      await updateScanProgress(supabase, scanId, progress, `Analyzed ${i + batch.length}/${subdomainArray.length} subdomains`);
    }

    // 5. Store results in database
    if (results.length > 0) {
      const { error: insertError } = await supabase
        .from('scan_results')
        .insert(results.map(result => ({
          scan_id: scanId,
          user_id: userId,
          subdomain: result.subdomain,
          ip: result.ip,
          http_status: result.httpStatus,
          server_header: result.serverHeader,
          open_ports: result.openPorts,
          cors_issues: result.corsIssues,
          technologies: result.technologies,
          vulnerabilities: result.vulnerabilities,
          risk: result.risk,
          fingerprints: result.fingerprints
        })));

      if (insertError) {
        console.error('Error inserting scan results:', insertError);
      }
    }

    // 6. Update final scan statistics
    const stats = calculateStats(results);
    await supabase
      .from('scans')
      .update({
        status: 'completed',
        progress: 100,
        total_subdomains: validatedSubdomains.size,
        live_subdomains: liveSubdomains.size,
        vulnerabilities: stats.vulnerabilities,
        high_risk: stats.highRisk,
        completed_at: new Date().toISOString()
      })
      .eq('id', scanId);

    console.log(`Scan ${scanId} completed successfully`);

  } catch (error) {
    console.error(`Error in scan ${scanId}:`, error);
    await supabase
      .from('scans')
      .update({
        status: 'failed',
        completed_at: new Date().toISOString()
      })
      .eq('id', scanId);
  }
}

async function crtshEnumeration(domain: string): Promise<Set<string>> {
  const url = `https://crt.sh/?q=%25.${domain}&output=json`;
  const subdomains = new Set<string>();
  
  try {
    const userAgent = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
    const response = await fetch(url, {
      headers: {
        'User-Agent': userAgent,
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      throw new Error(`CRT.sh request failed: ${response.status}`);
    }

    const data = await response.json();
    
    for (const entry of data) {
      const names = entry.name_value.split('\n');
      for (const name of names) {
        const trimmed = name.trim().toLowerCase();
        if (trimmed && !trimmed.startsWith('*')) {
          subdomains.add(trimmed);
        }
      }
    }
  } catch (error) {
    console.error('CRT.sh enumeration error:', error);
  }

  return subdomains;
}

function validateSubdomains(subdomains: Set<string>, targetDomain: string): Set<string> {
  const validated = new Set<string>();
  
  for (const sub of subdomains) {
    const cleaned = sub.replace(/^\*\./, '').replace(/^www\./, '');
    
    if (IP_REGEX.test(cleaned) || !SUBDOMAIN_REGEX.test(cleaned)) {
      continue;
    }
    
    if (cleaned.endsWith(`.${targetDomain}`) || cleaned === targetDomain) {
      validated.add(cleaned);
    }
  }
  
  return validated;
}

async function checkDnsLive(subdomains: Set<string>, concurrency: number): Promise<Set<string>> {
  const live = new Set<string>();
  const subdomainArray = Array.from(subdomains);
  
  for (let i = 0; i < subdomainArray.length; i += concurrency) {
    const batch = subdomainArray.slice(i, i + concurrency);
    const promises = batch.map(async (subdomain) => {
      try {
        // Simple DNS check by attempting HTTP request
        const response = await fetch(`https://${subdomain}`, {
          method: 'HEAD',
          signal: AbortSignal.timeout(5000)
        });
        return subdomain;
      } catch {
        try {
          const response = await fetch(`http://${subdomain}`, {
            method: 'HEAD',
            signal: AbortSignal.timeout(5000)
          });
          return subdomain;
        } catch {
          return null;
        }
      }
    });
    
    const results = await Promise.allSettled(promises);
    results.forEach((result) => {
      if (result.status === 'fulfilled' && result.value) {
        live.add(result.value);
      }
    });
  }
  
  return live;
}

async function analyzeSubdomain(subdomain: string, config: ScanConfig): Promise<SubdomainResult | null> {
  try {
    const result: SubdomainResult = {
      subdomain,
      openPorts: [],
      corsIssues: [],
      technologies: [],
      vulnerabilities: [],
      risk: 'low',
      fingerprints: {}
    };

    // HTTP Analysis
    await analyzeHttp(subdomain, result, config);
    
    // CORS Check
    if (config.enableCorsCheck) {
      await checkCors(subdomain, result);
    }
    
    // Subdomain Takeover Check
    if (config.enableTakeoverCheck) {
      checkSubdomainTakeover(subdomain, result);
    }
    
    // Calculate risk level
    result.risk = calculateRisk(result);
    
    return result;
  } catch (error) {
    console.error(`Error analyzing ${subdomain}:`, error);
    return null;
  }
}

async function analyzeHttp(subdomain: string, result: SubdomainResult, config: ScanConfig) {
  const urls = [`https://${subdomain}`, `http://${subdomain}`];
  
  for (const url of urls) {
    try {
      const response = await fetch(url, {
        signal: AbortSignal.timeout(config.timeout * 1000),
        redirect: 'manual'
      });
      
      result.httpStatus = response.status;
      
      // Extract server header
      const serverHeader = response.headers.get('server');
      if (serverHeader) {
        result.serverHeader = serverHeader;
        result.fingerprints.server = serverHeader;
      }
      
      // Technology detection from headers
      detectTechnologies(response.headers, result);
      
      // Try to get response body for further analysis
      try {
        const text = await response.text();
        detectTechnologiesFromBody(text, result);
      } catch (e) {
        // Body reading failed, continue
      }
      
      break; // Success, no need to try HTTP
    } catch (error) {
      // Try next URL
      continue;
    }
  }
}

function detectTechnologies(headers: Headers, result: SubdomainResult) {
  const techHeaders = [
    'x-powered-by',
    'x-aspnet-version',
    'x-request-id',
    'via',
    'x-backend-server'
  ];
  
  for (const headerName of techHeaders) {
    const value = headers.get(headerName);
    if (value) {
      result.fingerprints[headerName] = value;
      result.technologies.push(value);
    }
  }
}

function detectTechnologiesFromBody(body: string, result: SubdomainResult) {
  const bodyLower = body.toLowerCase();
  const techIndicators = [
    ['wordpress', 'wp-content'],
    ['drupal', 'drupal'],
    ['joomla', 'joomla'],
    ['react', 'react'],
    ['angular', 'angular'],
    ['vue', 'vue.js'],
    ['laravel', 'laravel']
  ];
  
  for (const [tech, indicator] of techIndicators) {
    if (bodyLower.includes(indicator)) {
      result.technologies.push(tech);
      result.fingerprints.framework = tech;
      break;
    }
  }
}

async function checkCors(subdomain: string, result: SubdomainResult) {
  const testOrigins = [
    'https://evil.com',
    'http://evil.com',
    'null',
    'https://attacker.example'
  ];
  
  for (const origin of testOrigins) {
    try {
      const response = await fetch(`https://${subdomain}`, {
        headers: { 'Origin': origin },
        signal: AbortSignal.timeout(5000)
      });
      
      const allowOrigin = response.headers.get('access-control-allow-origin');
      const allowCredentials = response.headers.get('access-control-allow-credentials');
      
      if (allowOrigin === '*') {
        result.corsIssues.push('Wildcard CORS allowed');
        result.vulnerabilities.push('CORS misconfiguration allows cross-origin requests');
      } else if (allowOrigin === origin) {
        result.corsIssues.push(`Reflects origin: ${origin}`);
        result.vulnerabilities.push('CORS reflects arbitrary origins');
      }
      
      if (allowCredentials === 'true') {
        result.corsIssues.push('Allow-Credentials: true');
        result.vulnerabilities.push('CORS allows credentials with permissive origin');
      }
      
    } catch (error) {
      // CORS check failed, continue
    }
  }
}

function checkSubdomainTakeover(subdomain: string, result: SubdomainResult) {
  const takeoverPatterns = [
    ['heroku', 'Heroku App'],
    ['s3', 'AWS S3'],
    ['azure', 'Microsoft Azure'],
    ['cloudfront', 'AWS CloudFront'],
    ['github', 'GitHub Pages'],
    ['firebase', 'Firebase'],
    ['netlify', 'Netlify'],
    ['vercel', 'Vercel']
  ];
  
  const subdomainLower = subdomain.toLowerCase();
  
  for (const [pattern, service] of takeoverPatterns) {
    if (subdomainLower.includes(pattern)) {
      result.vulnerabilities.push(`Potential ${service} subdomain takeover`);
    }
  }
}

function calculateRisk(result: SubdomainResult): 'low' | 'medium' | 'high' | 'critical' {
  let riskScore = 0;
  
  // CORS issues
  if (result.corsIssues.length > 0) {
    riskScore += result.corsIssues.length * 2;
  }
  
  // Vulnerabilities
  riskScore += result.vulnerabilities.length * 3;
  
  // Subdomain takeover is critical
  if (result.vulnerabilities.some(v => v.includes('takeover'))) {
    return 'critical';
  }
  
  if (riskScore >= 6) return 'high';
  if (riskScore >= 3) return 'medium';
  return 'low';
}

function calculateStats(results: SubdomainResult[]) {
  return {
    vulnerabilities: results.reduce((acc, r) => acc + r.vulnerabilities.length, 0),
    highRisk: results.filter(r => r.risk === 'high' || r.risk === 'critical').length
  };
}

async function updateScanProgress(supabase: any, scanId: string, progress: number, status?: string) {
  await supabase
    .from('scans')
    .update({ 
      progress,
      ...(status && { status: 'running' })
    })
    .eq('id', scanId);
}