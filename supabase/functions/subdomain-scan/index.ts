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

interface TakeoverEvidence {
  service: string;
  confidence: 'High' | 'Medium' | 'Low';
  proof: string;
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
  takeoverEvidence?: TakeoverEvidence[];
  cloudSaas?: string[];
}

const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (Version 14.1.1 Safari/605.1.15)",
];

const COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 8080, 8443, 3389, 27017, 9200, 9300];

const SUBDOMAIN_REGEX = /^[a-z0-9][-a-z0-9.]*[a-z0-9]\.([a-z0-9-]+\.)*[a-z0-9]+$/;
const IP_REGEX = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

const CLOUD_SAAS_PATTERNS = [
  { name: 'AWS S3', pattern: /^[a-z0-9-]+\.s3\.amazonaws\.com$/ },
  { name: 'Azure Blob', pattern: /^[a-z0-9-]+\.blob\.core\.windows\.net$/ },
  { name: 'GCP Storage', pattern: /^[a-z0-9-]+\.storage\.googleapis\.com$/ },
  { name: 'Heroku', pattern: /^[a-z0-9-]+\.herokuapp\.com$/ },
  { name: 'Netlify', pattern: /^[a-z0-9-]+\.netlify\.app$/ },
  { name: 'Shopify', pattern: /^[a-z0-9-]+\.myshopify\.com$/ },
  { name: 'Vercel', pattern: /^[a-z0-9-]+\.vercel\.app$/ },
  { name: 'Firebase', pattern: /^[a-z0-9-]+\.web\.app$/ },
];

const TAKEOVER_SIGNATURES = {
  'AWS S3': {
    patterns: ['s3', '.amazonaws.com'],
    errorSignatures: ['<Code>NoSuchBucket</Code>', 'The specified bucket does not exist']
  },
  'Heroku': {
    patterns: ['heroku'],
    errorSignatures: ['No such app', "There's nothing here, yet."],
    serverHeader: 'Cowboy'
  },
  'Azure Blob': {
    patterns: ['azure', '.blob.core.windows.net'],
    errorSignatures: ['<Code>BlobNotFound</Code>', '<Code>ContainerNotFound</Code>']
  },
  'GitHub Pages': {
    patterns: ['github'],
    errorSignatures: ["There isn't a GitHub Pages site here.", 'For root URLs']
  },
  'Netlify': {
    patterns: ['netlify'],
    errorSignatures: ['Not Found - Request ID:']
  }
};

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
    
    console.log(`Starting ShadowMap enhanced scan for ${config.domain} (user: ${user_id})`);

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
      message: 'ShadowMap enhanced scan started successfully' 
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
    await updateScanProgress(supabase, scanId, 5, 'Initializing ShadowMap scanner...');

    // 1. Enhanced CRT.sh Enumeration with retries
    const crtSubdomains = await crtshEnumerationWithRetries(config.domain, 3);
    console.log(`CRT.sh found ${crtSubdomains.size} potential subdomains`);

    await updateScanProgress(supabase, scanId, 15, 'Validating subdomains...');

    // 2. Enhanced validation and normalization
    const validatedSubdomains = enhancedValidateSubdomains(crtSubdomains, config.domain);
    console.log(`Validated ${validatedSubdomains.size} subdomains`);

    await updateScanProgress(supabase, scanId, 25, 'Performing DNS resolution...');

    // 3. Enhanced DNS resolution with multiple approaches
    const liveSubdomains = await enhancedDnsCheck(validatedSubdomains, config.concurrency);
    console.log(`${liveSubdomains.size} live subdomains detected`);

    await updateScanProgress(supabase, scanId, 35, 'Cloud/SaaS reconnaissance...');

    // 4. Cloud/SaaS reconnaissance
    const cloudSaasMap = await cloudSaasRecon(liveSubdomains, config.concurrency);

    await updateScanProgress(supabase, scanId, 45, 'Deep subdomain analysis...');

    // 5. Enhanced subdomain analysis
    const results: SubdomainResult[] = [];
    const subdomainArray = Array.from(liveSubdomains);
    
    for (let i = 0; i < subdomainArray.length; i += config.concurrency) {
      const batch = subdomainArray.slice(i, i + config.concurrency);
      const batchPromises = batch.map(subdomain => 
        enhancedAnalyzeSubdomain(subdomain, config, cloudSaasMap.get(subdomain))
      );
      const batchResults = await Promise.allSettled(batchPromises);
      
      batchResults.forEach((result) => {
        if (result.status === 'fulfilled' && result.value) {
          results.push(result.value);
        }
      });

      const progress = 45 + Math.floor((i / subdomainArray.length) * 45);
      await updateScanProgress(supabase, scanId, progress, `Analyzed ${i + batch.length}/${subdomainArray.length} subdomains`);
    }

    // 6. Store results in database
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

    // 7. Calculate final statistics
    const stats = calculateEnhancedStats(results);
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

    console.log(`ShadowMap scan ${scanId} completed successfully`);

  } catch (error) {
    console.error(`Error in ShadowMap scan ${scanId}:`, error);
    await supabase
      .from('scans')
      .update({
        status: 'failed',
        completed_at: new Date().toISOString()
      })
      .eq('id', scanId);
  }
}

// Enhanced CRT.sh enumeration with exponential backoff retries
async function crtshEnumerationWithRetries(domain: string, maxRetries: number): Promise<Set<string>> {
  const url = `https://crt.sh/?q=%25.${domain}&output=json`;
  const subdomains = new Set<string>();
  
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const userAgent = USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000);
      
      const response = await fetch(url, {
        headers: {
          'User-Agent': userAgent,
          'Accept': 'application/json'
        },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);

      if (!response.ok) {
        if (response.status >= 500 && attempt < maxRetries - 1) {
          await sleep(Math.pow(2, attempt) * 1000);
          continue;
        }
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
      break;
    } catch (error) {
      console.error(`CRT.sh attempt ${attempt + 1} failed:`, error);
      if (attempt === maxRetries - 1) {
        console.error('All CRT.sh attempts failed, continuing with empty set');
      } else {
        await sleep(Math.pow(2, attempt) * 1000);
      }
    }
  }

  return subdomains;
}

// Enhanced subdomain validation with better normalization
function enhancedValidateSubdomains(subdomains: Set<string>, targetDomain: string): Set<string> {
  const validated = new Set<string>();
  
  for (const sub of subdomains) {
    // Clean and normalize with better handling
    let cleaned = sub.replace(/^\*\./, '').replace(/^www\./, '');
    
    // Skip IP addresses
    if (IP_REGEX.test(cleaned)) {
      continue;
    }
    
    // Enhanced regex validation
    if (!SUBDOMAIN_REGEX.test(cleaned)) {
      continue;
    }
    
    // Ensure it belongs to target domain
    if (cleaned.endsWith(`.${targetDomain}`) || cleaned === targetDomain) {
      validated.add(cleaned);
    }
  }
  
  return validated;
}

// Enhanced DNS resolution with multiple validation approaches
async function enhancedDnsCheck(subdomains: Set<string>, concurrency: number): Promise<Set<string>> {
  const live = new Set<string>();
  const subdomainArray = Array.from(subdomains);
  
  // Process in batches to avoid overwhelming the system
  for (let i = 0; i < subdomainArray.length; i += concurrency) {
    const batch = subdomainArray.slice(i, i + concurrency);
    const promises = batch.map(async (subdomain) => {
      // Try multiple approaches: HTTPS, HTTP, and DNS over HTTPS
      const checks = [
        checkHttpsAvailability(subdomain),
        checkHttpAvailability(subdomain),
        checkDnsResolution(subdomain)
      ];
      
      const results = await Promise.allSettled(checks);
      return results.some(result => result.status === 'fulfilled' && result.value) ? subdomain : null;
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

async function checkHttpsAvailability(subdomain: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);
    
    const response = await fetch(`https://${subdomain}`, {
      method: 'HEAD',
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    return true;
  } catch {
    return false;
  }
}

async function checkHttpAvailability(subdomain: string): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);
    
    const response = await fetch(`http://${subdomain}`, {
      method: 'HEAD',
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    return true;
  } catch {
    return false;
  }
}

async function checkDnsResolution(subdomain: string): Promise<boolean> {
  try {
    // Use DNS over HTTPS for resolution check
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    
    const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${subdomain}&type=A`, {
      headers: { 'Accept': 'application/dns-json' },
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    const data = await response.json();
    return data.Answer && data.Answer.length > 0;
  } catch {
    return false;
  }
}

// Cloud/SaaS reconnaissance based on Rust implementation
async function cloudSaasRecon(subdomains: Set<string>, concurrency: number): Promise<Map<string, string[]>> {
  const results = new Map<string, string[]>();
  const subdomainArray = Array.from(subdomains);
  
  for (let i = 0; i < subdomainArray.length; i += concurrency) {
    const batch = subdomainArray.slice(i, i + concurrency);
    const promises = batch.map(async (subdomain) => {
      const findings: string[] = [];
      
      // Check against cloud/SaaS patterns
      for (const { name, pattern } of CLOUD_SAAS_PATTERNS) {
        if (pattern.test(subdomain)) {
          findings.push(`Matched ${name} pattern`);
        }
      }
      
      // Check for predicted cloud endpoints
      const predictions = [
        `api.${subdomain}`,
        `dev.${subdomain}`,
        `staging.${subdomain}`,
        `${subdomain.split('.')[0]}.s3.amazonaws.com`,
        `${subdomain.split('.')[0]}.blob.core.windows.net`,
        `${subdomain.split('.')[0]}.storage.googleapis.com`,
      ];
      
      for (const prediction of predictions) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 3000);
          
          const response = await fetch(`https://${prediction}`, {
            method: 'HEAD',
            signal: controller.signal
          });
          
          clearTimeout(timeoutId);
          findings.push(`Predicted endpoint exists: ${prediction}`);
        } catch {
          // Prediction failed, continue
        }
      }
      
      return findings.length > 0 ? { subdomain, findings } : null;
    });
    
    const batchResults = await Promise.allSettled(promises);
    batchResults.forEach((result) => {
      if (result.status === 'fulfilled' && result.value) {
        results.set(result.value.subdomain, result.value.findings);
      }
    });
  }
  
  return results;
}

// Enhanced subdomain analysis based on Rust implementation
async function enhancedAnalyzeSubdomain(
  subdomain: string, 
  config: ScanConfig, 
  cloudSaas?: string[]
): Promise<SubdomainResult | null> {
  try {
    const result: SubdomainResult = {
      subdomain,
      openPorts: [],
      corsIssues: [],
      technologies: [],
      vulnerabilities: [],
      risk: 'low',
      fingerprints: {},
      cloudSaas: cloudSaas || []
    };

    // Enhanced HTTP analysis
    await enhancedHttpAnalysis(subdomain, result, config);
    
    // Enhanced port scanning (if enabled)
    if (config.enablePortScan) {
      result.openPorts = await enhancedPortScan(subdomain);
    }
    
    // Enhanced CORS check (if enabled)
    if (config.enableCorsCheck) {
      await enhancedCorsCheck(subdomain, result);
    }
    
    // Enhanced subdomain takeover check (if enabled)
    if (config.enableTakeoverCheck) {
      result.takeoverEvidence = await enhancedTakeoverCheck(subdomain);
      if (result.takeoverEvidence && result.takeoverEvidence.length > 0) {
        result.vulnerabilities.push('Potential subdomain takeover detected');
      }
    }
    
    // Calculate enhanced risk level
    result.risk = calculateEnhancedRisk(result);
    
    return result;
  } catch (error) {
    console.error(`Error analyzing ${subdomain}:`, error);
    return null;
  }
}

// Enhanced HTTP analysis with better fingerprinting
async function enhancedHttpAnalysis(subdomain: string, result: SubdomainResult, config: ScanConfig) {
  const urls = [`https://${subdomain}`, `http://${subdomain}`];
  
  for (const url of urls) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), config.timeout * 1000);
      
      const response = await fetch(url, {
        signal: controller.signal,
        redirect: 'manual'
      });
      
      clearTimeout(timeoutId);
      result.httpStatus = response.status;
      
      // Enhanced header extraction
      const serverHeader = response.headers.get('server');
      if (serverHeader) {
        result.serverHeader = serverHeader;
        result.fingerprints.server = serverHeader;
      }
      
      // Enhanced technology detection
      enhancedTechnologyDetection(response.headers, result);
      
      // Body analysis for deeper fingerprinting
      try {
        const text = await response.text();
        enhancedBodyAnalysis(text, result);
      } catch (e) {
        // Body reading failed, continue
      }
      
      break; // Success, no need to try HTTP
    } catch (error) {
      continue;
    }
  }
}

// Enhanced technology detection based on Rust implementation
function enhancedTechnologyDetection(headers: Headers, result: SubdomainResult) {
  const techHeaders = [
    'x-powered-by', 'x-aspnet-version', 'x-request-id', 'via', 
    'x-backend-server', 'x-runtime', 'x-version', 'x-served-by',
    'server', 'x-generator', 'x-drupal-dynamic-cache'
  ];
  
  for (const headerName of techHeaders) {
    const value = headers.get(headerName);
    if (value) {
      result.fingerprints[headerName] = value;
      result.technologies.push(value);
    }
  }
}

// Enhanced body analysis with more comprehensive detection
function enhancedBodyAnalysis(body: string, result: SubdomainResult) {
  const bodyLower = body.toLowerCase();
  const techIndicators = [
    { tech: 'WordPress', indicators: ['wp-content', 'wp-includes', '/wp-json/', 'wp-admin'] },
    { tech: 'Drupal', indicators: ['drupal', 'drupal.js', '/sites/default/files'] },
    { tech: 'Joomla', indicators: ['joomla', '/media/jui/', 'joomla.org'] },
    { tech: 'React', indicators: ['react', '__react', 'react-dom', 'react-router'] },
    { tech: 'Angular', indicators: ['angular', 'ng-app', '@angular', 'angular.js'] },
    { tech: 'Vue.js', indicators: ['vue.js', 'vue.min.js', 'v-for', 'vuejs'] },
    { tech: 'Laravel', indicators: ['laravel', 'laravel_session', '/laravel/'] },
    { tech: 'Django', indicators: ['django', 'csrfmiddlewaretoken', 'django-admin'] },
    { tech: 'Spring Boot', indicators: ['spring-boot', 'spring framework', 'springframework'] },
    { tech: 'Express.js', indicators: ['express', 'x-powered-by: express'] },
    { tech: 'Ruby on Rails', indicators: ['ruby on rails', 'rails', 'authenticity_token'] }
  ];
  
  for (const { tech, indicators } of techIndicators) {
    if (indicators.some(indicator => bodyLower.includes(indicator))) {
      result.technologies.push(tech);
      result.fingerprints.framework = tech;
      break;
    }
  }
}

// Enhanced port scanning with better timeout handling
async function enhancedPortScan(subdomain: string): Promise<number[]> {
  const openPorts: number[] = [];
  const promises = COMMON_PORTS.map(async (port) => {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);
      
      // Try HTTP connection first, then raw TCP-like check via fetch
      const response = await fetch(`http://${subdomain}:${port}`, {
        method: 'HEAD',
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      return port;
    } catch {
      return null;
    }
  });
  
  const results = await Promise.allSettled(promises);
  results.forEach((result) => {
    if (result.status === 'fulfilled' && result.value) {
      openPorts.push(result.value);
    }
  });
  
  return openPorts;
}

// Enhanced CORS check with PoC validation based on Rust implementation
async function enhancedCorsCheck(subdomain: string, result: SubdomainResult) {
  const testOrigins = [
    'https://evil.com',
    'http://evil.com',
    'null',
    'https://attacker.example',
    'https://malicious.domain'
  ];
  
  for (const origin of testOrigins) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);
      
      const response = await fetch(`https://${subdomain}`, {
        headers: { 'Origin': origin },
        signal: controller.signal
      });
      
      clearTimeout(timeoutId);
      
      const allowOrigin = response.headers.get('access-control-allow-origin');
      const allowCredentials = response.headers.get('access-control-allow-credentials');
      
      if (allowOrigin === '*') {
        result.corsIssues.push('Wildcard CORS allowed');
        result.vulnerabilities.push('CORS misconfiguration allows cross-origin requests');
      } else if (allowOrigin === origin) {
        result.corsIssues.push(`Reflects arbitrary origin: ${origin}`);
        result.vulnerabilities.push('CORS reflects attacker-controlled origins');
      }
      
      if (allowCredentials === 'true') {
        result.corsIssues.push('Allow-Credentials: true with permissive origin');
        result.vulnerabilities.push('CORS allows credentials with dangerous configuration');
      }
      
      // Enhanced validation with body inspection for sensitive data
      if (allowOrigin === '*' || allowOrigin === origin) {
        try {
          const body = await response.text();
          const sensitiveKeywords = ['password', 'token', 'apikey', 'secret', 'credit', 'ssn'];
          const bodyLower = body.toLowerCase();
          
          for (const keyword of sensitiveKeywords) {
            if (bodyLower.includes(keyword)) {
              result.vulnerabilities.push(`CORS misconfiguration exposes sensitive data containing: ${keyword}`);
              break;
            }
          }
        } catch {
          // Body reading failed
        }
      }
      
    } catch (error) {
      // CORS check failed, continue
    }
  }
}

// Enhanced subdomain takeover detection based on Rust implementation
async function enhancedTakeoverCheck(subdomain: string): Promise<TakeoverEvidence[]> {
  const evidence: TakeoverEvidence[] = [];
  const subdomainLower = subdomain.toLowerCase();
  
  for (const [service, config] of Object.entries(TAKEOVER_SIGNATURES)) {
    // Check if subdomain matches service patterns
    if (config.patterns.some(pattern => subdomainLower.includes(pattern))) {
      try {
        // Test HTTPS first, then HTTP
        for (const protocol of ['https', 'http']) {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 10000);
          
          const response = await fetch(`${protocol}://${subdomain}`, {
            signal: controller.signal
          });
          
          clearTimeout(timeoutId);
          
          if (response.status === 404) {
            const body = await response.text();
            
            // Check for service-specific error signatures
            if (config.errorSignatures.some(sig => body.includes(sig))) {
              evidence.push({
                service,
                confidence: 'High',
                proof: body.substring(0, 500)
              });
              break;
            }
            
            // Check server header for Heroku
            if (service === 'Heroku' && config.serverHeader) {
              const serverHeader = response.headers.get('server');
              if (serverHeader === config.serverHeader) {
                evidence.push({
                  service,
                  confidence: 'Medium',
                  proof: `Server header: ${serverHeader}, Body snippet: ${body.substring(0, 200)}`
                });
                break;
              }
            }
          }
        }
      } catch (error) {
        // Connection failed - could indicate takeover opportunity
        if (error.name === 'AbortError' || error.message.includes('fetch')) {
          evidence.push({
            service,
            confidence: 'Low',
            proof: `Connection failed: ${error.message}`
          });
        }
      }
    }
  }
  
  return evidence;
}

// Enhanced risk calculation based on comprehensive factors
function calculateEnhancedRisk(result: SubdomainResult): 'low' | 'medium' | 'high' | 'critical' {
  let riskScore = 0;
  
  // CORS issues scoring
  riskScore += result.corsIssues.length * 2;
  
  // Vulnerability scoring
  riskScore += result.vulnerabilities.length * 3;
  
  // Takeover evidence scoring
  if (result.takeoverEvidence) {
    for (const evidence of result.takeoverEvidence) {
      switch (evidence.confidence) {
        case 'High': riskScore += 10; break;
        case 'Medium': riskScore += 6; break;
        case 'Low': riskScore += 3; break;
      }
    }
  }
  
  // Open ports scoring
  riskScore += Math.min(result.openPorts.length, 5);
  
  // Cloud/SaaS findings scoring
  if (result.cloudSaas && result.cloudSaas.length > 0) {
    riskScore += result.cloudSaas.length;
  }
  
  // Critical conditions
  if (result.takeoverEvidence?.some(e => e.confidence === 'High')) {
    return 'critical';
  }
  
  if (result.vulnerabilities.some(v => v.includes('sensitive data'))) {
    return 'critical';
  }
  
  if (riskScore >= 15) return 'critical';
  if (riskScore >= 8) return 'high';
  if (riskScore >= 4) return 'medium';
  return 'low';
}

// Enhanced statistics calculation
function calculateEnhancedStats(results: SubdomainResult[]) {
  return {
    vulnerabilities: results.reduce((acc, r) => acc + r.vulnerabilities.length, 0),
    highRisk: results.filter(r => r.risk === 'high' || r.risk === 'critical').length,
    takeoverTargets: results.filter(r => r.takeoverEvidence && r.takeoverEvidence.length > 0).length,
    corsIssues: results.filter(r => r.corsIssues.length > 0).length
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

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}