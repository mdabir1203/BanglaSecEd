-- Create scans table to track scanning sessions
CREATE TABLE public.scans (
    id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    domain TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    config JSONB NOT NULL DEFAULT '{}',
    progress INTEGER DEFAULT 0,
    total_subdomains INTEGER DEFAULT 0,
    live_subdomains INTEGER DEFAULT 0,
    vulnerabilities INTEGER DEFAULT 0,
    high_risk INTEGER DEFAULT 0,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create scan_results table to store individual subdomain findings
CREATE TABLE public.scan_results (
    id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    subdomain TEXT NOT NULL,
    ip TEXT,
    http_status INTEGER,
    server_header TEXT,
    open_ports INTEGER[] DEFAULT '{}',
    cors_issues TEXT[] DEFAULT '{}',
    technologies TEXT[] DEFAULT '{}',
    vulnerabilities TEXT[] DEFAULT '{}',
    risk TEXT NOT NULL DEFAULT 'low' CHECK (risk IN ('low', 'medium', 'high', 'critical')),
    fingerprints JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_results ENABLE ROW LEVEL SECURITY;

-- Create policies for public access (since this is a demo tool)
CREATE POLICY "Public can view scans" ON public.scans FOR SELECT USING (true);
CREATE POLICY "Public can create scans" ON public.scans FOR INSERT WITH CHECK (true);
CREATE POLICY "Public can update scans" ON public.scans FOR UPDATE USING (true);

CREATE POLICY "Public can view scan results" ON public.scan_results FOR SELECT USING (true);
CREATE POLICY "Public can create scan results" ON public.scan_results FOR INSERT WITH CHECK (true);
CREATE POLICY "Public can update scan results" ON public.scan_results FOR UPDATE USING (true);

-- Create indexes for performance
CREATE INDEX idx_scans_domain ON public.scans(domain);
CREATE INDEX idx_scans_status ON public.scans(status);
CREATE INDEX idx_scans_created_at ON public.scans(created_at DESC);
CREATE INDEX idx_scan_results_scan_id ON public.scan_results(scan_id);
CREATE INDEX idx_scan_results_risk ON public.scan_results(risk);

-- Create function to update timestamps
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = public;

-- Create triggers for automatic timestamp updates
CREATE TRIGGER update_scans_updated_at
    BEFORE UPDATE ON public.scans
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();

CREATE TRIGGER update_scan_results_updated_at
    BEFORE UPDATE ON public.scan_results
    FOR EACH ROW
    EXECUTE FUNCTION public.update_updated_at_column();