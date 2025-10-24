
import React, { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Search, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface DomainAnalysisCardProps {
  onResults: (result: any) => void;
  onMetascraperResults: (result: any) => void;
  onVirusTotalResults: (result: any) => void;
}

const DomainAnalysisCard = ({ onResults, onMetascraperResults, onVirusTotalResults }: DomainAnalysisCardProps) => {
  const [domain, setDomain] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const { toast } = useToast();

  const fetchWithTimeout = async (url: string, timeout = 15000) => {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);
    try {
      const res = await fetch(url, { signal: controller.signal });
      clearTimeout(id);
      return res;
    } catch (err: any) {
      clearTimeout(id);
      throw err;
    }
  };

  const handleScan = async () => {
    if (!domain.trim()) {
      toast({
        title: "Invalid Input",
        description: "Please enter a valid domain name",
        variant: "destructive",
      });
      return;
    }

    setIsScanning(true);
    
    try {
      const whoisUrl = `/api/whois/?domain=${encodeURIComponent(domain.trim())}`;
      let response: Response;
      // Simple retry for WHOIS fetch
      for (let attempt = 0; attempt < 2; attempt++) {
        try {
          response = await fetchWithTimeout(whoisUrl);
          break;
        } catch (err: any) {
          if (err.name === 'AbortError') {
            if (attempt === 1) throw new Error('Request timed out. Please try again later.');
            continue;
          }
          if (attempt === 1) throw err;
        }
      }
      if (!response.ok) {
        throw new Error(`API responded with status ${response.status}`);
      }
      const data = await response.json();

      const result = {
        id: Date.now(),
        domain: data.domain || domain.trim(),
        created: data.creation_date || "-",
        expires: data.expiration_date || "-",
        domain_age: data.domain_age || "-",
        registrar: data.registrar || "-",
        name_servers: data.name_servers || [],
        abuse_score: 0, // not provided by API
        is_vpn_proxy: false,
        ip_address: (data.ipv4_addresses?.[0]) || (data.ipv6_addresses?.[0]) || "-",
        country: (data.ipv4_locations?.[0]?.country) || (data.ipv6_locations?.[0]?.country) || "-",
        region: (data.ipv4_locations?.[0]?.region) || (data.ipv6_locations?.[0]?.region) || "-",
        city: (data.ipv4_locations?.[0]?.city) || (data.ipv6_locations?.[0]?.city) || "-",
        longitude: (data.ipv4_locations?.[0]?.longitude) || (data.ipv6_locations?.[0]?.longitude) || "-",
        latitude: (data.ipv4_locations?.[0]?.latitude) || (data.ipv6_locations?.[0]?.latitude) || "-",
        isp: (data.ipv4_locations?.[0]?.isp) || "-",
        timestamp: new Date().toLocaleString(),
      };

      // Skipping ISP enrichment and AbuseIPDB in the blocking path to speed up single scan

      onResults(result);
      
      // Kick off Metascraper in background (non-blocking)
      void (async () => {
        try {
          const targetUrl = `https://${domain.trim()}`;
          const corsProxies = [
            `https://api.allorigins.win/raw?url=${encodeURIComponent(targetUrl)}`,
            `https://corsproxy.io/?${encodeURIComponent(targetUrl)}`,
            `https://api.codetabs.com/v1/proxy?quest=${encodeURIComponent(targetUrl)}`,
          ];
          let metascraperResponse: Response | null = null;
          let lastError: any = null;
          for (const proxyUrl of corsProxies) {
            try {
              metascraperResponse = await fetchWithTimeout(proxyUrl, 8000);
              if (metascraperResponse.ok) break;
            } catch (err) {
              lastError = err;
              continue;
            }
          }
          if (!metascraperResponse || !metascraperResponse.ok) {
            throw lastError || new Error('All CORS proxies failed');
          }
          const html = await metascraperResponse.text();
          const metaData: any = { id: Date.now() + 1, domain: domain.trim(), timestamp: new Date().toLocaleString() };
          const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
          const ogTitleMatch = html.match(/<meta[^>]*property=["']og:title["'][^>]*content=["']([^"']+)["']/i);
          const twitterTitleMatch = html.match(/<meta[^>]*name=["']twitter:title["'][^>]*content=["']([^"']+)["']/i);
          metaData.title = (ogTitleMatch?.[1] || twitterTitleMatch?.[1] || titleMatch?.[1] || '').trim();
          const descMatch = html.match(/<meta[^>]*name=["']description["'][^>]*content=["']([^"']+)["']/i);
          const ogDescMatch = html.match(/<meta[^>]*property=["']og:description["'][^>]*content=["']([^"']+)["']/i);
          const twitterDescMatch = html.match(/<meta[^>]*name=["']twitter:description["'][^>]*content=["']([^"']+)["']/i);
          metaData.description = (ogDescMatch?.[1] || twitterDescMatch?.[1] || descMatch?.[1] || '').trim();
          const keywordsMatch = html.match(/<meta[^>]*name=["']keywords["'][^>]*content=["']([^"']+)["']/i);
          if (keywordsMatch) metaData.keywords = keywordsMatch[1].trim();
          const authorMatch = html.match(/<meta[^>]*name=["']author["'][^>]*content=["']([^"']+)["']/i);
          const articleAuthorMatch = html.match(/<meta[^>]*property=["']article:author["'][^>]*content=["']([^"']+)["']/i);
          if (authorMatch || articleAuthorMatch) metaData.author = (articleAuthorMatch?.[1] || authorMatch?.[1] || '').trim();
          const langMatch = html.match(/<html[^>]*lang=["']([^"']+)["']/i);
          const ogLocaleMatch = html.match(/<meta[^>]*property=["']og:locale["'][^>]*content=["']([^"']+)["']/i);
          if (langMatch || ogLocaleMatch) metaData.lang = (langMatch?.[1] || ogLocaleMatch?.[1] || '').trim();
          const publisherMatch = html.match(/<meta[^>]*property=["']og:site_name["'][^>]*content=["']([^"']+)["']/i);
          if (publisherMatch) metaData.publisher = publisherMatch[1].trim();
          const ogTypeMatch = html.match(/<meta[^>]*property=["']og:type["'][^>]*content=["']([^"']+)["']/i);
          if (ogTypeMatch) metaData.type = ogTypeMatch[1].trim();
          const imageMatch = html.match(/<meta[^>]*property=["']og:image["'][^>]*content=["']([^"']+)["']/i);
          const twitterImageMatch = html.match(/<meta[^>]*name=["']twitter:image["'][^>]*content=["']([^"']+)["']/i);
          if (imageMatch || twitterImageMatch) metaData.image = (imageMatch?.[1] || twitterImageMatch?.[1] || '').trim();
          const imageAltMatch = html.match(/<meta[^>]*property=["']og:image:alt["'][^>]*content=["']([^"']+)["']/i);
          if (imageAltMatch) metaData.imageAlt = imageAltMatch[1].trim();
          const ogUrlMatch = html.match(/<meta[^>]*property=["']og:url["'][^>]*content=["']([^"']+)["']/i);
          const canonicalMatch = html.match(/<link[^>]*rel=["']canonical["'][^>]*href=["']([^"']+)["']/i);
          metaData.url = (ogUrlMatch?.[1] || canonicalMatch?.[1] || targetUrl).trim();
          const twitterCardMatch = html.match(/<meta[^>]*name=["']twitter:card["'][^>]*content=["']([^"']+)["']/i);
          if (twitterCardMatch) metaData.twitterCard = twitterCardMatch[1].trim();
          const twitterSiteMatch = html.match(/<meta[^>]*name=["']twitter:site["'][^>]*content=["']([^"']+)["']/i);
          if (twitterSiteMatch) metaData.twitterSite = twitterSiteMatch[1].trim();
          const twitterCreatorMatch = html.match(/<meta[^>]*name=["']twitter:creator["'][^>]*content=["']([^"']+)["']/i);
          if (twitterCreatorMatch) metaData.twitterCreator = twitterCreatorMatch[1].trim();
          const publishedMatch = html.match(/<meta[^>]*property=["']article:published_time["'][^>]*content=["']([^"']+)["']/i);
          const dateMatch = html.match(/<meta[^>]*name=["']date["'][^>]*content=["']([^"']+)["']/i);
          if (publishedMatch || dateMatch) metaData.date = (publishedMatch?.[1] || dateMatch?.[1] || '').trim();
          const modifiedMatch = html.match(/<meta[^>]*property=["']article:modified_time["'][^>]*content=["']([^"']+)["']/i);
          if (modifiedMatch) metaData.modifiedDate = modifiedMatch[1].trim();
          const sectionMatch = html.match(/<meta[^>]*property=["']article:section["'][^>]*content=["']([^"']+)["']/i);
          if (sectionMatch) metaData.category = sectionMatch[1].trim();
          const articleTagsMatches = html.match(/<meta[^>]*property=["']article:tag["'][^>]*content=["']([^"']+)["']/gi);
          if (articleTagsMatches) {
            metaData.tags = articleTagsMatches.map(tag => {
              const match = tag.match(/content=["']([^"']+)["']/i);
              return match ? match[1] : '';
            }).filter(Boolean).join(', ');
          }
          const faviconMatch = html.match(/<link[^>]*rel=["'](?:icon|shortcut icon)["'][^>]*href=["']([^"']+)["']/i);
          if (faviconMatch) {
            const faviconUrl = faviconMatch[1].trim();
            metaData.favicon = faviconUrl.startsWith('http') ? faviconUrl : `https://${domain.trim()}${faviconUrl.startsWith('/') ? '' : '/'}${faviconUrl}`;
          }
          const appleTouchMatch = html.match(/<link[^>]*rel=["']apple-touch-icon["'][^>]*href=["']([^"']+)["']/i);
          if (appleTouchMatch) {
            const appleUrl = appleTouchMatch[1].trim();
            metaData.logo = appleUrl.startsWith('http') ? appleUrl : `https://${domain.trim()}${appleUrl.startsWith('/') ? '' : '/'}${appleUrl}`;
          }
          const robotsMatch = html.match(/<meta[^>]*name=["']robots["'][^>]*content=["']([^"']+)["']/i);
          if (robotsMatch) metaData.robots = robotsMatch[1].trim();
          const viewportMatch = html.match(/<meta[^>]*name=["']viewport["'][^>]*content=["']([^"']+)["']/i);
          if (viewportMatch) metaData.viewport = viewportMatch[1].trim();
          const themeColorMatch = html.match(/<meta[^>]*name=["']theme-color["'][^>]*content=["']([^"']+)["']/i);
          if (themeColorMatch) metaData.themeColor = themeColorMatch[1].trim();
          const charsetMatch = html.match(/<meta[^>]*charset=["']?([^"'\s>]+)["']?/i);
          if (charsetMatch) metaData.charset = charsetMatch[1].trim();
          const generatorMatch = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
          if (generatorMatch) metaData.generator = generatorMatch[1].trim();
          const rssFeedMatch = html.match(/<link[^>]*type=["']application\/rss\+xml["'][^>]*href=["']([^"']+)["']/i);
          if (rssFeedMatch) {
            const rssUrl = rssFeedMatch[1].trim();
            metaData.rssFeed = rssUrl.startsWith('http') ? rssUrl : `https://${domain.trim()}${rssUrl.startsWith('/') ? '' : '/'}${rssUrl}`;
          }
          const atomFeedMatch = html.match(/<link[^>]*type=["']application\/atom\+xml["'][^>]*href=["']([^"']+)["']/i);
          if (atomFeedMatch) {
            const atomUrl = atomFeedMatch[1].trim();
            metaData.atomFeed = atomUrl.startsWith('http') ? atomUrl : `https://${domain.trim()}${atomUrl.startsWith('/') ? '' : '/'}${atomUrl}`;
          }
          // JSON-LD
          const jsonLdMatches = html.match(/<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi);
          if (jsonLdMatches) {
            try {
              const jsonLdData = jsonLdMatches.map(script => {
                const content = script.match(/<script[^>]*type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/i);
                if (content && content[1]) {
                  try { return JSON.parse(content[1]); } catch { return null; }
                }
                return null;
              }).filter(Boolean);
              if (jsonLdData.length > 0) {
                metaData.jsonLd = jsonLdData;
                const firstSchema = Array.isArray(jsonLdData[0]) ? jsonLdData[0][0] : jsonLdData[0];
                if (firstSchema) {
                  if (firstSchema['@type']) metaData.schemaType = firstSchema['@type'];
                  if (firstSchema.name && !metaData.title) metaData.title = firstSchema.name;
                  if (firstSchema.description && !metaData.description) metaData.description = firstSchema.description;
                }
              }
            } catch (e) { /* ignore */ }
          }
          const totalFields = 30;
          const filledFields = Object.keys(metaData).filter(key => key !== 'id' && key !== 'domain' && key !== 'timestamp' && key !== 'jsonLd' && metaData[key]).length;
          metaData.completenessScore = Math.round((filledFields / totalFields) * 100);
          onMetascraperResults(metaData);
        } catch (metaError: any) {
          const errorMessage = metaError.name === 'AbortError'
            ? 'Request timed out while fetching metadata (try again or website may be slow)'
            : metaError.message || 'Failed to fetch metadata';
          onMetascraperResults({ id: Date.now() + 1, domain: domain.trim(), timestamp: new Date().toLocaleString(), error: errorMessage });
        }
      })();
      
      // Kick off VirusTotal in background (non-blocking)
      void (async () => {
        try {
          const vtUrl = `/api/vt/domains/${encodeURIComponent(domain.trim())}`;
          const vtResponse = await fetch(vtUrl);
          if (vtResponse.ok) {
            const vtData = await vtResponse.json();
            const data = vtData.data?.attributes || {};
            const virusTotalResult = {
              id: Date.now() + 2,
              domain: domain.trim(),
              timestamp: new Date().toLocaleString(),
              
              // Security & Reputation
              reputation: data.reputation || 0,
              last_analysis_stats: data.last_analysis_stats || {},
              total_votes: data.total_votes || {},
              
              // Categories
              categories: data.categories || {},
              
              // Popularity
              popularity_ranks: data.popularity_ranks || {},
              
              // WHOIS data from VT
              whois: data.whois || null,
              whois_date: data.whois_date ? new Date(data.whois_date * 1000).toLocaleString() : null,
              
              // Creation & Last Update
              creation_date: data.creation_date ? new Date(data.creation_date * 1000).toLocaleString() : null,
              last_update_date: data.last_update_date ? new Date(data.last_update_date * 1000).toLocaleString() : null,
              last_modification_date: data.last_modification_date ? new Date(data.last_modification_date * 1000).toLocaleString() : null,
              last_analysis_date: data.last_analysis_date ? new Date(data.last_analysis_date * 1000).toLocaleString() : null,
              
              // DNS Records
              last_dns_records: data.last_dns_records || [],
              last_dns_records_date: data.last_dns_records_date ? new Date(data.last_dns_records_date * 1000).toLocaleString() : null,
              
              // SSL Certificate
              last_https_certificate: data.last_https_certificate || null,
              last_https_certificate_date: data.last_https_certificate_date ? new Date(data.last_https_certificate_date * 1000).toLocaleString() : null,
              
              // Tags & Threat Names
              tags: data.tags || [],
              
              // Registrar
              registrar: data.registrar || null,
              
              // Jarm fingerprint
              jarm: data.jarm || null,
              
              // Analysis results details
              last_analysis_results: data.last_analysis_results || {},
              
              // Calculated scores
              malicious_score: data.last_analysis_stats?.malicious || 0,
              suspicious_score: data.last_analysis_stats?.suspicious || 0,
              harmless_score: data.last_analysis_stats?.harmless || 0,
              undetected_score: data.last_analysis_stats?.undetected || 0,
              
              // Risk assessment
              risk_level: (() => {
                const malicious = data.last_analysis_stats?.malicious || 0;
                const suspicious = data.last_analysis_stats?.suspicious || 0;
                if (malicious > 5) return 'High';
                if (malicious > 0 || suspicious > 3) return 'Medium';
                if (suspicious > 0) return 'Low';
                return 'Clean';
              })()
            };
            
            onVirusTotalResults(virusTotalResult);
          } else {
            throw new Error(`VirusTotal API responded with status ${vtResponse.status}`);
          }
        } catch (vtError: any) {
          onVirusTotalResults({ id: Date.now() + 2, domain: domain.trim(), timestamp: new Date().toLocaleString(), error: vtError.message || 'Failed to fetch VirusTotal data.' });
        }
      })();
      setIsScanning(false);
      setDomain("");

      toast({
        title: "Scan Complete",
        description: `Successfully analyzed ${domain.trim()}`,
      });
    } catch (error: any) {
      setIsScanning(false);
      toast({
        title: "Scan Failed",
        description: error.message || "Something went wrong while fetching data.",
        variant: "destructive",
      });
    }
  };

  return (
    <Card className="h-fit border-0 shadow-xl bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg hover:shadow-2xl transition-all duration-500 hover:scale-[1.02]">
      <CardHeader className="bg-gradient-to-r from-red-600/10 to-blue-600/10 border-b border-red-200/50 dark:border-blue-800/50">
        <CardTitle className="flex items-center space-x-2">
          <div className="p-2 bg-gradient-to-r from-red-600 to-blue-600 rounded-lg">
            <Search className="h-5 w-5 text-white" />
          </div>
          <span className="bg-gradient-to-r from-red-600 to-blue-600 bg-clip-text text-transparent">Domain Analysis</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6 p-6">
        <div className="space-y-3">
          <Label htmlFor="domain" className="text-sm font-medium text-slate-700 dark:text-slate-300">Domain Name</Label>
          <Input
            id="domain"
            type="text"
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !isScanning && handleScan()}
            className="border-red-200 dark:border-blue-800 focus:border-red-500 dark:focus:border-blue-500 focus:ring-red-500/20 dark:focus:ring-blue-500/20 transition-all duration-300"
          />
        </div>

        <Button 
          onClick={handleScan} 
          disabled={isScanning}
          className="w-full bg-gradient-to-r from-red-600 to-blue-600 hover:from-red-700 hover:to-blue-700 text-white shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-105"
        >
          {isScanning ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <Search className="mr-2 h-4 w-4" />
              Analyze Domain
            </>
          )}
        </Button>

        <div className="text-xs text-slate-600 dark:text-slate-400 bg-gradient-to-r from-red-50 to-blue-50 dark:from-red-950/50 dark:to-blue-950/50 p-4 rounded-xl border border-red-200/50 dark:border-blue-800/50">
          <p className="font-semibold mb-2 bg-gradient-to-r from-red-600 to-blue-600 bg-clip-text text-transparent">Analysis includes:</p>
          <ul className="space-y-1">
            <li className="hover:text-red-600 dark:hover:text-blue-400 transition-colors duration-300">• WHOIS registration data</li>
            <li className="hover:text-blue-600 dark:hover:text-red-400 transition-colors duration-300">• DNS record information</li>
            <li className="hover:text-red-600 dark:hover:text-blue-400 transition-colors duration-300">• IP geolocation & ASN</li>
            <li className="hover:text-blue-600 dark:hover:text-red-400 transition-colors duration-300">• Security reputation check</li>
            <li className="hover:text-red-600 dark:hover:text-blue-400 transition-colors duration-300">• VPN/Proxy detection</li>
            <li className="hover:text-blue-600 dark:hover:text-red-400 transition-colors duration-300">• VirusTotal security analysis</li>
            <li className="hover:text-red-600 dark:hover:text-blue-400 transition-colors duration-300">• Webpage metadata extraction</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
};

export default DomainAnalysisCard;
