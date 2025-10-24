
import React, { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Database, Upload, Loader2, FileText } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface BulkScannerCardProps {
  onResults: (result: any) => void;
  onMetascraperResults?: (result: any) => void;
  onVirusTotalResults?: (result: any) => void;
}

const BulkScannerCard = ({ onResults, onMetascraperResults, onVirusTotalResults }: BulkScannerCardProps) => {
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
  const [domains, setDomains] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const { toast } = useToast();

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setDomains(content);
      };
      reader.readAsText(file);
    }
  };

  const handleBulkScan = async () => {
    const domainList = domains.trim().split('\n').filter(d => d.trim());
    
    if (domainList.length === 0) {
      toast({
        title: "No Domains Found",
        description: "Please enter domains or upload a file",
        variant: "destructive",
      });
      return;
    }

    setIsScanning(true);
    setScanProgress(0);

    for (let i = 0; i < domainList.length; i++) {
      const domain = domainList[i].trim();

      try {
        const whoisUrl = `/api/whois/?domain=${encodeURIComponent(domain)}`;
        let response: Response;
        // Simple retry for WHOIS fetch
        for (let attempt = 0; attempt < 2; attempt++) {
          try {
            response = await fetchWithTimeout(whoisUrl);
            break;
          } catch (err: any) {
            if (err.name === 'AbortError') {
              if (attempt === 1) throw new Error('Request timed out.');
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
          id: Date.now() + i,
          domain: data.domain || domain,
          created: data.creation_date || "-",
          expires: data.expiration_date || "-",
          domain_age: data.domain_age || "-",
          registrar: data.registrar || "-",
          name_servers: data.name_servers || [],
          abuse_score: 0,
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

        // Enrich ISP if missing
        if (result.ip_address !== "-" && result.isp === "-") {
          try {
            const ipInfoRes = await fetch(`https://ipapi.co/${result.ip_address}/json/`);
            if (ipInfoRes.ok) {
              const ipInfo = await ipInfoRes.json();
              result.isp = ipInfo.org || ipInfo.asn_org || "-";
            }
          } catch {}
          if (result.isp === "-") {
            try {
              const whoRes = await fetch(`https://ipwho.is/${result.ip_address}`);
              if (whoRes.ok) {
                const whoData = await whoRes.json();
                result.isp = whoData.connection?.isp || whoData.org || "-";
              }
            } catch {}
          }
        }

        // Fetch abuse score if API key is present (to mirror single scan)
        const abuseKey = import.meta.env.VITE_ABUSEIPDB_API_KEY;
        if (abuseKey && result.ip_address !== "-") {
          try {
            const abuseRes = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${result.ip_address}&maxAgeInDays=365`, {
              headers: {
                Key: abuseKey,
                Accept: 'application/json',
              },
            });
            if (abuseRes.ok) {
              const abuseData = await abuseRes.json();
              result.abuse_score = abuseData.data?.abuseConfidenceScore ?? result.abuse_score;
            }
          } catch {}
        }

        onResults(result);

        // Metascraper (optional)
        if (onMetascraperResults) {
          try {
            const targetUrl = `https://${domain}`;
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
            const metaData: any = {
              id: Date.now() + i + 1,
              domain: domain,
              timestamp: new Date().toLocaleString()
            };
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
              metaData.favicon = faviconUrl.startsWith('http') ? faviconUrl : `https://${domain}${faviconUrl.startsWith('/') ? '' : '/'}${faviconUrl}`;
            }
            const appleTouchMatch = html.match(/<link[^>]*rel=["']apple-touch-icon["'][^>]*href=["']([^"']+)["']/i);
            if (appleTouchMatch) {
              const appleUrl = appleTouchMatch[1].trim();
              metaData.logo = appleUrl.startsWith('http') ? appleUrl : `https://${domain}${appleUrl.startsWith('/') ? '' : '/'}${appleUrl}`;
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
              metaData.rssFeed = rssUrl.startsWith('http') ? rssUrl : `https://${domain}${rssUrl.startsWith('/') ? '' : '/'}${rssUrl}`;
            }
            const atomFeedMatch = html.match(/<link[^>]*type=["']application\/atom\+xml["'][^>]*href=["']([^"']+)["']/i);
            if (atomFeedMatch) {
              const atomUrl = atomFeedMatch[1].trim();
              metaData.atomFeed = atomUrl.startsWith('http') ? atomUrl : `https://${domain}${atomUrl.startsWith('/') ? '' : '/'}${atomUrl}`;
            }
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
              } catch (e) { /* ignore parse errors */ }
            }
            const totalFields = 30;
            const filledFields = Object.keys(metaData).filter(key => key !== 'id' && key !== 'domain' && key !== 'timestamp' && key !== 'jsonLd' && metaData[key]).length;
            metaData.completenessScore = Math.round((filledFields / totalFields) * 100);
            onMetascraperResults(metaData);
          } catch (metaError: any) {
            onMetascraperResults({
              id: Date.now() + i + 1,
              domain: domain,
              timestamp: new Date().toLocaleString(),
              error: metaError?.message || 'Failed to fetch metadata'
            });
          }
        }
        // VirusTotal via proxy (dev: Vite proxy, prod: Vercel function)
        if (onVirusTotalResults) {
          try {
            const vtUrl = `/api/vt/domains/${encodeURIComponent(domain)}`;
            const vtResponse = await fetchWithTimeout(vtUrl, 15000);
            if (vtResponse.ok) {
              const vtData = await vtResponse.json();
              const data = vtData.data?.attributes || {};
              const virusTotalResult = {
                id: Date.now() + i + 2,
                domain: domain,
                timestamp: new Date().toLocaleString(),
                reputation: data.reputation || 0,
                last_analysis_stats: data.last_analysis_stats || {},
                total_votes: data.total_votes || {},
                categories: data.categories || {},
                popularity_ranks: data.popularity_ranks || {},
                whois: data.whois || null,
                whois_date: data.whois_date ? new Date(data.whois_date * 1000).toLocaleString() : null,
                creation_date: data.creation_date ? new Date(data.creation_date * 1000).toLocaleString() : null,
                last_update_date: data.last_update_date ? new Date(data.last_update_date * 1000).toLocaleString() : null,
                last_modification_date: data.last_modification_date ? new Date(data.last_modification_date * 1000).toLocaleString() : null,
                last_analysis_date: data.last_analysis_date ? new Date(data.last_analysis_date * 1000).toLocaleString() : null,
                last_dns_records: data.last_dns_records || [],
                last_dns_records_date: data.last_dns_records_date ? new Date(data.last_dns_records_date * 1000).toLocaleString() : null,
                last_https_certificate: data.last_https_certificate || null,
                last_https_certificate_date: data.last_https_certificate_date ? new Date(data.last_https_certificate_date * 1000).toLocaleString() : null,
                tags: data.tags || [],
                registrar: data.registrar || null,
                jarm: data.jarm || null,
                last_analysis_results: data.last_analysis_results || {},
                malicious_score: data.last_analysis_stats?.malicious || 0,
                suspicious_score: data.last_analysis_stats?.suspicious || 0,
                harmless_score: data.last_analysis_stats?.harmless || 0,
                undetected_score: data.last_analysis_stats?.undetected || 0,
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
            onVirusTotalResults({
              id: Date.now() + i + 2,
              domain: domain,
              timestamp: new Date().toLocaleString(),
              error: vtError.message || 'Failed to fetch VirusTotal data.'
            });
          }
        }
        // Removed artificial throttling to speed up bulk scanning
      } catch (error: any) {
        toast({
          title: `Scan failed for ${domain}`,
          description: error.message || "Unknown error",
          variant: "destructive",
        });
      }

      setScanProgress(((i + 1) / domainList.length) * 100);
    }

    setIsScanning(false);
    toast({
      title: "Bulk Scan Complete",
      description: `Successfully scanned ${domainList.length} domains`,
    });

  };

  return (
    <Card className="h-fit border-0 shadow-xl bg-white/80 dark:bg-slate-900/80 backdrop-blur-lg hover:shadow-2xl transition-all duration-500 hover:scale-[1.02]">
      <CardHeader className="bg-gradient-to-r from-blue-600/10 to-red-600/10 border-b border-blue-200/50 dark:border-red-800/50">
        <CardTitle className="flex items-center space-x-2">
          <div className="p-2 bg-gradient-to-r from-blue-600 to-red-600 rounded-lg">
            <Database className="h-5 w-5 text-white" />
          </div>
          <span className="bg-gradient-to-r from-blue-600 to-red-600 bg-clip-text text-transparent">Bulk Domain Scanner</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6 p-6">
        <div className="space-y-3">
          <Label htmlFor="file-upload" className="text-sm font-medium text-slate-700 dark:text-slate-300">Upload Domain List (.txt)</Label>
          <div className="flex items-center space-x-2">
            <Button variant="outline" className="w-full border-blue-200 dark:border-red-800 hover:bg-gradient-to-r hover:from-blue-50 hover:to-red-50 dark:hover:from-blue-950/50 dark:hover:to-red-950/50 transition-all duration-300" asChild>
              <label htmlFor="file-upload" className="cursor-pointer">
                <Upload className="mr-2 h-4 w-4" />
                Choose File
              </label>
            </Button>
            <input
              id="file-upload"
              type="file"
              accept=".txt"
              onChange={handleFileUpload}
              className="hidden"
            />
          </div>
        </div>

        <div className="space-y-3">
          <Label htmlFor="domains-text" className="text-sm font-medium text-slate-700 dark:text-slate-300">Or paste domains (one per line)</Label>
          <textarea
            id="domains-text"
            className="w-full h-32 px-3 py-2 text-sm border border-blue-200 dark:border-red-800 bg-background rounded-lg resize-none focus:outline-none focus:ring-2 focus:ring-blue-500/20 dark:focus:ring-red-500/20 focus:border-blue-500 dark:focus:border-red-500 transition-all duration-300"
            placeholder={`google.com\ngithub.com\nexample.com`}
            value={domains}
            onChange={(e) => setDomains(e.target.value)}
          />
        </div>

        {isScanning && (
          <div className="space-y-3">
            <div className="flex justify-between text-sm font-medium">
              <span className="bg-gradient-to-r from-blue-600 to-red-600 bg-clip-text text-transparent">Scanning progress...</span>
              <span className="bg-gradient-to-r from-red-600 to-blue-600 bg-clip-text text-transparent">{Math.round(scanProgress)}%</span>
            </div>
            <div className="w-full bg-slate-200 dark:bg-slate-700 rounded-full h-3 overflow-hidden">
              <div 
                className="bg-gradient-to-r from-blue-600 to-red-600 h-3 rounded-full transition-all duration-500 shadow-lg"
                style={{ width: `${scanProgress}%` }}
              />
            </div>
          </div>
        )}

        <Button 
          onClick={handleBulkScan} 
          disabled={isScanning}
          className="w-full bg-gradient-to-r from-blue-600 to-red-600 hover:from-blue-700 hover:to-red-700 text-white shadow-lg hover:shadow-xl transition-all duration-300 hover:scale-105"
        >
          {isScanning ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Scanning ({Math.round(scanProgress)}%)
            </>
          ) : (
            <>
              <Database className="mr-2 h-4 w-4" />
              Start Bulk Scan
            </>
          )}
        </Button>

        <div className="text-xs text-slate-600 dark:text-slate-400 bg-gradient-to-r from-blue-50 to-red-50 dark:from-blue-950/50 dark:to-red-950/50 p-4 rounded-xl border border-blue-200/50 dark:border-red-800/50">
          <p className="font-semibold mb-2 bg-gradient-to-r from-blue-600 to-red-600 bg-clip-text text-transparent">Bulk scan features:</p>
          <ul className="space-y-1">
            <li className="hover:text-blue-600 dark:hover:text-red-400 transition-colors duration-300">• Bulk Scanning via Text Imports</li>
            <li className="hover:text-red-600 dark:hover:text-blue-400 transition-colors duration-300">• Real-time progress tracking</li>
            <li className="hover:text-blue-600 dark:hover:text-red-400 transition-colors duration-300">• Failed lookup logging</li>
            <li className="hover:text-red-600 dark:hover:text-blue-400 transition-colors duration-300">• CSV export with domain age</li>
            <li className="hover:text-blue-600 dark:hover:text-red-400 transition-colors duration-300">• Comprehensive reporting</li>
          </ul>
        </div>
      </CardContent>
    </Card>
  );
};

export default BulkScannerCard;
