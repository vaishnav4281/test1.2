
import React, { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Database, Upload, Loader2, FileText } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface BulkScannerCardProps {
  onResults: (result: any) => void;
}

const BulkScannerCard = ({ onResults }: BulkScannerCardProps) => {
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
        const API_BASE = (() => {
          const base = import.meta.env.VITE_API_BASE;
          return base && /^https?:\/\//i.test(base) ? base : "https://whois-aoi.onrender.com";
        })();
        let response: Response;
        try {
          response = await fetchWithTimeout(`${API_BASE}/whois/?domain=${encodeURIComponent(domain)}`);
        } catch (err: any) {
          if (err.name === 'AbortError') {
            throw new Error('Request timed out.');
          }
          throw err;
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

        onResults(result);
      } catch (error: any) {
        toast({
          title: `Scan failed for ${domain}`,
          description: error.message || "Unknown error",
          variant: "destructive",
        });
      }

      setScanProgress(((i + 1) / domainList.length) * 100);

      // Optional small delay between requests to avoid overwhelming the API
      await new Promise((r) => setTimeout(r, 300));
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
            <li className="hover:text-blue-600 dark:hover:text-red-400 transition-colors duration-300">• Process up to 1000 domains</li>
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
