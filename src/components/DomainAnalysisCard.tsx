
import React, { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Search, Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface DomainAnalysisCardProps {
  onResults: (result: any) => void;
}

const DomainAnalysisCard = ({ onResults }: DomainAnalysisCardProps) => {
  const [domain, setDomain] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const { toast } = useToast();

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
      const response = await fetch(`/api/whois/?domain=${encodeURIComponent(domain.trim())}`);
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

      // Enrich with ISP info and abuse score if possible
      if (result.ip_address !== "-" && result.isp === "-") {
        try {
          const ipInfoRes = await fetch(`https://ipapi.co/${result.ip_address}/json/`);
          if (ipInfoRes.ok) {
            const ipInfo = await ipInfoRes.json();
            result.isp = ipInfo.org || ipInfo.asn_org || "-";
          }
        } catch {}

        // Fallback to ipwho.is if still not populated
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

      // Fetch abuse score
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
          </ul>
        </div>
      </CardContent>
    </Card>
  );
};

export default DomainAnalysisCard;
