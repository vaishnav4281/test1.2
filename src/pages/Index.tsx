
import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Shield, Search, Database, FileText, Globe, Activity, Moon, Sun } from "lucide-react";
import DomainAnalysisCard from "@/components/DomainAnalysisCard";
import BulkScannerCard from "@/components/BulkScannerCard";
import ResultsPanel from "@/components/ResultsPanel";

const Index = () => {
  const [activeTab, setActiveTab] = useState<'single' | 'bulk'>('single');
  const [results, setResults] = useState([]);
  const [isDarkMode, setIsDarkMode] = useState(false);

  useEffect(() => {
    // Check for saved theme preference or default to light mode
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
      setIsDarkMode(true);
      document.documentElement.classList.add('dark');
    }
  }, []);

  const toggleDarkMode = () => {
    setIsDarkMode(!isDarkMode);
    if (!isDarkMode) {
      document.documentElement.classList.add('dark');
      localStorage.setItem('theme', 'dark');
    } else {
      document.documentElement.classList.remove('dark');
      localStorage.setItem('theme', 'light');
    }
  };

  // Create callback functions that properly handle state updates
  const handleSingleResults = (newResult: any) => {
    setResults(prev => [newResult, ...prev]);
  };

  const handleBulkResults = (newResult: any) => {
    setResults(prev => [newResult, ...prev]);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-red-50 dark:from-slate-900 dark:via-blue-950 dark:to-red-950 transition-all duration-700">
      {/* Header */}
      <header className="bg-white/90 dark:bg-slate-900/90 backdrop-blur-lg border-b border-blue-200 dark:border-red-800 sticky top-0 z-50 transition-all duration-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3 animate-fade-in">
              <div className="bg-gradient-to-r from-red-600 to-blue-600 p-2 sm:p-3 rounded-xl shadow-lg hover:scale-110 transition-transform duration-300">
                <Shield className="h-5 w-5 sm:h-6 sm:w-6 text-white" />
              </div>
              <div>
                <h1 className="text-lg sm:text-2xl font-bold bg-gradient-to-r from-red-600 to-blue-600 bg-clip-text text-transparent">
                  Domain Intelligence Toolkit
                </h1>
                <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-400">
                  OSINT • DNS • WHOIS • Security Analysis
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-2 sm:space-x-4">
              <Button
                onClick={toggleDarkMode}
                variant="outline"
                size="icon"
                className="hover:scale-110 transition-transform duration-300 border-blue-300 hover:border-red-400"
              >
                {isDarkMode ? (
                  <Sun className="h-4 w-4 text-yellow-500" />
                ) : (
                  <Moon className="h-4 w-4 text-blue-600" />
                )}
              </Button>
              <div className="hidden sm:block text-sm text-slate-600 dark:text-slate-400">
                Built by <span className="font-semibold bg-gradient-to-r from-red-600 to-blue-600 bg-clip-text text-transparent">Vaishnav K</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 sm:py-8">
        {/* Features Overview */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 sm:gap-4 mb-6 sm:mb-8">
          {[
            { icon: Search, label: "WHOIS Lookup", color: "text-red-600", bg: "bg-red-100 dark:bg-red-950" },
            { icon: Globe, label: "DNS Records", color: "text-blue-600", bg: "bg-blue-100 dark:bg-blue-950" },
            { icon: Database, label: "IP Geolocation", color: "text-red-500", bg: "bg-red-100 dark:bg-red-950" },
            { icon: Shield, label: "Abuse Detection", color: "text-blue-500", bg: "bg-blue-100 dark:bg-blue-950" },
            { icon: Activity, label: "VPN Detection", color: "text-red-600", bg: "bg-red-100 dark:bg-red-950" },
            { icon: FileText, label: "CSV Reports", color: "text-blue-600", bg: "bg-blue-100 dark:bg-blue-950" },
          ].map((feature, index) => (
            <Card key={index} className="text-center hover:shadow-xl transition-all duration-500 hover:scale-105 border-transparent hover:border-gradient-to-r hover:from-red-200 hover:to-blue-200 group animate-fade-in" style={{ animationDelay: `${index * 100}ms` }}>
              <CardContent className="p-2 sm:p-4">
                <div className={`h-8 w-8 sm:h-12 sm:w-12 mx-auto mb-2 sm:mb-3 rounded-xl ${feature.bg} flex items-center justify-center group-hover:scale-110 transition-transform duration-300`}>
                  <feature.icon className={`h-4 w-4 sm:h-6 sm:w-6 ${feature.color}`} />
                </div>
                <p className="text-xs font-medium text-slate-700 dark:text-slate-300">
                  {feature.label}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Tab Navigation */}
        <div className="flex space-x-1 mb-4 sm:mb-6 bg-gradient-to-r from-red-100 to-blue-100 dark:from-red-950 dark:to-blue-950 p-1 rounded-xl w-fit mx-auto animate-fade-in">
          <Button
            variant={activeTab === 'single' ? 'default' : 'ghost'}
            size="sm"
            onClick={() => setActiveTab('single')}
            className={`rounded-lg transition-all duration-300 text-xs sm:text-sm ${activeTab === 'single' 
              ? 'bg-gradient-to-r from-red-600 to-blue-600 text-white shadow-lg hover:scale-105' 
              : 'hover:bg-white/50 dark:hover:bg-slate-800/50'
            }`}
          >
            <Search className="h-3 w-3 sm:h-4 sm:w-4 mr-1 sm:mr-2" />
            Single Domain
          </Button>
          <Button
            variant={activeTab === 'bulk' ? 'default' : 'ghost'}
            size="sm"
            onClick={() => setActiveTab('bulk')}
            className={`rounded-lg transition-all duration-300 text-xs sm:text-sm ${activeTab === 'bulk' 
              ? 'bg-gradient-to-r from-red-600 to-blue-600 text-white shadow-lg hover:scale-105' 
              : 'hover:bg-white/50 dark:hover:bg-slate-800/50'
            }`}
          >
            <Database className="h-3 w-3 sm:h-4 sm:w-4 mr-1 sm:mr-2" />
            Bulk Scanner
          </Button>
        </div>

        {/* Main Content Area */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 sm:gap-6">
          {/* Scanner Panel */}
          <div className="xl:col-span-1 animate-slide-in-right">
            {activeTab === 'single' ? (
              <DomainAnalysisCard onResults={handleSingleResults} />
            ) : (
              <BulkScannerCard onResults={handleBulkResults} />
            )}
          </div>

          {/* Results Panel */}
          <div className="xl:col-span-2 animate-slide-in-right" style={{ animationDelay: '200ms' }}>
            <ResultsPanel results={results} />
          </div>
        </div>
      </main>
    </div>
  );
};

export default Index;
