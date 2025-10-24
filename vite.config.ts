import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";
import { componentTagger } from "lovable-tagger";

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const vtKey = env.VITE_VIRUSTOTAL_API_KEY;

  return {
    server: {
      host: "::",
      port: 8080,
      proxy: {
        '/api/whois': {
          target: 'https://whois-aoi.onrender.com',
          changeOrigin: true,
          rewrite: (p) => p.replace(/^\/api\/whois/, '/whois'),
        },
        // Dev proxy for VirusTotal to avoid CORS and inject API key server-side
        '/api/vt': {
          target: 'https://www.virustotal.com',
          changeOrigin: true,
          rewrite: (p) => p.replace(/^\/api\/vt/, '/api/v3'),
          configure: (proxy) => {
            proxy.on('proxyReq', (proxyReq) => {
              if (vtKey) {
                proxyReq.setHeader('x-apikey', vtKey);
              }
            });
          },
        },
      },
    },
    plugins: [
      react(),
      mode === 'development' && componentTagger(),
    ].filter(Boolean),
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "./src"),
      },
    },
  };
});
