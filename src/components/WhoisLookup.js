// src/components/WhoisLookup.js (or anywhere you want)

const domain = "google.com";

// API URL using .env variable from Vite
const apiUrl = `${import.meta.env.VITE_API_BASE}/whois/?domain=${domain}`;

fetch(apiUrl)
  .then((res) => {
    if (!res.ok) throw new Error(`HTTP error! status: ${res.status}`);
    return res.json();
  })
  .then((data) => {
    console.log("WHOIS Data:", data);
    // You can now display this in your component
  })
  .catch((err) => {
    console.error("API error:", err);
  });
