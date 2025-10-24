export const config = { runtime: 'edge' };

export default async function handler(req: Request): Promise<Response> {
  try {
    const { searchParams } = new URL(req.url);
    const domain = searchParams.get('domain');
    if (!domain) {
      return new Response(JSON.stringify({ error: 'Missing domain query param' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const apiKey = process.env.VT_API_KEY;
    if (!apiKey) {
      return new Response(JSON.stringify({ error: 'Server misconfigured: VT_API_KEY not set' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    const vtRes = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
      headers: {
        'x-apikey': apiKey,
      },
      // Avoid caching to get fresh analysis
      cache: 'no-store',
    });

    const text = await vtRes.text();
    return new Response(text, {
      status: vtRes.status,
      headers: {
        'Content-Type': vtRes.headers.get('Content-Type') || 'application/json',
      },
    });
  } catch (err: any) {
    return new Response(JSON.stringify({ error: err?.message || 'Unexpected error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
    });
  }
}
