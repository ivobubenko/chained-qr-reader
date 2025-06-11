export function basicUrlChecks(url) {
  if (!/^https?:/i.test(url)) return "UNSAFE_SCHEME";
  if (/^https?:\/\/(?:\d{1,3}\.){3}\d{1,3}/.test(url) || /localhost/i.test(url))
    return "POTENTIAL_MALWARE_HOST";

  const u = new URL(url);
  const unicodeHost = u.hostname;
  if (
    /\p{Script=Cyrl}/u.test(unicodeHost) &&
    /google|microsoft|bank|apple/i.test(unicodeHost)
  )
    return "HOMOGRAPH_SPOOF";

  return "SAFE"; 
}

async function isUrlMalicious(url, apiKey){
    const body = {
      client: { clientId: 'secure-qr', clientVersion: '1.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }]
      }
    };
  
    const r = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
    );
    const { matches } = await r.json();
    return Array.isArray(matches) && matches.length > 0;
  }
  
