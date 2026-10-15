import fs from 'fs';

async function inspect() {
  const url = "https://aurome.bd/advisor/";
  console.log("Fetching", url);
  const res = await fetch(url, {
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    }
  });

  const html = await res.text();
  fs.writeFileSync("./advisor.html", html);
  console.log("Saved ./advisor.html, bytes:", html.length);

  // Parse scripts
  const scriptRegex = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let match;
  const externalScripts = [];
  const inlineScripts = [];

  while ((match = scriptRegex.exec(html)) !== null) {
    const attrs = match[1];
    const content = match[2];
    const srcMatch = attrs.match(/src=["']([^"']+)["']/i);
    if (srcMatch) {
      externalScripts.push(srcMatch[1]);
    } else if (content.trim()) {
      inlineScripts.push(content.trim());
    }
  }

  console.log(`\nExternal scripts (${externalScripts.length}):`);
  for (const s of externalScripts) {
    if (/advisor|chat|bot|ai|bundle|app|aurome|custom|rest|vue|react/i.test(s)) {
      console.log("  [MATCH]", s);
    } else {
      console.log("         ", s);
    }
  }

  console.log(`\nInline scripts (${inlineScripts.length}) checking for keyword matches:`);
  for (let i = 0; i < inlineScripts.length; i++) {
    const c = inlineScripts[i];
    if (/advisor|chat|wp-json|endpoint|aurome|rest|nonce/i.test(c)) {
      console.log(`\n--- Match ${i} (length: ${c.length}) ---`);
      console.log(c.slice(0, 600));
    }
  }

  const divMatches = html.match(/<(div|section|aside|main)[^>]+(id|class)=["'][^"']*(advisor|chat|bot|ai|perfume-finder)[^"']*["'][^>]*>/gi);
  console.log("\nMatching HTML elements:", divMatches);
}

inspect().catch(console.error);
