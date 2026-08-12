// Every URL the new tags advertise must actually resolve, and resolve as the right KIND
// of thing. A 200 alone proves nothing: a server with a catch-all would answer 200 with
// index.html for robots.txt, and a grep for "User-agent" against that body is the only
// thing that tells the two apart.
import fs from 'node:fs';

const BASE = process.argv[2] || 'http://127.0.0.1:3095';
let bad = 0;
// Two details, not one. A single string has to describe the pass and the failure at once,
// and it ends up printing the failure sentence next to an OK, which is how a green run
// reads as a broken one.
const check = (name, ok, detail, okDetail) => {
  const note = ok ? (okDetail ?? detail) : detail;
  process.stdout.write(`${ok ? 'OK  ' : 'BAD '} ${name}${note ? `  <- ${note}` : ''}\n`);
  if (!ok) bad += 1;
};

// A request that never reached a server is NOT a page that lacks a tag. Without this the
// whole run answers "no robots.txt, no card, no canonical" against a host that was simply
// down, and it did: pointed at a port nothing was listening on, every fetch rejected and
// this script still exited 0. Unreachable is its own outcome and it is fatal, because a
// deploy check that cannot see the deploy has not checked it.
async function get(path) {
  let res;
  try {
    res = await fetch(BASE + path, { signal: AbortSignal.timeout(5000) });
  } catch (err) {
    process.stdout.write(`BAD  could not reach ${BASE}${path}: ${err.message}\n`);
    process.stdout.write('     Nothing below was measured. This is not a missing tag, it is a missing server.\n');
    process.exit(2);
  }
  return { status: res.status, type: res.headers.get('content-type') || '', corp: res.headers.get('cross-origin-resource-policy'), body: Buffer.from(await res.arrayBuffer()) };
}

// The pages, taken FROM the files rather than retyped, so this cannot drift from them.
const pages = ['index.html', 'app.html', 'faq.html', 'privacy.html', 'terms.html', 'acceptable-use.html'];
const urls = pages.map((p) => {
  const t = fs.readFileSync(`public/${p}`, 'utf8');
  return { page: p, url: t.match(/rel="canonical" href="([^"]+)"/)[1] };
});
check('every page states a canonical URL, so there is something to test', urls.length === 6, `${urls.length} found`);

for (const { page, url } of urls) {
  const path = new URL(url).pathname;
  const r = await get(path);
  check(`the URL ${page} advertises actually serves a page: ${path}`,
    r.status === 200 && r.type.startsWith('text/html') && r.body.includes('<html'),
    `status ${r.status}, type ${r.type}, ${r.body.length} bytes`);
}

const card = await get('/og-card.png');
check('og-card.png is served as a PNG, not an octet-stream',
  card.status === 200 && card.type === 'image/png' && card.body.subarray(1, 4).toString() === 'PNG',
  `status ${card.status}, type ${card.type}, magic ${JSON.stringify(card.body.subarray(1, 4).toString())}`);
check('and it is readable by another origin, which is the only reason it exists',
  card.corp === 'cross-origin', `cross-origin-resource-policy: ${card.corp}`);

const robots = await get('/robots.txt');
check('robots.txt is text/plain and is really robots.txt, not a page',
  robots.status === 200 && robots.type.startsWith('text/plain') && robots.body.toString().includes('User-agent:'),
  `status ${robots.status}, type ${robots.type}`);
// Gated on the file being there. Read as `!/Disallow: \/app/` alone this passed against a
// 404 body, which is to say it reported green on a site with no robots.txt at all: the one
// state where the question it asks has no answer.
const robotsServed = robots.status === 200 && robots.body.toString().includes('User-agent:');
check('robots.txt does NOT disallow /app, which is what a gate link is',
  robotsServed && !/^\s*Disallow:\s*\/app/mi.test(robots.body.toString()),
  robotsServed
    ? 'a Disallow: /app line is present, so a pasted gate link will not render a card'
    : 'there is no robots.txt to read, so this says nothing either way',
  'no Disallow: /app line');

const sitemap = await get('/sitemap.xml');
check('sitemap.xml is XML and parses as a urlset',
  sitemap.status === 200 && sitemap.type.includes('xml') && sitemap.body.toString().includes('<urlset'),
  `status ${sitemap.status}, type ${sitemap.type}`);

// Every URL the sitemap lists must serve, or it is a list of 404s. Counted first: a
// sitemap that parses but lists nothing would run this loop zero times, emit not one
// check, and leave the run looking exactly like a run where every entry resolved.
const locs = [...sitemap.body.toString().matchAll(/<loc>([^<]+)<\/loc>/g)];
check('the sitemap actually lists URLs, so the per-entry checks below ran',
  locs.length >= 5, `${locs.length} <loc> entries`);
for (const loc of locs) {
  const path = new URL(loc[1]).pathname;
  const r = await get(path);
  check(`sitemap entry resolves: ${path}`, r.status === 200 && r.type.startsWith('text/html'), `status ${r.status}, type ${r.type}`);
}

// The control. If the server answered everything with a page, every check above would
// pass while proving nothing, so a path that must NOT exist has to actually 404.
const ghost = await get('/definitely-not-a-real-path.txt');
check('CONTROL: an absent path 404s, so a 200 above means the file is really there',
  ghost.status === 404,
  `a missing path answered ${ghost.status}, so this server has a catch-all and every check above is meaningless`,
  'a missing path 404s');

process.stdout.write(bad ? `\n${bad} failed\n` : '\nall good\n');
process.exit(bad ? 1 : 0);
