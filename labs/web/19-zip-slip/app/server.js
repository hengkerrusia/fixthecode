#!/usr/bin/env node
const http = require('http');
const fs = require('fs');
const path = require('path');
const { Readable } = require('stream');
const unzipper = require('unzipper');

const PORT = parseInt(process.env.PORT || '8080', 10);
const UPLOADS = '/data/uploads';
const MAX_BODY = 5 * 1024 * 1024;

fs.mkdirSync(UPLOADS, { recursive: true });

function send(res, code, body, type) {
  const data = Buffer.from(body, 'utf8');
  res.writeHead(code, {
    'Content-Type': type || 'text/plain; charset=utf-8',
    'Content-Length': data.length,
  });
  res.end(data);
}

function extractZip(buffer, targetDir) {
  return new Promise((resolve, reject) => {
    const jobs = [];
    let count = 0;
    Readable.from([buffer])
      .pipe(unzipper.Parse())
      .on('entry', (entry) => {
        if (entry.type === 'Directory') {
          entry.autodrain();
          return;
        }
        const outPath = path.join(targetDir, entry.path);
        fs.mkdirSync(path.dirname(outPath), { recursive: true });
        count += 1;
        jobs.push(
          new Promise((res, rej) => {
            const ws = fs.createWriteStream(outPath);
            ws.on('finish', res);
            ws.on('error', rej);
            entry.on('error', rej);
            entry.pipe(ws);
          })
        );
      })
      .on('close', () => {
        Promise.all(jobs).then(() => resolve(count), reject);
      })
      .on('error', reject);
  });
}

const FORM_HTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>arsipku — upload &amp; extract</title></head>
<body>
<h1>arsipku</h1>
<p>Unggah arsip <code>.zip</code>: isinya diekstrak ke direktori unggahan.</p>
<input type="file" id="f" accept=".zip">
<button id="b">Unggah</button>
<pre id="o"></pre>
<script>
document.getElementById('b').onclick = async () => {
  const f = document.getElementById('f').files[0];
  if (!f) return;
  const buf = await f.arrayBuffer();
  const r = await fetch('/upload', { method: 'POST', body: buf,
    headers: { 'Content-Type': 'application/zip' } });
  document.getElementById('o').textContent = r.status + ' ' + await r.text();
};
</script>
</body></html>
`;

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && (req.url === '/' || req.url.startsWith('/?'))) {
    send(res, 200, FORM_HTML, 'text/html; charset=utf-8');
    return;
  }

  if (req.method === 'POST' && req.url === '/upload') {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      chunks.push(c);
    });
    req.on('end', async () => {
      if (size === 0 || size > MAX_BODY) {
        send(res, 413, 'body kosong atau melebihi batas\n');
        return;
      }
      try {
        const n = await extractZip(Buffer.concat(chunks), UPLOADS);
        send(res, 200, 'ok: extracted ' + n + ' files\n');
      } catch (e) {
        send(res, 400, 'bad archive\n');
      }
    });
    req.on('error', () => send(res, 400, 'bad request\n'));
    return;
  }

  if (req.method === 'GET' && req.url.startsWith('/files/')) {
    const raw = req.url.slice('/files/'.length).split('?')[0];
    const name = path.basename(decodeURIComponent(raw));
    if (!name) {
      send(res, 404, 'not found\n');
      return;
    }
    fs.readFile(path.join(UPLOADS, name), (err, data) => {
      if (err) {
        send(res, 404, 'not found\n');
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': data.length,
      });
      res.end(data);
    });
    return;
  }

  send(res, 404, 'not found\n');
});

server.listen(PORT, () => {
  console.log('arsipku listening on ' + PORT);
});
