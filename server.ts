import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';
import { createInvestigationApp } from './src/server/app';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const app = createInvestigationApp();

// Start Express server and mount Vite
async function start() {
  const isDev = process.env.NODE_ENV !== 'production';

  if (isDev) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static('dist'));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`REA Studio server running at http://localhost:${port}`);
  });
}

// Only start the server if directly executed as the main module
if (process.argv[1] && process.argv[1].endsWith('server.ts')) {
  start().catch(err => {
    console.error('Fatal server startup error:', err);
    process.exit(1);
  });
}
