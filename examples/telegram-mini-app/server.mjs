import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { ZkTeleAuthGateway } from '../../dist/gateway/server.js';
import { loadGatewayConfig } from '../../dist/gateway/config.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const publicRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public');
const gatewayConfig = loadGatewayConfig({
  ...process.env,
  NODE_ENV: process.env.NODE_ENV || 'development',
  ZK_TELE_AUTH_CORS_ORIGIN: process.env.ZK_TELE_AUTH_CORS_ORIGIN || 'http://127.0.0.1:3000',
});
const gateway = new ZkTeleAuthGateway(gatewayConfig);
await gateway.verifyStartupPolicy();
gateway.markReady();
const gatewayServer = gateway.createServer();
gatewayServer.listen(gatewayConfig.port, gatewayConfig.host, () => {
  console.log(`gateway listening on http://${gatewayConfig.host}:${gatewayConfig.port}`);
});

function safeFile(requestPath) {
  const relative = requestPath === '/' ? 'index.html' : requestPath.replace(/^\/+/, '');
  const candidate = path.resolve(publicRoot, relative);
  if (!candidate.startsWith(`${publicRoot}${path.sep}`)) return undefined;
  return candidate;
}

const staticServer = http.createServer((request, response) => {
  if (request.url === '/client.js' || request.url === '/types.js') {
    const clientPath = path.join(root, request.url === '/client.js' ? 'dist/client/client.js' : 'dist/client/types.js');
    response.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store' });
    response.end(fs.readFileSync(clientPath));
    return;
  }
  const file = safeFile(new URL(request.url || '/', 'http://localhost').pathname);
  if (!file || !fs.existsSync(file)) {
    response.writeHead(404, { 'Content-Type': 'text/plain' });
    response.end('not found');
    return;
  }
  const contentType = file.endsWith('.html') ? 'text/html; charset=utf-8' : 'text/javascript; charset=utf-8';
  response.writeHead(200, { 'Content-Type': contentType, 'Cache-Control': 'no-store' });
  response.end(fs.readFileSync(file));
});
staticServer.listen(3000, '127.0.0.1', () => {
  console.log('Mini App example at http://127.0.0.1:3000');
});

function shutdown() {
  gateway.markNotReady();
  gateway.stopAccepting();
  staticServer.close();
  gatewayServer.close();
}
process.once('SIGINT', shutdown);
process.once('SIGTERM', shutdown);
