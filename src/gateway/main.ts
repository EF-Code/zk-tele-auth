import { loadGatewayConfig } from './config.js';
import { assertArtifactReadiness } from './artifact-readiness.js';
import { ZkTeleAuthGateway } from './server.js';

async function main(): Promise<void> {
  const config = loadGatewayConfig();
  const artifacts = assertArtifactReadiness({
    artifactsDir: process.env.ZK_TELE_AUTH_ARTIFACTS_DIR,
    allowDevelopmentArtifacts: config.allowDevelopmentArtifacts,
  });
  const gateway = new ZkTeleAuthGateway(config);
  const server = gateway.createServer();
  server.requestTimeout = config.requestTimeoutMs;
  server.headersTimeout = config.headersTimeoutMs;
  server.keepAliveTimeout = config.keepAliveTimeoutMs;
  let stopping = false;
  const shutdown = (signal: string) => {
    if (stopping) return;
    stopping = true;
    console.log(JSON.stringify({ event: 'shutdown_started', signal }));
    server.close((error) => {
      if (error) {
        console.error(JSON.stringify({ event: 'shutdown_failed', error: error.message }));
        process.exitCode = 1;
      } else {
        console.log(JSON.stringify({ event: 'shutdown_complete' }));
      }
    });
  };
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.once('SIGINT', () => shutdown('SIGINT'));
  server.listen(config.port, config.host, () => {
    console.log(JSON.stringify({
      event: 'gateway_ready',
      environment: config.environment,
      host: config.host,
      port: config.port,
      artifactStatus: artifacts.status,
      manifestDigest: artifacts.manifestDigest,
    }));
  });
}

main().catch((error) => {
  console.error(JSON.stringify({ event: 'gateway_start_failed', error: error instanceof Error ? error.message : String(error) }));
  process.exitCode = 1;
});

