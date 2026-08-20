import { loadGatewayConfigFromSecretProvider } from './config.js';
import { assertArtifactReadiness } from './artifact-readiness.js';
import { ZkTeleAuthGateway } from './server.js';
import { ChainedSecretProvider, EnvironmentSecretProvider, FileSecretProvider, structuredLog, secretPresence } from './secrets.js';

async function main(): Promise<void> {
  const config = await loadGatewayConfigFromSecretProvider(process.env, new ChainedSecretProvider([new EnvironmentSecretProvider(), new FileSecretProvider()]));
  const artifacts = assertArtifactReadiness({
    artifactsDir: process.env.ZK_TELE_AUTH_ARTIFACTS_DIR,
    allowDevelopmentArtifacts: config.allowDevelopmentArtifacts,
    requiredCircuits: config.enableExperimentalPriva ? ['telegram_auth', 'priva_purchase_auth'] : ['telegram_auth'],
  });
  const gateway = new ZkTeleAuthGateway(config);
  await gateway.verifyStartupPolicy();
  gateway.markReady();
  const server = gateway.createServer();
  server.requestTimeout = config.requestTimeoutMs;
  server.headersTimeout = config.headersTimeoutMs;
  server.keepAliveTimeout = config.keepAliveTimeoutMs;
  let stopping = false;
  const shutdown = (signal: string) => {
    if (stopping) return;
    stopping = true;
    gateway.markNotReady();
    gateway.stopAccepting();
    console.log(structuredLog('shutdown_started', { signal }));
    server.close((error) => {
      if (error) {
        console.error(structuredLog('shutdown_failed', { error: error.message }));
        process.exitCode = 1;
      } else {
        void gateway.drain(config.requestTimeoutMs).then((drained) => {
          void gateway.close();
          if (!drained) process.exitCode = 1;
          console.log(structuredLog('shutdown_complete', { drained }));
        });
      }
    });
  };
  process.once('SIGTERM', () => shutdown('SIGTERM'));
  process.once('SIGINT', () => shutdown('SIGINT'));
  server.listen(config.port, config.host, () => {
    console.log(structuredLog('gateway_ready', {
      environment: config.environment,
      host: config.host,
      port: config.port,
      artifactStatus: artifacts.status,
      manifestDigest: artifacts.manifestDigest,
      telegramBotToken: secretPresence(config.botToken),
      issuerSecret: secretPresence(config.issuerSecret),
      issuerKeyHash: config.expectedIssuerKeyHash ? 'configured' : 'not_configured',
    }));
  });
}

main().catch((error) => {
  console.error(structuredLog('gateway_start_failed', { error: error instanceof Error ? error.message : String(error) }));
  process.exitCode = 1;
});
