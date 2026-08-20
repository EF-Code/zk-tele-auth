import { ZkTeleAuthClient } from '/client.js';

const status = document.querySelector('#status');
const result = document.querySelector('#result');
const button = document.querySelector('#authenticate');
const client = new ZkTeleAuthClient({ baseUrl: 'http://127.0.0.1:8080' });

button.addEventListener('click', async () => {
  button.disabled = true;
  result.textContent = '';
  try {
    const initData = window.Telegram?.WebApp?.initData;
    if (!initData) throw new Error('Open this page as a configured Telegram Mini App.');
    const response = await client.authenticate({ initData });
    status.textContent = 'Authenticated; send proofPayload to your backend for verification.';
    result.textContent = JSON.stringify({ nullifierHash: response.nullifierHash, publicSignals: response.proofPayload.publicSignals }, null, 2);
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : 'Authentication failed';
  } finally {
    button.disabled = false;
  }
});
