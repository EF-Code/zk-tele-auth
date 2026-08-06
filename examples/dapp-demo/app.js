import { ZkAuthProofGenerator } from '../../src/sdk/proof-generator.js';
import { ZkAuthProofVerifier } from '../../src/sdk/proof-verifier.js';

document.addEventListener('DOMContentLoaded', () => {
  const loginBtn = document.getElementById('loginBtn');
  const statusBox = document.getElementById('statusBox');
  const resultCard = document.getElementById('resultCard');
  const authBox = document.getElementById('authBox');
  const nullifierVal = document.getElementById('nullifierVal');
  const resetBtn = document.getElementById('resetBtn');

  loginBtn.addEventListener('click', async () => {
    loginBtn.classList.add('hidden');
    statusBox.classList.remove('hidden');

    try {
      // In a real deployment the Telegram MiniApp injects the authenticated
      // user via initData (see src/sdk/initdata-parser.ts); here we simulate
      // the user payload so the browser demo can run without a bot token.
      const simulatedUserId = 987654321;
      const appDomain = 'dapp.zk-tele-auth.io';

      // 1. Generate a real Groth16 Proof locally (requires committed artifacts)
      const proofPayload = await ZkAuthProofGenerator.generateProof({
        userId: simulatedUserId,
        authDate: Math.floor(Date.now() / 1000) - 300,
        isPremium: true,
        appDomain,
        currentTimestamp: Math.floor(Date.now() / 1000)
      });

      // 2. Verify Proof (real snarkjs pairing check)
      const verification = await ZkAuthProofVerifier.verifyProof(proofPayload, appDomain);

      if (verification.isValid) {
        statusBox.classList.add('hidden');
        authBox.classList.add('hidden');
        resultCard.classList.remove('hidden');
        nullifierVal.textContent = verification.nullifierHash;
      } else {
        alert(`Verification failed: ${verification.error}`);
      }
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  });

  resetBtn.addEventListener('click', () => {
    resultCard.classList.add('hidden');
    authBox.classList.remove('hidden');
    loginBtn.classList.remove('hidden');
  });
});
