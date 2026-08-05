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
      // Simulated Telegram WebApp user payload
      const mockUserId = 987654321;
      const appDomain = 'dapp.zk-tele-auth.io';

      // 1. Generate Groth16 Proof locally
      const proofPayload = await ZkAuthProofGenerator.generateProof({
        userId: mockUserId,
        authDate: Math.floor(Date.now() / 1000) - 300,
        isPremium: true,
        appDomain,
        currentTimestamp: Math.floor(Date.now() / 1000)
      });

      // 2. Verify Proof
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
