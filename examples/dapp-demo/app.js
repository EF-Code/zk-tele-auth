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
      const initData = window.Telegram?.WebApp?.initData;
      if (!initData) {
        throw new Error('Open this page as a configured Telegram Mini App; initData is missing.');
      }

      const response = await fetch('/authenticate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ initData }),
      });
      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.error || `Gateway returned HTTP ${response.status}`);
      }

      statusBox.classList.add('hidden');
      authBox.classList.add('hidden');
      resultCard.classList.remove('hidden');
      nullifierVal.textContent = result.nullifierHash;
    } catch (err) {
      statusBox.classList.add('hidden');
      loginBtn.classList.remove('hidden');
      alert(`Error: ${err.message}`);
    }
  });

  resetBtn.addEventListener('click', () => {
    resultCard.classList.add('hidden');
    authBox.classList.remove('hidden');
    loginBtn.classList.remove('hidden');
  });
});
