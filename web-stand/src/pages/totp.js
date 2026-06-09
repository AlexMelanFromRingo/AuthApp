// Сторінка TOTP: конфігурація параметрів → QR для додатка → валідація коду
// (US2; FR-021, FR-022). Усі дані живуть лише в пам'яті сесії (FR-020).
import { ALGORITHMS } from '../crypto/mac.js';
import { generateTotp, verifyTotp } from '../crypto/totp.js';
import { base32Encode, base32Decode } from '../crypto/base32.js';
import { buildTotpUri, drawQr } from '../qr.js';

export function renderTotpPage(root) {
  root.innerHTML = `
    <section class="card">
      <h2 class="text-lg font-semibold mb-4">Параметри TOTP-токена</h2>
      <div class="grid sm:grid-cols-2 gap-4">
        <div>
          <label class="field-label" for="totp-alg">Алгоритм</label>
          <select id="totp-alg" class="field-input">
            ${Object.keys(ALGORITHMS).map((a) => `<option>${a}</option>`).join('')}
          </select>
        </div>
        <div>
          <label class="field-label" for="totp-digits">Довжина коду (цифри)</label>
          <select id="totp-digits" class="field-input"></select>
        </div>
        <div>
          <label class="field-label" for="totp-period">Період, секунд</label>
          <select id="totp-period" class="field-input">
            <option>15</option><option selected>30</option><option>60</option><option>120</option>
          </select>
        </div>
        <div>
          <label class="field-label" for="totp-secret">Секрет (Base32)</label>
          <div class="flex gap-2">
            <input id="totp-secret" class="field-input font-mono" spellcheck="false" />
            <button id="totp-gen-secret" class="btn-secondary whitespace-nowrap" type="button">Згенерувати</button>
          </div>
        </div>
        <div>
          <label class="field-label" for="totp-issuer">Назва сервісу</label>
          <input id="totp-issuer" class="field-input" value="Стенд" />
        </div>
        <div>
          <label class="field-label" for="totp-account">Обліковий запис</label>
          <input id="totp-account" class="field-input" value="demo@stand" />
        </div>
      </div>
      <button id="totp-build" class="btn-primary mt-4" type="button">Згенерувати QR-код</button>
      <p id="totp-error" class="text-red-700 text-sm mt-2 hidden"></p>
    </section>

    <section id="totp-result" class="card hidden">
      <h2 class="text-lg font-semibold mb-4">Відскануйте додатком</h2>
      <div class="flex flex-col sm:flex-row gap-6 items-center">
        <canvas id="totp-qr" class="rounded-lg border border-slate-200"></canvas>
        <div class="flex-1 w-full">
          <p class="text-sm text-slate-600 mb-2">Еталонний код стенду (для самоперевірки):</p>
          <p id="totp-reference" class="text-3xl font-mono font-bold tracking-wider"></p>
          <p id="totp-countdown" class="text-sm text-slate-500 mt-1"></p>
          <hr class="my-4" />
          <label class="field-label" for="totp-check">Введіть код із додатка</label>
          <div class="flex gap-2">
            <input id="totp-check" class="field-input font-mono" inputmode="numeric" autocomplete="off" />
            <button id="totp-verify" class="btn-primary whitespace-nowrap" type="button">Перевірити</button>
          </div>
          <p id="totp-verdict" class="mt-3 hidden"></p>
        </div>
      </div>
    </section>`;

  const el = (id) => root.querySelector(`#${id}`);
  const algSelect = el('totp-alg');
  const digitsSelect = el('totp-digits');

  // Допустимі довжини залежать від алгоритму: 6–8 стандартні, 6–10 розширені
  function refreshDigits() {
    const extended = ALGORITHMS[algSelect.value].extended;
    const max = extended ? 10 : 8;
    digitsSelect.innerHTML = '';
    for (let d = 6; d <= max; d++) {
      digitsSelect.insertAdjacentHTML('beforeend', `<option ${d === 6 ? 'selected' : ''}>${d}</option>`);
    }
  }
  refreshDigits();
  algSelect.addEventListener('change', refreshDigits);

  el('totp-gen-secret').addEventListener('click', () => {
    const bytes = crypto.getRandomValues(new Uint8Array(20));
    el('totp-secret').value = base32Encode(bytes);
  });
  el('totp-gen-secret').click();

  let ticker = null;

  el('totp-build').addEventListener('click', async () => {
    const errorEl = el('totp-error');
    errorEl.classList.add('hidden');
    try {
      const config = {
        alg: algSelect.value,
        digits: Number(digitsSelect.value),
        period: Number(el('totp-period').value),
        secret: base32Decode(el('totp-secret').value),
        secretBase32: el('totp-secret').value.trim(),
        issuer: el('totp-issuer').value.trim() || 'Стенд',
        account: el('totp-account').value.trim(),
      };
      if (config.secret.length < 10) throw new Error('Секрет закороткий: щонайменше 10 байтів (16 символів Base32)');

      await drawQr(el('totp-qr'), buildTotpUri(config));
      el('totp-result').classList.remove('hidden');

      // Живий еталонний код із відліком до зміни
      clearInterval(ticker);
      const tick = () => {
        const now = Math.floor(Date.now() / 1000);
        el('totp-reference').textContent =
          generateTotp(config.alg, config.secret, now, config.period, config.digits);
        el('totp-countdown').textContent =
          `Зміниться через ${config.period - (now % config.period)} с`;
      };
      tick();
      ticker = setInterval(tick, 1000);

      el('totp-verify').onclick = () => {
        const verdict = el('totp-verdict');
        const ok = verifyTotp(
          config.alg, config.secret, el('totp-check').value,
          Math.floor(Date.now() / 1000), config.period, config.digits, 1,
        );
        verdict.className = ok ? 'result-ok mt-3' : 'result-fail mt-3';
        verdict.textContent = ok
          ? 'Код збігається: додаток обчислює алгоритм правильно'
          : 'Код НЕ збігається (перевірте час на пристрої або параметри)';
        verdict.classList.remove('hidden');
      };
    } catch (e) {
      errorEl.textContent = e.message;
      errorEl.classList.remove('hidden');
    }
  });
}
