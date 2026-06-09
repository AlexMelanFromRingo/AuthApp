// Симулятор сервера OCRA (US3; FR-014, FR-023): провіжининг токена,
// генерація виклику в QR, валідація відгуку. Виклики живуть лише в пам'яті
// сесії: 120 с TTL, одна успішна валідація, повтори відхиляються.
import { parseSuite, verifyResponse } from '../crypto/ocra.js';
import { base32Encode, base32Decode } from '../crypto/base32.js';
import { buildOcraTokenUri, buildChallengeUri, drawQr } from '../qr.js';

const SUITES = [
  'OCRA-1:HOTP-SHA1-6:QN08',
  'OCRA-1:HOTP-SHA256-8:QN08',
  'OCRA-1:HOTP-SHA512-8:QN08',
  'OCRA-1:HOTP-SHA256-8:QN08-T30S',
  'OCRA-1:HOTP-SHA512-8:QN08-T1M',
];

export function renderOcraPage(root) {
  // Стан «сервера» — лише в пам'яті сторінки (FR-020)
  const challenges = new Map(); // cid → {q, suite, createdAt, status}

  root.innerHTML = `
    <section class="card">
      <h2 class="text-lg font-semibold mb-4">Крок 1. Токен OCRA</h2>
      <div class="grid sm:grid-cols-2 gap-4">
        <div>
          <label class="field-label" for="ocra-suite">OCRA-профіль</label>
          <select id="ocra-suite" class="field-input">
            ${SUITES.map((s) => `<option>${s}</option>`).join('')}
          </select>
        </div>
        <div>
          <label class="field-label" for="ocra-secret">Секрет (Base32)</label>
          <div class="flex gap-2">
            <input id="ocra-secret" class="field-input font-mono" spellcheck="false" />
            <button id="ocra-gen-secret" class="btn-secondary whitespace-nowrap" type="button">Згенерувати</button>
          </div>
        </div>
      </div>
      <button id="ocra-provision" class="btn-primary mt-4" type="button">QR для додавання токена в додаток</button>
      <div id="ocra-provision-result" class="mt-4 hidden">
        <canvas id="ocra-token-qr" class="rounded-lg border border-slate-200"></canvas>
      </div>
      <p id="ocra-error" class="text-red-700 text-sm mt-2 hidden"></p>
    </section>

    <section class="card">
      <h2 class="text-lg font-semibold mb-4">Крок 2. Виклик сервера</h2>
      <button id="ocra-challenge-btn" class="btn-primary" type="button">Згенерувати виклик</button>
      <div id="ocra-challenge-result" class="mt-4 hidden">
        <div class="flex flex-col sm:flex-row gap-6 items-center">
          <canvas id="ocra-challenge-qr" class="rounded-lg border border-slate-200"></canvas>
          <div class="flex-1 w-full">
            <p class="text-sm text-slate-600">Виклик (Q): <span id="ocra-q" class="font-mono font-bold"></span></p>
            <p class="text-sm text-slate-600">Дійсний: <span id="ocra-ttl"></span></p>
            <p class="text-sm text-slate-500 mt-1">Відскануйте QR на екрані OCRA додатка.</p>
          </div>
        </div>
      </div>
    </section>

    <section class="card">
      <h2 class="text-lg font-semibold mb-4">Крок 3. Валідація відгуку</h2>
      <label class="field-label" for="ocra-response">Відгук із додатка</label>
      <div class="flex gap-2">
        <input id="ocra-response" class="field-input font-mono" inputmode="numeric" autocomplete="off" />
        <button id="ocra-verify" class="btn-primary whitespace-nowrap" type="button">Перевірити</button>
      </div>
      <p id="ocra-verdict" class="mt-3 hidden"></p>
    </section>`;

  const el = (id) => root.querySelector(`#${id}`);
  let currentCid = null;
  let ttlTimer = null;

  const showError = (message) => {
    const e = el('ocra-error');
    e.textContent = message;
    e.classList.remove('hidden');
  };

  el('ocra-gen-secret').addEventListener('click', () => {
    el('ocra-secret').value = base32Encode(crypto.getRandomValues(new Uint8Array(32)));
  });
  el('ocra-gen-secret').click();

  el('ocra-provision').addEventListener('click', async () => {
    el('ocra-error').classList.add('hidden');
    try {
      parseSuite(el('ocra-suite').value); // валідація профілю
      const uri = buildOcraTokenUri({
        issuer: 'Стенд',
        account: 'ocra-demo',
        secretBase32: el('ocra-secret').value.trim(),
        suite: el('ocra-suite').value,
      });
      await drawQr(el('ocra-token-qr'), uri);
      el('ocra-provision-result').classList.remove('hidden');
    } catch (e) {
      showError(e.message);
    }
  });

  el('ocra-challenge-btn').addEventListener('click', async () => {
    el('ocra-error').classList.add('hidden');
    try {
      const suiteRaw = el('ocra-suite').value;
      parseSuite(suiteRaw);

      // QN08: 8 цифр через CSPRNG, провідні нулі допустимі (FR-014)
      const rnd = crypto.getRandomValues(new Uint32Array(1))[0];
      const q = String(rnd % 100000000).padStart(8, '0');
      const cidBytes = crypto.getRandomValues(new Uint8Array(8));
      const cid = btoa(String.fromCharCode(...cidBytes))
        .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');

      challenges.set(cid, { q, suite: suiteRaw, createdAt: Date.now(), status: 'ISSUED' });
      currentCid = cid;

      await drawQr(el('ocra-challenge-qr'), buildChallengeUri({ suite: suiteRaw, q, cid, label: 'Стенд' }));
      el('ocra-q').textContent = q;
      el('ocra-challenge-result').classList.remove('hidden');
      el('ocra-verdict').classList.add('hidden');

      clearInterval(ttlTimer);
      const tick = () => {
        const challenge = challenges.get(cid);
        const left = Math.max(0, 120 - Math.floor((Date.now() - challenge.createdAt) / 1000));
        if (left === 0 && challenge.status === 'ISSUED') challenge.status = 'EXPIRED';
        el('ocra-ttl').textContent = challenge.status === 'EXPIRED'
          ? 'строк дії минув' : `ще ${left} с`;
      };
      tick();
      ttlTimer = setInterval(tick, 1000);
    } catch (e) {
      showError(e.message);
    }
  });

  el('ocra-verify').addEventListener('click', () => {
    const verdict = el('ocra-verdict');
    const show = (ok, message) => {
      verdict.className = ok ? 'result-ok mt-3' : 'result-fail mt-3';
      verdict.textContent = message;
      verdict.classList.remove('hidden');
    };

    const challenge = currentCid && challenges.get(currentCid);
    if (!challenge) return show(false, 'Спершу згенеруйте виклик (крок 2)');
    if (challenge.status === 'VALIDATED') {
      return show(false, 'Цей виклик уже використано: повторна валідація відхилена');
    }
    if (challenge.status === 'EXPIRED' || Date.now() - challenge.createdAt > 120_000) {
      challenge.status = 'EXPIRED';
      return show(false, 'Строк дії виклику минув: згенеруйте новий');
    }

    try {
      const suite = parseSuite(challenge.suite);
      const ok = verifyResponse(
        suite,
        base32Decode(el('ocra-secret').value),
        challenge.q,
        el('ocra-response').value,
        suite.timeStepSeconds ? Math.floor(Date.now() / 1000) : null,
      );
      if (ok) {
        challenge.status = 'VALIDATED';
        show(true, 'Відгук валідний: автентифікацію підтверджено');
      } else {
        // Невдала спроба НЕ спалює виклик — можна виправити одруківку
        show(false, 'Відгук невалідний (перевірте введення або час на пристрої)');
      }
    } catch (e) {
      show(false, e.message);
    }
  });
}
