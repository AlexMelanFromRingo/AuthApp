// Симулятор сервера OCRA (US3; FR-014, FR-023, FR-027): три режими —
// виклик-відповідь (з C/P/S/T), взаємна автентифікація, підпис транзакції.
// Стан «сервера» живе лише в пам'яті сторінки: виклики 120 с TTL, одна
// успішна валідація, лічильник C синхронізується після успіху.
import { parseSuite, computeResponse, verifyResponse, hashPin } from '../crypto/ocra.js';
import { base32Encode, base32Decode } from '../crypto/base32.js';
import { buildOcraTokenUri, buildChallengeUri, buildMutualUri, drawQr } from '../qr.js';

const CR_SUITES = [
  'OCRA-1:HOTP-SHA1-6:QN08',
  'OCRA-1:HOTP-SHA256-8:QN08',
  'OCRA-1:HOTP-SHA256-8:C-QN08',
  'OCRA-1:HOTP-SHA256-8:QN08-PSHA1',
  'OCRA-1:HOTP-SHA256-8:C-QN08-PSHA1',
  'OCRA-1:HOTP-SHA256-8:QN08-S064',
  'OCRA-1:HOTP-SHA256-8:QN08-T30S',
  'OCRA-1:HOTP-SHA512-8:QN08-T1M',
];

// Взаємна автентифікація: пари профілів сервер/клієнт із RFC 6287 C.2
const MUTUAL_PAIRS = [
  { label: 'SHA256 (клієнт без PIN)', server: 'OCRA-1:HOTP-SHA256-8:QA08', client: 'OCRA-1:HOTP-SHA256-8:QA08' },
  { label: 'SHA512 (клієнт із PIN)', server: 'OCRA-1:HOTP-SHA512-8:QA08', client: 'OCRA-1:HOTP-SHA512-8:QA08-PSHA1' },
];

const SIGN_SUITES = ['OCRA-1:HOTP-SHA256-8:QA08', 'OCRA-1:HOTP-SHA512-8:QA10-T1M'];

export function renderOcraPage(root) {
  const state = {
    challenge: null,   // {cid, q, suite, counter?, session?, createdAt, status, mode}
    mutual: null,      // {cid, qc, qs, pair, createdAt, status}
    counter: 0,        // серверний лічильник для C-профілів
  };

  root.innerHTML = `
    <section class="card">
      <h2 class="text-lg font-semibold mb-4">Режим</h2>
      <div class="flex gap-2 flex-wrap" id="ocra-modes">
        <button data-mode="cr" class="btn-primary" type="button">Виклик-відповідь</button>
        <button data-mode="mutual" class="btn-secondary" type="button">Взаємна автентифікація</button>
        <button data-mode="sign" class="btn-secondary" type="button">Підпис транзакції</button>
      </div>
    </section>

    <section class="card">
      <h2 class="text-lg font-semibold mb-4">Крок 1. Токен OCRA</h2>
      <div class="grid sm:grid-cols-2 gap-4">
        <div>
          <label class="field-label" for="ocra-suite">OCRA-профіль</label>
          <select id="ocra-suite" class="field-input"></select>
        </div>
        <div>
          <label class="field-label" for="ocra-secret">Секрет (Base32)</label>
          <div class="flex gap-2">
            <input id="ocra-secret" class="field-input font-mono" spellcheck="false" />
            <button id="ocra-gen-secret" class="btn-secondary whitespace-nowrap" type="button">Згенерувати</button>
          </div>
        </div>
        <div id="ocra-pin-wrap" class="hidden">
          <label class="field-label" for="ocra-pin">PIN-код (знає і сервер, і користувач)</label>
          <input id="ocra-pin" class="field-input font-mono" value="1234" inputmode="numeric" />
        </div>
        <div id="ocra-sign-wrap" class="hidden">
          <label class="field-label" for="ocra-sign-data">Дані транзакції (виклик QA)</label>
          <input id="ocra-sign-data" class="field-input font-mono" value="SIG10000" maxlength="64" />
        </div>
      </div>
      <button id="ocra-provision" class="btn-primary mt-4" type="button">QR для додавання токена в додаток</button>
      <div id="ocra-provision-result" class="mt-4 hidden">
        <canvas id="ocra-token-qr" class="qr-canvas"></canvas>
        <p class="text-sm text-muted mt-2">
          Відскануйте цей QR просто на екрані OCRA додатка — токен додасться
          автоматично. Після цього переходьте до кроку 2.
        </p>
      </div>
      <p id="ocra-error" class="text-error text-sm mt-2 hidden"></p>
    </section>

    <section class="card">
      <h2 class="text-lg font-semibold mb-4">Крок 2. Виклик сервера</h2>
      <button id="ocra-challenge-btn" class="btn-primary" type="button">Згенерувати виклик</button>
      <div id="ocra-challenge-result" class="mt-4 hidden">
        <div class="flex flex-col sm:flex-row gap-6 items-center">
          <canvas id="ocra-challenge-qr" class="qr-canvas"></canvas>
          <div class="flex-1 w-full text-sm text-muted" id="ocra-challenge-info"></div>
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
  let mode = 'cr';
  let ttlTimer = null;

  const showError = (message) => {
    const e = el('ocra-error');
    e.textContent = message;
    e.classList.remove('hidden');
  };

  // -- Перемикання режимів ---------------------------------------------------

  function refreshModeUi() {
    root.querySelectorAll('#ocra-modes button').forEach((btn) => {
      btn.className = btn.dataset.mode === mode ? 'btn-primary' : 'btn-secondary';
    });
    const suiteSelect = el('ocra-suite');
    suiteSelect.innerHTML = '';
    const suites = mode === 'cr' ? CR_SUITES
      : mode === 'sign' ? SIGN_SUITES
      : MUTUAL_PAIRS.map((p) => p.label);
    suites.forEach((s) => suiteSelect.insertAdjacentHTML('beforeend', `<option>${s}</option>`));
    refreshFieldVisibility();
  }

  function currentClientSuite() {
    if (mode === 'mutual') {
      return MUTUAL_PAIRS[el('ocra-suite').selectedIndex].client;
    }
    return el('ocra-suite').value;
  }

  function refreshFieldVisibility() {
    const suite = parseSuite(currentClientSuite());
    el('ocra-pin-wrap').classList.toggle('hidden', !suite.pinHashAlgorithm);
    el('ocra-sign-wrap').classList.toggle('hidden', mode !== 'sign');
  }

  root.querySelector('#ocra-modes').addEventListener('click', (event) => {
    const next = event.target.dataset?.mode;
    if (next) {
      mode = next;
      refreshModeUi();
    }
  });
  el('ocra-suite').addEventListener('change', refreshFieldVisibility);

  el('ocra-gen-secret').addEventListener('click', () => {
    el('ocra-secret').value = base32Encode(crypto.getRandomValues(new Uint8Array(32)));
  });
  el('ocra-gen-secret').click();
  refreshModeUi();

  // -- Допоміжне --------------------------------------------------------------

  const randomDigits = (n) => {
    const out = [];
    const buffer = crypto.getRandomValues(new Uint32Array(n));
    for (let i = 0; i < n; i++) out.push(buffer[i] % 10);
    return out.join('');
  };
  const newCid = () => {
    const bytes = crypto.getRandomValues(new Uint8Array(8));
    return btoa(String.fromCharCode(...bytes))
      .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  };
  const pinHashOrNull = (suite) => suite.pinHashAlgorithm
    ? hashPin(el('ocra-pin').value, suite.pinHashAlgorithm)
    : null;

  // -- Крок 1: провіжининг -----------------------------------------------------

  el('ocra-provision').addEventListener('click', async () => {
    el('ocra-error').classList.add('hidden');
    try {
      const clientSuite = currentClientSuite();
      parseSuite(clientSuite);
      const uri = buildOcraTokenUri({
        issuer: 'Стенд',
        account: mode === 'mutual' ? 'mutual-demo' : mode === 'sign' ? 'sign-demo' : 'ocra-demo',
        secretBase32: el('ocra-secret').value.trim(),
        suite: clientSuite,
      });
      await drawQr(el('ocra-token-qr'), uri);
      el('ocra-provision-result').classList.remove('hidden');
    } catch (e) {
      showError(e.message);
    }
  });

  // -- Крок 2: виклик -----------------------------------------------------------

  el('ocra-challenge-btn').addEventListener('click', async () => {
    el('ocra-error').classList.add('hidden');
    el('ocra-verdict').classList.add('hidden');
    try {
      const cid = newCid();
      const info = el('ocra-challenge-info');

      if (mode === 'mutual') {
        const pair = MUTUAL_PAIRS[el('ocra-suite').selectedIndex];
        const qc = `CLI${randomDigits(5)}`;
        const qs = `SRV${randomDigits(5)}`;
        // Сервер відповідає першим: Q = QC ‖ QS (RFC 6287 C.2)
        const serverResponse = computeResponse(
          parseSuite(pair.server), base32Decode(el('ocra-secret').value), { question: qc + qs },
        );
        state.mutual = { cid, qc, qs, pair, createdAt: Date.now(), status: 'ISSUED' };
        state.challenge = null;
        await drawQr(el('ocra-challenge-qr'), buildMutualUri({
          clientSuite: pair.client, serverSuite: pair.server,
          qc, qs, serverResponse, cid, label: 'Стенд',
        }));
        info.innerHTML = `Виклик клієнта QC: <b class="font-mono">${qc}</b><br>` +
          `Виклик сервера QS: <b class="font-mono">${qs}</b><br>` +
          `Відгук сервера: <b class="font-mono">${serverResponse}</b> ` +
          `(додаток перевірить його перед відповіддю)<br>` +
          `<span id="ocra-ttl"></span>`;
      } else {
        const suiteRaw = currentClientSuite();
        const suite = parseSuite(suiteRaw);
        const isSign = mode === 'sign';
        const q = isSign
          ? el('ocra-sign-data').value.trim()
          : randomDigits(suite.questionLength);

        let sessionB64 = null;
        let session = null;
        if (suite.sessionLength != null) {
          session = crypto.getRandomValues(new Uint8Array(suite.sessionLength));
          sessionB64 = btoa(String.fromCharCode(...session))
            .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
        }
        const counter = suite.useCounter ? state.counter : null;

        state.challenge = {
          cid, q, suite: suiteRaw, counter, session,
          createdAt: Date.now(), status: 'ISSUED', mode: isSign ? 'sign' : null,
        };
        state.mutual = null;
        await drawQr(el('ocra-challenge-qr'), buildChallengeUri({
          suite: suiteRaw, q, cid, label: 'Стенд',
          counter, sessionB64, mode: isSign ? 'sign' : null,
        }));
        info.innerHTML =
          (isSign ? `Транзакція на підпис: <b class="font-mono">${q}</b><br>`
                  : `Виклик (Q): <b class="font-mono">${q}</b><br>`) +
          (counter != null ? `Лічильник C: <b class="font-mono">${counter}</b><br>` : '') +
          (session ? 'Сесійні дані: передано у QR (S064)<br>' : '') +
          `<span id="ocra-ttl"></span>`;
      }

      el('ocra-challenge-result').classList.remove('hidden');

      clearInterval(ttlTimer);
      const active = () => state.mutual ?? state.challenge;
      const tick = () => {
        const current = active();
        if (!current) return;
        const left = Math.max(0, 120 - Math.floor((Date.now() - current.createdAt) / 1000));
        if (left === 0 && current.status === 'ISSUED') current.status = 'EXPIRED';
        const ttlEl = root.querySelector('#ocra-ttl');
        if (ttlEl) {
          ttlEl.textContent = current.status === 'EXPIRED'
            ? 'Строк дії минув' : `Дійсний ще ${left} с`;
        }
      };
      tick();
      ttlTimer = setInterval(tick, 1000);
    } catch (e) {
      showError(e.message);
    }
  });

  // -- Крок 3: валідація ---------------------------------------------------------

  el('ocra-verify').addEventListener('click', () => {
    const verdict = el('ocra-verdict');
    const show = (ok, message) => {
      verdict.className = ok ? 'result-ok mt-3' : 'result-fail mt-3';
      verdict.textContent = message;
      verdict.classList.remove('hidden');
    };

    const current = state.mutual ?? state.challenge;
    if (!current) return show(false, 'Спершу згенеруйте виклик (крок 2)');
    if (current.status === 'VALIDATED') {
      return show(false, 'Цей виклик уже використано: повторна валідація відхилена');
    }
    if (current.status === 'EXPIRED' || Date.now() - current.createdAt > 120_000) {
      current.status = 'EXPIRED';
      return show(false, 'Строк дії виклику минув: згенеруйте новий');
    }

    try {
      const key = base32Decode(el('ocra-secret').value);
      const response = el('ocra-response').value;
      let ok;
      if (state.mutual) {
        // Клієнтська відповідь: Q = QS ‖ QC (RFC 6287 C.2)
        const suite = parseSuite(state.mutual.pair.client);
        ok = verifyResponse(suite, key, {
          question: state.mutual.qs + state.mutual.qc,
          pinHash: pinHashOrNull(suite),
        }, response);
      } else {
        const suite = parseSuite(state.challenge.suite);
        ok = verifyResponse(suite, key, {
          question: state.challenge.q,
          counter: state.challenge.counter,
          pinHash: pinHashOrNull(suite),
          sessionInfo: state.challenge.session,
          timeSeconds: suite.timeStepSeconds ? Math.floor(Date.now() / 1000) : null,
        }, response);
        if (ok && state.challenge.counter != null) {
          state.counter = state.challenge.counter + 1; // серверна синхронізація C
        }
      }
      if (ok) {
        current.status = 'VALIDATED';
        show(true, state.mutual
          ? 'Взаємну автентифікацію завершено: клієнт і сервер підтвердили одне одного'
          : state.challenge.mode === 'sign'
            ? 'Підпис транзакції валідний'
            : 'Відгук валідний: автентифікацію підтверджено');
      } else {
        show(false, 'Відгук невалідний (перевірте PIN, введення або час на пристрої)');
      }
    } catch (e) {
      show(false, e.message);
    }
  });
}
