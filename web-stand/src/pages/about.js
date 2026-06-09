// Довідкова сторінка (T041): опис алгоритмів і протоколів — матеріал для
// демонстрації на захисті дипломної роботи.
export function renderAboutPage(root) {
  root.innerHTML = `
    <section class="card">
      <h2 class="text-lg font-semibold mb-3">Про стенд</h2>
      <p class="text-sm leading-relaxed">
        Цей стенд — демонстраційна частина дипломної роботи бакалавра з
        кібербезпеки: «Комплекс засобів аутентифікації». Він генерує QR-коди
        для Android-додатка і незалежно валідує одноразові коди. Всі
        обчислення виконуються у браузері (бібліотека @noble/hashes);
        серверної частини немає, секрети живуть лише в пам'яті сторінки.
      </p>
    </section>

    <section class="card">
      <h2 class="text-lg font-semibold mb-3">Підтримувані алгоритми TOTP (RFC 6238)</h2>
      <table class="w-full text-sm">
        <thead><tr class="text-left border-b border-slate-200 dark:border-slate-600">
          <th class="py-2">Алгоритм</th><th>Конструкція MAC</th><th>MAC, байтів</th><th>Усічення</th>
        </tr></thead>
        <tbody class="divide-y divide-slate-100 dark:divide-slate-700">
          <tr><td class="py-2 font-mono">SHA1</td><td>HMAC</td><td>20</td><td>RFC 4226</td></tr>
          <tr><td class="py-2 font-mono">SHA256</td><td>HMAC</td><td>32</td><td>RFC 4226</td></tr>
          <tr><td class="py-2 font-mono">SHA512</td><td>HMAC</td><td>64</td><td>RFC 4226</td></tr>
          <tr><td class="py-2 font-mono">SHA3-256</td><td>HMAC</td><td>32</td><td>узагальнене</td></tr>
          <tr><td class="py-2 font-mono">BLAKE2S-256</td><td>keyed-режим</td><td>32</td><td>узагальнене</td></tr>
          <tr><td class="py-2 font-mono">BLAKE2B-512</td><td>keyed-режим</td><td>64</td><td>узагальнене</td></tr>
          <tr><td class="py-2 font-mono">BLAKE3-256</td><td>keyed-режим</td><td>32</td><td>узагальнене</td></tr>
        </tbody>
      </table>
    </section>

    <section class="card">
      <h2 class="text-lg font-semibold mb-3">Узагальнене динамічне усічення</h2>
      <p class="text-sm leading-relaxed mb-2">
        RFC 4226 визначає зміщення вікна вилучення як молодший нібл
        останнього байта MAC (0–15), тож для дайджестів понад 20 байтів
        більша частина MAC ніколи не використовується. Для розширених
        алгоритмів у роботі визначено узагальнення:
      </p>
      <pre class="bg-slate-900 text-slate-100 rounded-lg p-3 text-xs overflow-x-auto">offset = MAC[L−1] mod (L−4)        // коди 6–8 цифр: 4 байти, 31 біт
offset = MAC[L−1] mod (L−8)        // коди 9–10 цифр: 8 байтів, 63 біти
код = вилучене_число mod 10^d</pre>
      <p class="text-sm leading-relaxed mt-2">
        Вікно рівномірно покриває весь MAC і не торкається байта-джерела
        offset. Для L=20 і d≤8 правило вироджується в оригінальний RFC 4226
        (mod 16 = молодший нібл) — це строге узагальнення стандарту.
      </p>
    </section>

    <section class="card">
      <h2 class="text-lg font-semibold mb-3">OCRA (RFC 6287)</h2>
      <p class="text-sm leading-relaxed">
        Симулятор підтримує односторонні профілі «виклик-відповідь»
        <span class="font-mono">QN08</span> (числовий виклик на 8 цифр) із
        хеш-функціями SHA-1/256/512 та опціональною часовою прив'язкою
        (T30S/T1M). Виклик генерується криптографічно стійким генератором,
        діє 120 секунд і приймає рівно одну успішну валідацію; повторні
        спроби відхиляються.
      </p>
    </section>

    <section class="card">
      <h2 class="text-lg font-semibold mb-3">Перевірка коректності</h2>
      <p class="text-sm leading-relaxed">
        Реалізації Kotlin (Bouncy Castle), JavaScript (@noble/hashes) та
        незалежний Python-референс (hashlib + blake3) звіряються на спільному
        наборі тестових векторів, що включає офіційні вектори RFC 6238
        (Додаток B) і RFC 6287 (Додаток C.1). Збіг трьох незалежних кодових
        баз — доказ коректності розширених режимів, для яких офіційних
        векторів не існує.
      </p>
      <p class="text-sm mt-2">
        Стандарти:
        <a class="text-blue-700 underline dark:text-blue-400" href="https://www.rfc-editor.org/rfc/rfc4226" target="_blank" rel="noopener">RFC 4226 (HOTP)</a> •
        <a class="text-blue-700 underline dark:text-blue-400" href="https://www.rfc-editor.org/rfc/rfc6238" target="_blank" rel="noopener">RFC 6238 (TOTP)</a> •
        <a class="text-blue-700 underline dark:text-blue-400" href="https://www.rfc-editor.org/rfc/rfc6287" target="_blank" rel="noopener">RFC 6287 (OCRA)</a>
      </p>
    </section>`;
}
