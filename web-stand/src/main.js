// Точка входу стенду: простий роутер трьох сторінок без фреймворку (R3).
import { renderTotpPage } from './pages/totp.js';
import { renderOcraPage } from './pages/ocra.js';
import { renderAboutPage } from './pages/about.js';

const pages = {
  totp: renderTotpPage,
  ocra: renderOcraPage,
  about: renderAboutPage,
};

const app = document.getElementById('app');
const nav = document.getElementById('nav');

function navigate(page) {
  app.innerHTML = '';
  nav.querySelectorAll('.nav-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.page === page);
  });
  pages[page](app);
}

nav.addEventListener('click', (event) => {
  const page = event.target.dataset?.page;
  if (page && pages[page]) navigate(page);
});

navigate('totp');
