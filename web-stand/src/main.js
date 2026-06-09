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

// Темна тема: типово — системна; вибір користувача запам'ятовується
const themeToggle = document.getElementById('theme-toggle');
function applyTheme(dark) {
  document.documentElement.classList.toggle('dark', dark);
  themeToggle.textContent = dark ? '☀️' : '🌙';
}
let darkTheme = localStorage.getItem('theme')
  ? localStorage.getItem('theme') === 'dark'
  : window.matchMedia('(prefers-color-scheme: dark)').matches;
applyTheme(darkTheme);
themeToggle.addEventListener('click', () => {
  darkTheme = !darkTheme;
  localStorage.setItem('theme', darkTheme ? 'dark' : 'light');
  applyTheme(darkTheme);
});

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
