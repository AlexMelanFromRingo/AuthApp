import { defineConfig } from 'vite';
import tailwindcss from '@tailwindcss/vite';

// Статична збірка для GitHub Pages: сайт живе за адресою /<репозиторій>/,
// тому base задається відносним шляхом.
export default defineConfig({
  base: './',
  plugins: [tailwindcss()],
  server: {
    fs: {
      // Дозволяємо читати спільні тестові вектори з кореня монорепозиторію
      allow: ['..'],
    },
  },
});
