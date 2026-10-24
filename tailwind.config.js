// Tailwind build for the static pages (claude-agents#152): compiled once into assets/css/site.css
// by scripts/build-css.sh, never the Play CDN. Rebuild after adding a class to any page.
module.exports = {
  content: ['./*.html', './applied/*.html', './blog/*.html'],
  theme: { extend: {} },
  plugins: [],
};
