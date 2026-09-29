/*
 * Shared <head> loader, referenced by every page as the first element in
 * <head>. It pulls in the three things the whole UI depends on:
 *
 *   1. the Tailwind Play CDN (there is no build step in this project)
 *   2. js/tailwind-config.js, which assigns the design tokens
 *   3. css/style.css plus the three webfonts (IBM Plex Sans for UI,
 *      Courier Prime for code, Material Symbols Outlined for icons)
 *
 * Order matters: the CDN script has to execute before tailwind-config.js,
 * because the config file assigns to the `tailwind` global the CDN
 * creates. These are written with document.write() on purpose - it is the
 * only way to keep that order, and to keep the stylesheet render-blocking,
 * while still being loaded from a single file. This script is only ever
 * included synchronously from <head>; document.write() anywhere else
 * would blow away the document.
 */
(function () {
  // Pinned to the current Play CDN v3 build: the bare cdn.tailwindcss.com
  // URL 302s to /3.4.17, and the config in tailwind-config.js uses v3
  // `theme.extend` syntax, so this must not float to a v4 URL.
  document.write('<script src="https://cdn.tailwindcss.com/3.4.17"><\/script>');
  document.write('<script src="js/tailwind-config.js"><\/script>');
  document.write('<link rel="icon" type="image/svg+xml" href="assets/icons/favicon.svg">');
  document.write('<link rel="stylesheet" href="css/style.css">');
  document.write('<link rel="preconnect" href="https://fonts.googleapis.com">');
  document.write('<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>');
  document.write(
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2' +
      "?family=IBM+Plex+Sans:wght@400;500;600;700" +
      "&family=IBM+Plex+Mono:wght@400;500;600" +
      "&family=Courier+Prime:wght@400;700" +
      "&family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20,400,0,0" +
      '&display=block">'
  );
})();
