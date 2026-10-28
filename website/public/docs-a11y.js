// Docs pages only. Two accessibility fixes Starlight does not make on its own:
//  - A table that scrolls sideways must be reachable from the keyboard, so a wrapper that
//    overflows becomes a focusable, named region (and stops being one if it stops overflowing).
//  - The search button shows "Search" and the shortcut, but is named only "Search" (WCAG 2.5.3,
//    label in name). Name it from the text that is actually shown; the phone layout shows only
//    the icon, so fall back to "Search" there.
function wireTables() {
  for (const el of document.querySelectorAll('.table-scroll')) {
    if (el.scrollWidth > el.clientWidth + 1) {
      el.tabIndex = 0;
      el.setAttribute('role', 'region');
      el.setAttribute('aria-label', 'Table, scrolls sideways');
    } else {
      el.removeAttribute('tabindex');
      el.removeAttribute('role');
      el.removeAttribute('aria-label');
    }
  }
}
function nameSearch() {
  for (const b of document.querySelectorAll('button[data-open-modal]')) {
    b.setAttribute('aria-label', b.innerText.replace(/\s+/g, ' ').trim() || 'Search');
  }
}
const wire = () => {
  wireTables();
  nameSearch();
};
document.addEventListener('DOMContentLoaded', wire);
addEventListener('load', wire);
addEventListener('resize', wire);
