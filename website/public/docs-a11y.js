// Docs pages only. Three accessibility fixes Starlight does not make on its own:
//  - A table that scrolls sideways must be reachable from the keyboard, so a wrapper that
//    overflows becomes a focusable, named region (and stops being one if it stops overflowing).
//  - A code block that scrolls sideways must be focusable too (WebKit does not do it by itself).
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
// Text from separate elements ("Search", "Ctrl", "K") is joined with no space by the checkers that
// compare the shown text with the name, so a space is put between neighbouring elements. It takes no
// room: the parents are flex boxes, which drop whitespace-only text. (site.ts does the same for the
// homepage's own search button; keep the two in step.)
function spaceOut(el) {
  for (const child of [...el.children]) {
    if (child.tagName === 'svg') continue;
    spaceOut(child);
    const next = child.nextSibling;
    const spaced = next && next.nodeType === 3 && /^\s/.test(next.textContent);
    if (child.nextElementSibling && child.nextElementSibling.tagName !== 'svg' && !spaced) child.after(' ');
  }
}
// Code blocks that scroll sideways are keyboard-reachable in Chrome and Firefox, but not in WebKit,
// so one that overflows is made focusable. It is never made unfocusable again (the renderer may have
// set it), and a block inside a closed tab is measured when it is first shown.
const watched = new WeakSet();
function wireCode() {
  for (const el of document.querySelectorAll('pre')) {
    const check = () => {
      if (el.scrollWidth > el.clientWidth + 1) el.tabIndex = 0;
    };
    check();
    if (!watched.has(el) && 'ResizeObserver' in window) {
      watched.add(el);
      new ResizeObserver(check).observe(el);
    }
  }
}
function nameSearch() {
  for (const b of document.querySelectorAll('button[data-open-modal]')) {
    if (!b.dataset.spaced) {
      spaceOut(b);
      b.dataset.spaced = '1';
    }
    b.setAttribute('aria-label', b.innerText.replace(/\s+/g, ' ').trim() || 'Search');
  }
}
const wire = () => {
  wireTables();
  wireCode();
  nameSearch();
};
document.addEventListener('DOMContentLoaded', wire);
addEventListener('load', wire);
addEventListener('resize', wire);
