// Shared by render-mermaid.mjs (draws the pictures) and sync-docs.mjs (shows them): the same way of
// finding a ```mermaid block in a document, and the same name for its pictures, so the two cannot
// disagree about which picture belongs to which block.
import { createHash } from 'node:crypto';

/** The sources of the ```mermaid blocks in `text`, line by line (so CRLF and trailing blanks do not matter). */
export function mermaidBlocks(text) {
  const blocks = [];
  let current = null;
  let fence = null;
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    if (current) {
      if (/^```\s*$/.test(line)) {
        blocks.push(current.join('\n') + '\n');
        current = null;
      } else {
        current.push(line);
      }
    } else if (fence) {
      if (line.startsWith(fence)) fence = null;
    } else if (/^```mermaid\s*$/.test(line)) {
      current = [];
    } else if (/^\s*(```|~~~)/.test(line)) {
      fence = line.trim().slice(0, 3);
    }
  }
  return blocks;
}

/** A short id for one block's source. */
export const mermaidId = (source) => createHash('sha256').update(source).digest('hex').slice(0, 12);

/** The two pictures of a block, light first. */
export const mermaidFiles = (source) => ['light', 'dark'].map((theme) => `mermaid-${mermaidId(source)}.${theme}.svg`);
