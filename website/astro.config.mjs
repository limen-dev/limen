import { satteri } from '@astrojs/markdown-satteri';
import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

// A project site on GitHub Pages is served under /<repo>/; a custom domain from /.
// Both come from the environment so moving hosts is a settings change (issues #136, #138).
const site = process.env.SITE_URL ?? 'https://jfcmartins.github.io';
const base = (process.env.SITE_BASE ?? '/').replace(/\/?$/, '/');

// Wraps every table in a scroll container, so a wide one scrolls on its own instead of
// stretching the page on a phone. (Starlight's own table scroll is lost once a table is styled
// with rounded corners, so the border lives on the wrapper.)
const scrollableTables = {
  name: 'limen-scrollable-tables',
  element: {
    filter: ['table'],
    visit(node, ctx) {
      ctx.wrapNode(node, { type: 'element', tagName: 'div', properties: { className: ['table-scroll'] }, children: [] });
    },
  },
};

export default defineConfig({
  markdown: { processor: satteri({ hastPlugins: [scrollableTables] }) },
  site,
  base,
  // 'ignore' so /docs and /docs/ both load in dev and preview; built pages keep the slash.
  trailingSlash: 'ignore',
  build: { format: 'directory' },
  integrations: [
    starlight({
      title: 'Limen',
      description: 'Identity-aware access to SSH, databases, Kubernetes and internal apps. Short-lived, audited, self-hosted.',
      logo: { light: './src/assets/mark-light.svg', dark: './src/assets/mark-dark.svg', alt: '' },
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/jfcmartins/limen' }],
      customCss: [
        '@fontsource-variable/geist/index.css',
        '@fontsource-variable/geist-mono/index.css',
        './src/styles/tokens.css',
        './src/styles/docs.css',
      ],
      head: [
        { tag: 'meta', attrs: { property: 'og:image', content: new URL(`${base}og.png`, site).href } },
        { tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
      ],
      components: { Footer: './src/components/DocsFooter.astro' },
      // Our own 404 page (src/pages/404.astro) replaces Starlight's.
      disable404Route: true,
      lastUpdated: false,
      pagination: true,
      tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
      sidebar: [
        {
          label: 'Start here',
          items: [
            { slug: 'docs', label: 'Introduction' },
            { slug: 'docs/quickstart' },
            { slug: 'docs/concepts' },
            { slug: 'docs/status' },
          ],
        },
        {
          label: 'Connect',
          items: [
            { slug: 'docs/guides/cli' },
            { slug: 'docs/guides/databases' },
            { slug: 'docs/guides/redis' },
            { slug: 'docs/guides/mongodb' },
            { slug: 'docs/guides/search' },
            { slug: 'docs/guides/messaging' },
            { slug: 'docs/guides/kubernetes' },
            { slug: 'docs/guides/web-apps' },
            { slug: 'docs/guides/tcp' },
          ],
        },
        {
          label: 'Identity and access',
          items: [
            { slug: 'docs/guides/bots' },
            { slug: 'docs/guides/access-requests' },
            { slug: 'docs/guides/access-reviews' },
            { slug: 'docs/guides/discovery' },
            { slug: 'docs/guides/policy-tooling' },
            { slug: 'docs/reference/policy' },
          ],
        },
        {
          label: 'Audit and insight',
          items: [
            { slug: 'docs/guides/console' },
            { slug: 'docs/guides/audit-search' },
            { slug: 'docs/guides/watching-sessions' },
            { slug: 'docs/guides/metrics' },
            { slug: 'docs/guides/tracing' },
            { slug: 'docs/runbooks/audit-verify' },
          ],
        },
        {
          label: 'Operate',
          items: [
            { slug: 'docs/guides/scale-out' },
            { slug: 'docs/reference/compose-stack' },
            { label: 'Runbooks', collapsed: true, items: [{ autogenerate: { directory: 'docs/runbooks' } }] },
          ],
        },
        {
          label: 'Architecture',
          items: [
            { slug: 'docs/architecture/design' },
            { slug: 'docs/architecture/diagrams' },
            { slug: 'docs/architecture/components' },
            { slug: 'docs/architecture/threat-model' },
            { slug: 'docs/architecture/pentest-plan' },
            { label: 'Decision records', collapsed: true, items: [{ autogenerate: { directory: 'docs/architecture/adr' } }] },
          ],
        },
      ],
    }),
  ],
});
