import { satteri } from '@astrojs/markdown-satteri';
import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';
import { readFileSync } from 'node:fs';

// A project site on GitHub Pages is served under /<repo>/; a custom domain from /.
// Both come from the environment so moving hosts is a settings change (issues #136, #138).
const site = process.env.SITE_URL ?? 'https://limen-dev.github.io';
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
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/limen-dev/limen' }],
      customCss: [
        '@fontsource-variable/geist/index.css',
        '@fontsource-variable/geist-mono/index.css',
        './src/styles/tokens.css',
        './src/styles/docs.css',
        './src/styles/transitions.css',
      ],
      head: [
        { tag: 'meta', attrs: { property: 'og:image', content: new URL(`${base}og.png`, site).href } },
        { tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
        { tag: 'script', attrs: { src: `${base}docs-a11y.js`, defer: true } },
        // Inline, so it is listening before the page is first drawn and costs no request.
        { tag: 'script', content: readFileSync(new URL('./src/scripts/page-transitions.js', import.meta.url), 'utf8') },
      ],
      components: { Footer: './src/components/DocsFooter.astro' },
      // Our own 404 page (src/pages/404.astro) replaces Starlight's.
      disable404Route: true,
      // Wrap long code lines instead of scrolling them sideways.
      expressiveCode: { defaultProps: { wrap: true } },
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
            { slug: 'docs/guides/ai-agents' },
          ],
        },
        {
          label: 'Identity and access',
          items: [
            { slug: 'docs/guides/okta' },
            { slug: 'docs/guides/offboarding' },
            { slug: 'docs/guides/bots' },
            { slug: 'docs/guides/management-api' },
            { slug: 'docs/guides/terraform' },
            { slug: 'docs/guides/access-requests' },
            { slug: 'docs/guides/access-reviews' },
            { slug: 'docs/guides/discovery' },
            { slug: 'docs/guides/policy-tooling' },
            { slug: 'docs/reference/policy' },
            { slug: 'docs/reference/cli' },
          ],
        },
        {
          label: 'Audit and insight',
          items: [
            { slug: 'docs/guides/console' },
            { slug: 'docs/guides/audit-search' },
            { slug: 'docs/guides/audit-ocsf' },
            { slug: 'docs/guides/honeytokens' },
            { slug: 'docs/guides/watching-sessions' },
            { slug: 'docs/guides/metrics' },
            { slug: 'docs/guides/tracing' },
            { slug: 'docs/guides/observability' },
            { slug: 'docs/runbooks/audit-verify' },
          ],
        },
        {
          label: 'Operate',
          items: [
            { slug: 'docs/guides/rollout' },
            { slug: 'docs/guides/deploy' },
            {
              label: 'Deploy reference',
              collapsed: true,
              items: [
                { slug: 'docs/reference/deploy/helm-chart' },
                { slug: 'docs/reference/deploy/terraform-modules' },
                { slug: 'docs/reference/deploy/terraform-foundation' },
                { slug: 'docs/reference/deploy/terraform-ecs' },
                { slug: 'docs/reference/deploy/terraform-ec2' },
                { slug: 'docs/reference/deploy/terraform-discovery' },
                { slug: 'docs/reference/deploy/terraform-audit' },
                { slug: 'docs/reference/deploy/terraform-datadog' },
                { slug: 'docs/reference/deploy/terraform-example-complete' },
                { slug: 'docs/reference/deploy/terraform-example-kubernetes' },
              ],
            },
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
