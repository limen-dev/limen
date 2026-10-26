import starlight from '@astrojs/starlight';
import { defineConfig } from 'astro/config';

// GitHub Pages serves a project site under /<repo>/. A custom domain serves from /.
// Both come from the environment so moving hosts is a settings change (issue #136).
const site = process.env.SITE_URL ?? 'https://jfcmartins.github.io';
const base = (process.env.SITE_BASE ?? '/').replace(/\/?$/, '/');

export default defineConfig({
  site,
  base,
  trailingSlash: 'always',
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
      components: { Footer: './src/components/DocsFooter.astro' },
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
