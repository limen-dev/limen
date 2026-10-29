// Shared by the homepage, the 404 page and the layout.
export const GH = 'https://github.com/limen-dev/limen';
export const ghPath = 'M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z';

/** Address of a documentation page under the site's base path. */
export const docsUrl = (base: string, p: string) => `${base}docs/${p}`;

/** The entries the ⌘K palette and the 404 page's suggestions search. Plain data, no third-party search. */
export const paletteFor = (base: string) => {
  const docs = (p: string) => docsUrl(base, p);
  return [
    { t: 'Introduction', h: docs(''), k: 'docs start what is limen' },
    { t: 'Quickstart', h: docs('quickstart/'), k: 'install run compose docker local' },
    { t: 'Concepts', h: docs('concepts/'), k: 'certificates policy audit workers proxy' },
    { t: 'What is built and verified', h: docs('status/'), k: 'status unverified roadmap honest' },
    { t: 'CLI guide', h: docs('guides/cli/'), k: 'commands login ssh ls' },
    { t: 'Databases', h: docs('guides/databases/'), k: 'postgres mysql aurora redshift rds' },
    { t: 'Kubernetes', h: docs('guides/kubernetes/'), k: 'kubectl eks k8s' },
    { t: 'Access requests and break-glass', h: docs('guides/access-requests/'), k: 'approve approval just in time jit' },
    { t: 'Bots for CI', h: docs('guides/bots/'), k: 'github actions gitlab machine identity' },
    { t: 'Policy reference', h: docs('reference/policy/'), k: 'yaml roles rules labels' },
    { t: 'Verify the audit chain', h: docs('runbooks/audit-verify/'), k: 'hash signed prove limen-audit-verify' },
    { t: 'Architecture and design', h: docs('architecture/design/'), k: 'design adr' },
    { t: 'Threat model', h: docs('architecture/threat-model/'), k: 'security' },
    { t: 'GitHub repository', h: GH, k: 'source code star issues' },
  ];
};
