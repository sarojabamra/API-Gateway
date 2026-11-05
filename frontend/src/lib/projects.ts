/** Built-in intentionally vulnerable practice API seeded with SentinelGW. */
export const DEMO_PROJECT_SLUG = 'vulnshop';

export function isDemoProject(slug?: string | null): boolean {
  return (slug || '').trim().toLowerCase() === DEMO_PROJECT_SLUG;
}

/** Display name for selectors / headings — keeps "Demo" visible even on older DB names. */
export function formatProjectLabel(name: string, slug?: string | null): string {
  const label = (name || '').trim() || 'Untitled project';
  if (!isDemoProject(slug)) return label;
  if (/\bdemo\b/i.test(label)) return label;
  return `${label} (Demo Project)`;
}
