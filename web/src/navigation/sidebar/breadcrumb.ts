import { areaLinks, type NavArea, navAreas } from "./sidebar-items";

// One step of the page location shown in the header: a nav.item.<id>
// message key and, when it is a page of its own, where it leads.
export interface Crumb {
  id: string;
  url?: string;
}

// Pages that are not sidebar entries. They are shown under the entry they
// belong to: parent is that entry's id, id the page's own nav.item key.
export const EXTRA_ROUTES: readonly { url: string; parent: string; id: string }[] = [
  { url: "/defensive/assets/host", parent: "infra", id: "host-detail" },
  { url: "/defensive/feedback", parent: "siem-quality", id: "siem-feedback" },
  { url: "/defensive/sources", parent: "connections", id: "security-sources" },
  { url: "/function/sync", parent: "connections", id: "sync" },
  { url: "/function/findings/detail", parent: "findings", id: "finding-detail" },
  { url: "/system/agents/detail", parent: "agents", id: "agent-detail" },
];

const clean = (path: string) => {
  let p = path;
  try {
    p = decodeURIComponent(path);
  } catch {
    /* keep the raw path */
  }
  return p.replace(/\/+$/, "") || "/";
};

const under = (path: string, url: string) => path === url || path.startsWith(`${url}/`);

// trailOf returns the menu path to an entry: [area, entry].
function trailOf(id: string, areas: readonly NavArea[]): Crumb[] | null {
  for (const area of areas) {
    const link = areaLinks(area).find((l) => l.id === id);
    if (link) return [{ id: area.id }, { id: link.id, url: link.url }];
  }
  return null;
}

// breadcrumbFor derives the page location from the menu, so titles always
// say what the menu says: "진단 > 작업". The longest matching url wins; a
// page listed in EXTRA_ROUTES is appended to its parent's trail.
export function breadcrumbFor(pathname: string, areas: readonly NavArea[] = navAreas): Crumb[] {
  const path = clean(pathname);
  const extra = [...EXTRA_ROUTES].sort((a, b) => b.url.length - a.url.length).find((r) => under(path, r.url));
  if (extra) {
    const parent = trailOf(extra.parent, areas);
    if (parent) return [...parent, { id: extra.id }];
  }
  let best: { id: string; url: string } | null = null;
  for (const area of areas) {
    for (const entry of areaLinks(area)) {
      if (under(path, entry.url) && (!best || entry.url.length > best.url.length)) {
        best = { id: entry.id, url: entry.url };
      }
    }
  }
  return best ? (trailOf(best.id, areas) ?? []) : [];
}
