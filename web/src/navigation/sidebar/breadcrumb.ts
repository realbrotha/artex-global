import { type NavGroup, sidebarItems } from "./sidebar-items";

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

// trailOf returns the sidebar path to an entry: [entry] for a top-level one,
// [parent, entry] for one inside a collapsible menu.
function trailOf(id: string, groups: readonly NavGroup[]): Crumb[] | null {
  for (const group of groups) {
    for (const item of group.items) {
      if (item.subItems) {
        const sub = item.subItems.find((s) => s.id === id);
        if (sub) return [{ id: item.id }, { id: sub.id, url: sub.url }];
      } else if (item.id === id) {
        return [{ id: item.id, url: item.url }];
      }
    }
  }
  return null;
}

// breadcrumbFor derives the page location from the sidebar, so the header
// always says what the menu says: "진단 > 작업". The longest matching url
// wins; a page listed in EXTRA_ROUTES is appended to its parent's trail.
export function breadcrumbFor(pathname: string, groups: readonly NavGroup[] = sidebarItems): Crumb[] {
  const path = clean(pathname);
  const extra = [...EXTRA_ROUTES].sort((a, b) => b.url.length - a.url.length).find((r) => under(path, r.url));
  if (extra) {
    const parent = trailOf(extra.parent, groups);
    if (parent) return [...parent, { id: extra.id }];
  }
  let best: { id: string; url: string } | null = null;
  for (const group of groups) {
    for (const item of group.items) {
      for (const entry of item.subItems ?? [item]) {
        if (under(path, entry.url) && (!best || entry.url.length > best.url.length)) {
          best = { id: entry.id, url: entry.url };
        }
      }
    }
  }
  return best ? (trailOf(best.id, groups) ?? []) : [];
}
