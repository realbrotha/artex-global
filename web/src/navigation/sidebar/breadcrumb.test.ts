import { describe, expect, it } from "vitest";

import { breadcrumbFor, EXTRA_ROUTES } from "./breadcrumb";
import { sidebarItems } from "./sidebar-items";

const ids = (path: string) => breadcrumbFor(path).map((c) => c.id);

describe("breadcrumbFor", () => {
  it("names a top-level page by its menu entry", () => {
    expect(ids("/dashboard")).toEqual(["dashboard"]);
    expect(ids("/defensive/detections/")).toEqual(["detections"]);
  });

  it("puts a page inside a collapsible menu under that menu", () => {
    expect(ids("/function/tasks")).toEqual(["pentest", "tasks"]);
    expect(ids("/system/schedule")).toEqual(["config", "schedule"]);
    expect(ids("/defensive/quality")).toEqual(["activity", "siem-quality"]);
  });

  it("shows a page that is not in the menu under the entry it belongs to", () => {
    expect(ids("/defensive/assets/host")).toEqual(["infra", "host-detail"]);
    expect(ids("/defensive/feedback")).toEqual(["activity", "siem-quality", "siem-feedback"]);
  });

  it("prefers the longest matching entry", () => {
    // Both are entries of the same menu; the deeper url must not fall to the shorter.
    expect(ids("/system/intercept")).toEqual(["config", "intercept"]);
    expect(ids("/system/intercept/assets")).toEqual(["config", "asset-intercept"]);
  });

  it("returns nothing for an unknown path", () => {
    expect(ids("/nowhere")).toEqual([]);
  });

  it("every sidebar entry and extra route resolves to a trail", () => {
    for (const group of sidebarItems) {
      for (const item of group.items) {
        for (const entry of item.subItems ?? [item]) {
          expect(ids(entry.url).at(-1), entry.url).toBe(entry.id);
        }
      }
    }
    for (const route of EXTRA_ROUTES) {
      expect(ids(route.url).at(-1), route.url).toBe(route.id);
    }
  });
});
