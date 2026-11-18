import { describe, expect, it } from "vitest";

import { breadcrumbFor, EXTRA_ROUTES } from "./breadcrumb";
import { areaLinks, navAreas } from "./sidebar-items";

const ids = (path: string) => breadcrumbFor(path).map((c) => c.id);

describe("breadcrumbFor", () => {
  it("puts the daily screens under the home area", () => {
    expect(ids("/dashboard")).toEqual(["home", "dashboard"]);
    expect(ids("/chat")).toEqual(["home", "chat"]);
  });

  it("puts a submenu page under its area", () => {
    expect(ids("/defensive/detections/")).toEqual(["monitor", "detections"]);
    expect(ids("/function/tasks")).toEqual(["pentest", "tasks"]);
    expect(ids("/system/schedule")).toEqual(["config", "schedule"]);
    expect(ids("/defensive/quality")).toEqual(["activity", "siem-quality"]);
  });

  it("shows a page that is not in the menu under the entry it belongs to", () => {
    expect(ids("/defensive/assets/host")).toEqual(["monitor", "infra", "host-detail"]);
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
    for (const area of navAreas) {
      for (const entry of areaLinks(area)) {
        expect(ids(entry.url).at(-1), entry.url).toBe(entry.id);
      }
    }
  });

  it("splits an area into sections of at most 8 entries", () => {
    for (const area of navAreas) {
      for (const section of area.sections) {
        expect(section.items.length, `${area.id}/${section.id}`).toBeLessThanOrEqual(8);
      }
    }
  });

  it("gives every area a submenu, so the menu width never changes", () => {
    for (const area of navAreas) {
      expect(areaLinks(area).length, area.id).toBeGreaterThan(0);
    }
    for (const route of EXTRA_ROUTES) {
      expect(ids(route.url).at(-1), route.url).toBe(route.id);
    }
  });
});
