import { describe, expect, it } from "vitest";
import { routeFromHash, routeTitle } from "./route";

describe("routeFromHash", () => {
  it("defaults to analyze for an empty hash", () => {
    expect(routeFromHash("")).toBe("analyze");
    expect(routeFromHash("#")).toBe("analyze");
    expect(routeFromHash("#/")).toBe("analyze");
  });
  it("accepts every tab with or without a leading slash or trailing slash", () => {
    expect(routeFromHash("#/feed")).toBe("feed");
    expect(routeFromHash("#history")).toBe("history");
    expect(routeFromHash("#/catalog/")).toBe("catalog");
  });
  it("reports unknown routes as not found", () => {
    expect(routeFromHash("#/settings")).toBe("notfound");
    expect(routeFromHash("#/analyze/extra")).toBe("notfound");
  });
});

describe("routeTitle", () => {
  it("names the view", () => {
    expect(routeTitle("history")).toBe("Verdicts & stats · UniPhish 2 SOC Console");
    expect(routeTitle("notfound")).toBe("Page not found · UniPhish 2 SOC Console");
  });
});
