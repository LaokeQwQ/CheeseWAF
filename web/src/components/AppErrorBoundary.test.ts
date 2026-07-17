import { describe, expect, it } from "vitest";
import {
  buildFreshModuleURL,
  extractFailedModuleURL,
} from "./AppErrorBoundary";

describe("buildFreshModuleURL", () => {
  it("preserves the route state while replacing the cache-busting marker", () => {
    const url = new URL(
      buildFreshModuleURL(
        "http://127.0.0.1:4173/login?returnTo=%2Fcaptcha-lab&__cw_reload=old#verify",
        36,
      ),
    );
    expect(url.pathname).toBe("/login");
    expect(url.searchParams.get("returnTo")).toBe("/captcha-lab");
    expect(url.searchParams.get("__cw_reload")).toBe("10");
    expect(url.hash).toBe("#verify");
  });
});

describe("extractFailedModuleURL", () => {
  it("extracts the failed same-origin dynamic module", () => {
    expect(
      extractFailedModuleURL(
        "TypeError: Failed to fetch dynamically imported module: http://localhost:3000/src/pages/Login/LoginPage.tsx",
      ),
    ).toBe("http://localhost:3000/src/pages/Login/LoginPage.tsx");
  });

  it("does not probe a cross-origin URL", () => {
    expect(
      extractFailedModuleURL(
        "Failed to fetch dynamically imported module: https://example.com/module.js",
      ),
    ).toBeNull();
  });
});