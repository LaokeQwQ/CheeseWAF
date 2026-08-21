import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import * as React from 'react';
import { cleanup, render, waitFor } from "@testing-library/react";
import {
  AppErrorBoundary,
  buildFreshModuleURL,
  extractFailedModuleURL,
} from "./AppErrorBoundary";

vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key }),
}));

function Boom(): never {
  throw new Error("boom");
}

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

describe("UI error reporting", () => {
  beforeEach(() => {
    sessionStorage.clear();
    window.history.replaceState({}, "", "/");
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("reports the error path without the hash", async () => {
    window.history.replaceState({}, "", "/ai?tab=models#reasoning");
    sessionStorage.setItem("cheesewaf-authed", "1");
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    vi.spyOn(console, "error").mockImplementation(() => {});

    render(
      React.createElement(AppErrorBoundary, { resetKey: "r", children: React.createElement(Boom) }),
    );

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());

    const request = fetchMock.mock.calls[0][1] as RequestInit;
    const payload = JSON.parse(request.body as string) as { path: string };
    expect(payload.path).toBe("/ai?tab=models");
  });
});
