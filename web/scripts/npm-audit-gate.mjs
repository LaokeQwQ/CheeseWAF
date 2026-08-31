#!/usr/bin/env node
/**
 * Fail CI on high/critical npm audit findings, with an explicit allowlist.
 *
 * Allowlisted advisories must include:
 *  - why the risk is accepted for CheeseWAF today
 *  - the follow-up that removes the allowlist entry
 *
 * SPA (Vite + React 18 + pure shadcn/Radix) does not use React Router RSC / SSR
 * single-fetch action pipelines. The only remaining high finding
 * (GHSA-qwww-vcr4-c8h2) is fixed in react-router 8.3.0, which requires
 * React >=19.2.7 and dropping react-router-dom.
 */
import { execFileSync } from "node:child_process";

/** @type {Record<string, { reason: string; followUp: string }>} */
const ALLOWLIST = {
  "GHSA-QWWW-VCR4-C8H2": {
    reason:
      "RSC-mode CSRF in react-router 7.12–8.2; CheeseWAF admin is a client-only SPA without RSC/SSR actions.",
    followUp:
      "Upgrade to React 19.2.7+ and react-router 8.3.0 (design system no longer blocks React 19).",
  },
};

function runNpmAuditJson() {
  // Prefer PATH resolution without shell to avoid Windows arg concatenation warnings.
  const npmCmd = process.platform === "win32" ? "npm.cmd" : "npm";
  try {
    return execFileSync(npmCmd, ["audit", "--json"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    // npm audit exits non-zero when findings exist; JSON is still on stdout.
    const stdout = error && typeof error === "object" ? error.stdout : "";
    return String(stdout ?? "");
  }
}

function main() {
  const raw = runNpmAuditJson();
  if (!raw.trim()) {
    console.error("npm audit produced no JSON output");
    process.exit(2);
  }

  const report = JSON.parse(raw);
  const vulns = report.vulnerabilities ?? {};
  const blocking = [];
  const allowed = [];

  for (const [name, entry] of Object.entries(vulns)) {
    const severity = String(entry.severity ?? "").toLowerCase();
    if (severity !== "high" && severity !== "critical") {
      continue;
    }
    const via = Array.isArray(entry.via) ? entry.via : [];
    const ghsas = via
      .map((item) => (typeof item === "object" && item ? item.url || item.source || item.title : item))
      .filter(Boolean)
      .map(String);

    const ids = new Set();
    for (const item of via) {
      if (typeof item === "object" && item) {
        if (item.url && String(item.url).includes("GHSA-")) {
          const m = String(item.url).match(/GHSA-[a-z0-9-]+/i);
          if (m) ids.add(m[0].toUpperCase());
        }
        if (item.source && String(item.source).startsWith("GHSA-")) {
          ids.add(String(item.source).toUpperCase());
        }
      }
    }
    // Also parse advisory strings
    for (const g of ghsas) {
      const m = String(g).match(/GHSA-[a-z0-9-]+/i);
      if (m) ids.add(m[0].toUpperCase());
    }

    if (ids.size === 0) {
      // Nested "via" entries may only name a parent package (no GHSA object).
      blocking.push({ name, severity, ids: ["(no-ghsa)"], via: ghsas });
      continue;
    }

    const allAllowed = [...ids].every((id) => ALLOWLIST[id.toUpperCase()]);
    if (allAllowed) {
      allowed.push({ name, severity, ids: [...ids] });
      continue;
    }
    blocking.push({ name, severity, ids: [...ids], via: ghsas });
  }

  if (allowed.length) {
    console.log("Allowed high/critical findings (documented):");
    for (const item of allowed) {
      for (const id of item.ids) {
        const meta = ALLOWLIST[String(id).toUpperCase()];
        if (meta) {
          console.log(`- ${item.name} ${id}: ${meta.reason}`);
          console.log(`  follow-up: ${meta.followUp}`);
        }
      }
    }
  }

  if (blocking.length) {
    console.error("Blocking high/critical npm audit findings:");
    for (const item of blocking) {
      console.error(`- ${item.name} (${item.severity}) ids=${item.ids.join(",")}`);
    }
    process.exit(1);
  }

  console.log("web npm audit gate passed (no unallowlisted high/critical).");
}

main();
