import { expect, test } from "@playwright/test";

test.describe("live source scenario validation", () => {
  test.skip(!process.env.ATDR_RUN_LIVE_SCENARIO, "Set ATDR_RUN_LIVE_SCENARIO=1 after running source scenarios against the local DB.");

  test("scenario sources, parser warnings, and dedup details are visible", async ({ page }) => {
    await page.goto("/login");
    await page.getByRole("button", { name: /sign in/i }).click();
    await page.waitForURL(/overview/);

    await expect(page.getByText("Log Sources")).toBeVisible();
    await expect(page.getByText("scenario-lab-firewall-1")).toBeVisible();
    await expect(page.getByText("scenario-dedup-firewall")).toBeVisible();
    await expect(page.getByText("scenario-router-generic")).toBeVisible();
    await expect(page.getByText("scenario-raw-fallback")).toBeVisible();

    await page.getByText("scenario-raw-fallback").click();
    await expect(page.getByText("Parser Profile", { exact: true })).toBeVisible();
    await expect(page.getByText("raw_fallback", { exact: true }).first()).toBeVisible();
    await expect(page.getByText("Error: repeated parser failures")).toBeVisible();
    await expect(page.getByText("Parser failure examples are available for review.")).toBeVisible();
    await page.getByRole("button", { name: "Close details" }).click();

    await page.goto("/logs");
    await page.getByText("Advanced filters and sorting").click();
    await page.getByRole("button", { name: "Log source filter" }).click();
    await page.getByRole("option", { name: "scenario-lab-firewall-1" }).click();
    await expect(page.getByRole("cell", { name: "scenario-lab-firewall-1" }).first()).toBeVisible();

    await page.goto("/alerts");
    await page.getByRole("button", { name: "Alert source filter" }).click();
    await page.getByRole("option", { name: "scenario-dedup-firewall" }).click();
    await expect(page.getByRole("cell", { name: "scenario-dedup-firewall" }).first()).toBeVisible();
    await page.getByText(/Multiple denied or dropped connections/i).first().click();
    await expect(page.getByText("Why flagged?")).toBeVisible();
    await expect(page.getByText("Alert Occurrences")).toBeVisible();
    await expect(page.getByText("Related Log Count")).toBeVisible();
    await expect(page.getByText("Deduplicated", { exact: true })).toBeVisible();

    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 2);
    expect(overflow).toBe(false);
  });
});
