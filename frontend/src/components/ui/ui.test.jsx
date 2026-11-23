import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import EmptyState from "./EmptyState.jsx";
import Icon, { ICON_NAMES } from "./Icon.jsx";
import SeverityBadge from "./SeverityBadge.jsx";
import StatusBadge from "./StatusBadge.jsx";
import Time from "./Time.jsx";

describe("SeverityBadge", () => {
  it.each([["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]])(
    "%s shows a text label and an icon, so it never relies on colour alone", (value, label) => {
      const { container } = render(<SeverityBadge value={value} />);
      const badge = screen.getByText(label).closest(".badge");
      expect(badge).toHaveClass("badge", value);
      expect(container.querySelector("svg")).toBeInTheDocument();
    });

  it("uses a different icon for each severity", () => {
    const shapes = ["critical", "high", "medium", "low"].map((v) => {
      const { container, unmount } = render(<SeverityBadge value={v} />);
      const d = container.querySelector("svg").innerHTML;
      unmount();
      return d;
    });
    expect(new Set(shapes).size).toBe(4);
  });

  it("falls back to the plain text for an unknown value", () => {
    render(<SeverityBadge value="weird" />);
    expect(screen.getByText("weird")).toBeInTheDocument();
  });
});

describe("StatusBadge", () => {
  it.each([["OPEN", "Open"], ["INVESTIGATING", "Investigating"], ["RESOLVED", "Resolved"]])(
    "%s reads %s with an icon", (value, label) => {
      const { container } = render(<StatusBadge value={value} />);
      expect(screen.getByText(label).closest(".badge")).toHaveClass("badge", value);
      expect(container.querySelector("svg")).toBeInTheDocument();
    });
});

describe("Time", () => {
  const NOW = Date.parse("2026-11-23T12:00:00Z");

  it("shows relative text and the exact timestamp on hover", () => {
    render(<Time value="2026-11-23T11:48:00" now={NOW} />);
    const el = screen.getByText("12 min ago");
    expect(el.tagName).toBe("TIME");
    expect(el).toHaveAttribute("title", new Date(Date.parse("2026-11-23T11:48:00Z")).toLocaleString());
    expect(el).toHaveAttribute("datetime", "2026-11-23T11:48:00");
  });

  it("renders a dash for missing values without a broken element", () => {
    const { container } = render(<Time value={null} now={NOW} />);
    expect(container).toHaveTextContent("-");
  });
});

describe("EmptyState", () => {
  it("shows a title, help text and an optional action", () => {
    render(<EmptyState title="No alerts yet" action={<button>Import logs</button>}>Alerts appear here.</EmptyState>);
    expect(screen.getByText("No alerts yet")).toBeInTheDocument();
    expect(screen.getByText("Alerts appear here.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import logs" })).toBeInTheDocument();
  });

  it("still works with only a message", () => {
    render(<EmptyState>Nothing here.</EmptyState>);
    expect(screen.getByText("Nothing here.")).toBeInTheDocument();
  });
});

describe("Icon", () => {
  it("is hidden from assistive technology unless labelled", () => {
    const { container, rerender } = render(<Icon name="bell" />);
    expect(container.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
    rerender(<Icon name="bell" label="Alerts" />);
    expect(screen.getByRole("img", { name: "Alerts" })).toBeInTheDocument();
  });

  it("renders nothing for an unknown name and has every icon the UI uses", () => {
    const { container } = render(<Icon name="nope" />);
    expect(container).toBeEmptyDOMElement();
    for (const name of ["dashboard", "list", "bell", "folders", "database", "chart", "file", "upload", "sun", "moon",
      "chevron-right", "close", "alert", "arrow-up", "arrow-down", "minus", "check", "shield", "search"]) {
      expect(ICON_NAMES).toContain(name);
    }
  });
});
