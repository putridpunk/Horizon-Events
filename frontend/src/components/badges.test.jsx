import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { technique } from "../test/fixtures.js";
import IntelBadge from "./IntelBadge.jsx";
import TechniqueBadges from "./TechniqueBadges.jsx";
import { EmptyState, ErrorBanner, Pager, SeverityBadge, StatCard } from "./common.jsx";

describe("TechniqueBadges", () => {
  it("links each technique to attack.mitre.org in a new, safe tab", () => {
    render(<TechniqueBadges techniques={[technique(), technique({ id: "T1110.003", name: "Password Spraying", url: "https://attack.mitre.org/techniques/T1110/003/" })]} />);
    const link = screen.getByRole("link", { name: "T1110.003" });
    expect(link).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1110/003/");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link.getAttribute("rel")).toContain("noopener");
    expect(link).toHaveAttribute("title", expect.stringContaining("Password Spraying"));
  });

  it("marks low-confidence mappings", () => {
    render(<TechniqueBadges techniques={[technique({ id: "T1489", confidence: "low" })]} />);
    const link = screen.getByRole("link", { name: "T1489" });
    expect(link).toHaveClass("low");
    expect(link).toHaveAttribute("title", expect.stringContaining("low-confidence"));
  });

  it("renders nothing without techniques", () => {
    const { container } = render(<TechniqueBadges />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("IntelBadge", () => {
  it("shows 'Known malicious' with the feed names when listed", () => {
    render(<IntelBadge intel={{ listed: true, feeds: [{ id: "a", name: "Feed A" }, { id: "b", name: "Feed B" }] }} />);
    expect(screen.getByText("Known malicious")).toHaveAttribute("title", "Listed on: Feed A, Feed B");
  });

  it("renders nothing when not listed or missing", () => {
    const { container, rerender } = render(<IntelBadge intel={{ listed: false, feeds: [] }} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<IntelBadge intel={undefined} />);
    expect(container).toBeEmptyDOMElement();
  });
});

describe("common components", () => {
  it("StatCard shows a dash for missing values and zero for zero", () => {
    const { rerender } = render(<StatCard label="Events" value={undefined} />);
    expect(screen.getByText("-")).toBeInTheDocument();
    rerender(<StatCard label="Events" value={0} />);
    expect(screen.getByText("0")).toBeInTheDocument();
  });

  it("ErrorBanner shows only when there is an error", () => {
    const { container, rerender } = render(<ErrorBanner error={null} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<ErrorBanner error="boom" />);
    expect(screen.getByText(/Could not load data: boom/)).toBeInTheDocument();
  });

  it("SeverityBadge and EmptyState render their content", () => {
    render(<><SeverityBadge value="critical" /><EmptyState>Nothing here</EmptyState></>);
    expect(screen.getByText("critical")).toHaveClass("badge", "critical");
    expect(screen.getByText("Nothing here")).toBeInTheDocument();
  });

  it("Pager disables Prev on the first page and Next on the last", () => {
    const onChange = () => {};
    const { rerender } = render(<Pager offset={0} limit={10} total={25} onChange={onChange} />);
    expect(screen.getByText(/Page 1 of 3/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Prev" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next" })).toBeEnabled();
    rerender(<Pager offset={20} limit={10} total={25} onChange={onChange} />);
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
  });
});
