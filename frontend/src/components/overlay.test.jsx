import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { Drawer, Modal } from "./overlay.jsx";

function Harness({ kind = "drawer", busy = false }) {
  const [open, setOpen] = useState(false);
  const Shell = kind === "drawer" ? Drawer : Modal;
  return (
    <div>
      <button onClick={() => setOpen(true)}>Open it</button>
      {open && (
        <Shell title="Details" subtitle="more" onClose={() => setOpen(false)} busy={busy}>
          <button>First action</button>
          <button>Last action</button>
        </Shell>
      )}
    </div>
  );
}

describe.each([["drawer"], ["modal"]])("%s", (kind) => {
  it("is announced as a dialog with its title as the name", async () => {
    const user = userEvent.setup();
    render(<Harness kind={kind} />);
    await user.click(screen.getByRole("button", { name: "Open it" }));
    const dialog = screen.getByRole("dialog", { name: "Details" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
  });

  it("closes with Escape and gives focus back to what opened it", async () => {
    const user = userEvent.setup();
    render(<Harness kind={kind} />);
    const opener = screen.getByRole("button", { name: "Open it" });
    await user.click(opener);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("moves keyboard focus inside when it opens", async () => {
    const user = userEvent.setup();
    render(<Harness kind={kind} />);
    await user.click(screen.getByRole("button", { name: "Open it" }));
    expect(screen.getByRole("dialog")).toContainElement(document.activeElement);
  });

  it("keeps Tab inside: from the last control it wraps to the first, and Shift+Tab the other way", async () => {
    const user = userEvent.setup();
    render(<Harness kind={kind} />);
    await user.click(screen.getByRole("button", { name: "Open it" }));
    const dialog = screen.getByRole("dialog");
    const last = screen.getByRole("button", { name: "Last action" });
    last.focus();
    await user.tab();
    expect(dialog).toContainElement(document.activeElement);
    expect(document.activeElement).not.toBe(last);
    await user.tab({ shift: true });
    expect(dialog).toContainElement(document.activeElement);
    for (let i = 0; i < 6; i += 1) {  // however many times Tab is pressed, focus never leaves
      await user.tab();
      expect(dialog).toContainElement(document.activeElement);
    }
  });

  it("closes from the backdrop but not from clicks inside", async () => {
    const user = userEvent.setup();
    render(<Harness kind={kind} />);
    await user.click(screen.getByRole("button", { name: "Open it" }));
    await user.click(screen.getByRole("button", { name: "Last action" }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    await user.click(document.querySelector(".overlay"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("drawer specifics", () => {
  it("has a Close button in a header that stays visible", async () => {
    const user = userEvent.setup();
    render(<Harness kind="drawer" />);
    await user.click(screen.getByRole("button", { name: "Open it" }));
    expect(screen.getByText("more")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("modal specifics", () => {
  it("cannot be dismissed while it is busy (a request is in flight)", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<Modal title="Working" onClose={onClose} busy><button>Inside</button></Modal>);
    await user.keyboard("{Escape}");
    await user.click(document.querySelector(".overlay"));
    expect(onClose).not.toHaveBeenCalled();
  });
});
