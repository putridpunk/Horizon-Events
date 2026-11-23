import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { alertDetail } from "../test/fixtures.js";
import * as api from "../services/api.js";
import AlertDrawer from "./AlertDrawer.jsx";

vi.mock("../services/api.js");

function setup(detail = alertDetail()) {
  vi.mocked(api.getAlert).mockResolvedValue(detail);
  const props = { alertId: 1, onClose: vi.fn(), onChanged: vi.fn() };
  render(<AlertDrawer {...props} />);
  return props;
}

describe("AlertDrawer", () => {
  it("shows the alert, its disclaimer, techniques, history and related events", async () => {
    setup();
    expect(await screen.findByText("ALT-000001")).toBeInTheDocument();
    expect(screen.getByText(/unusually high number of failed authentication/)).toBeInTheDocument();
    expect(screen.getByText(/not a confirmed breach/)).toBeInTheDocument();
    expect(screen.getByText("5 minutes")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "T1110" })).toBeInTheDocument();
    expect(screen.getByText("Created as OPEN")).toBeInTheDocument();
    expect(screen.getByText("Related events (1)")).toBeInTheDocument();
  });

  it("starts an investigation and refreshes the alert", async () => {
    const user = userEvent.setup();
    const props = setup();
    vi.mocked(api.updateAlert).mockResolvedValue({});
    await user.click(await screen.findByRole("button", { name: "Start investigation" }));
    expect(api.updateAlert).toHaveBeenCalledWith(1, { status: "INVESTIGATING", note: null });
    await waitFor(() => expect(props.onChanged).toHaveBeenCalledTimes(1));
    expect(api.getAlert).toHaveBeenCalledTimes(2);
  });

  it("sends the typed note with the status change and clears the box", async () => {
    const user = userEvent.setup();
    setup();
    vi.mocked(api.updateAlert).mockResolvedValue({});
    const box = await screen.findByPlaceholderText("Add a note (optional)");
    await user.type(box, "  checked with owner  ");
    await user.click(screen.getByRole("button", { name: "Resolve" }));
    expect(api.updateAlert).toHaveBeenCalledWith(1, { status: "RESOLVED", note: "checked with owner" });
    await waitFor(() => expect(box).toHaveValue(""));
  });

  it("shows the server's message and does not report a change when the update fails", async () => {
    const user = userEvent.setup();
    const props = setup();
    vi.mocked(api.updateAlert).mockRejectedValue(new Error("Cannot change status from OPEN to OPEN"));
    await user.click(await screen.findByRole("button", { name: "Resolve" }));
    expect(await screen.findByText("Cannot change status from OPEN to OPEN")).toBeInTheDocument();
    expect(props.onChanged).not.toHaveBeenCalled();
  });

  it("offers only 'Reopen' for a resolved alert", async () => {
    setup(alertDetail({ status: "RESOLVED" }));
    expect(await screen.findByRole("button", { name: "Reopen" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resolve" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start investigation" })).not.toBeInTheDocument();
  });

  it("closes from the button or the backdrop, but not from clicks inside the drawer", async () => {
    const user = userEvent.setup();
    const props = setup();
    await user.click(await screen.findByText("Investigation"));
    expect(props.onClose).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(props.onClose).toHaveBeenCalledTimes(1);
    await user.click(document.querySelector(".overlay"));
    expect(props.onClose).toHaveBeenCalledTimes(2);
  });

  it("shows a banner when the alert cannot be loaded", async () => {
    vi.mocked(api.getAlert).mockRejectedValue(new Error("Alert not found"));
    render(<AlertDrawer alertId={99} onClose={() => {}} />);
    expect(await screen.findByText(/Could not load data: Alert not found/)).toBeInTheDocument();
  });
});
