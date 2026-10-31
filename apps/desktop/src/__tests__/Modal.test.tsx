import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { Modal } from "../components/ui";

afterEach(cleanup);

it("focuses the first form field, not the close button", () => {
  render(
    <Modal title="New" onClose={vi.fn()}>
      <input aria-label="Name" />
      <button>Create</button>
    </Modal>,
  );
  expect(document.activeElement).toBe(screen.getByRole("textbox", { name: "Name" }));
});
