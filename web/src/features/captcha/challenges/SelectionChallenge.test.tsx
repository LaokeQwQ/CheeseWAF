import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IconClickChallenge } from "./IconClickChallenge";
import { TextClickChallenge } from "./TextClickChallenge";

afterEach(cleanup);

describe("selection captcha challenges", () => {
  it("maps a responsive pointer position to normalized natural-image coordinates", () => {
    const onChange = vi.fn();
    render(<TextClickChallenge imageSrc="data:image/png;base64,AA==" width={400} height={220} label="Select target" onChange={onChange}/>);
    const surface = screen.getByTestId("captcha-surface");
    vi.spyOn(surface, "getBoundingClientRect").mockReturnValue({ left: 20, top: 10, width: 200, height: 110, right: 220, bottom: 120, x: 20, y: 10, toJSON: () => ({}) });
    fireEvent.click(surface, { clientX: 170, clientY: 37.5 });
    expect(onChange).toHaveBeenCalledWith({ x: 7500, y: 2500 });
  });

  it("supports keyboard positioning and selection", () => {
    const onChange = vi.fn();
    render(<IconClickChallenge imageSrc="data:image/png;base64,AA==" label="Select icon" onChange={onChange}/>);
    const surface = screen.getByTestId("captcha-surface");
    expect(surface.getAttribute("data-challenge-type")).toBe("icon-click-challenge");
    fireEvent.keyDown(surface, { key: "ArrowRight", shiftKey: true });
    fireEvent.keyDown(surface, { key: "ArrowUp" });
    fireEvent.keyDown(surface, { key: "Enter" });
    expect(onChange).toHaveBeenCalledWith({ x: 6000, y: 4750 });
  });

  it("freezes pointer and keyboard input when disabled", () => {
    const onChange = vi.fn();
    render(<TextClickChallenge imageSrc="data:image/png;base64,AA==" label="Select target" disabled onChange={onChange}/>);
    const surface = screen.getByTestId("captcha-surface");
    fireEvent.click(surface, { clientX: 10, clientY: 10 });
    fireEvent.keyDown(surface, { key: "Enter" });
    expect(onChange).not.toHaveBeenCalled();
    expect(surface.getAttribute("tabindex")).toBe("-1");
  });
});
