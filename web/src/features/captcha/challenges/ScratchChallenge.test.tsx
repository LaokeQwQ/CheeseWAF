import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ScratchChallenge } from "./ScratchChallenge";

class ReadyImage {
  onload: null | (() => void) = null;
  set src(_value: string) { queueMicrotask(() => this.onload?.()); }
}

afterEach(cleanup);

describe("ScratchChallenge", () => {
  let context: CanvasRenderingContext2D;

  beforeEach(() => {
    vi.stubGlobal("Image", ReadyImage);
    context = { clearRect: vi.fn(), drawImage: vi.fn(), beginPath: vi.fn(), moveTo: vi.fn(), lineTo: vi.fn(), stroke: vi.fn(), globalCompositeOperation: "source-over", lineCap: "round", lineJoin: "round", lineWidth: 0 } as unknown as CanvasRenderingContext2D;
    vi.spyOn(HTMLCanvasElement.prototype, "getContext").mockReturnValue(context);
  });

  it("submits normalized pointer trajectory without exposing target data", async () => {
    const onSubmit = vi.fn();
    render(<ScratchChallenge imageSrc="data:image/png;base64,AA==" maskSrc="data:image/png;base64,BB==" label="Scratch" startedAt={{ current: performance.now() - 500 }} onInteractionStart={vi.fn()} onSubmit={onSubmit}/>);
    const surface = await screen.findByTestId("scratch-challenge");
    await vi.waitFor(() => expect(surface.getAttribute("aria-disabled")).toBe("false"));
    vi.spyOn(surface, "getBoundingClientRect").mockReturnValue({ left: 0, top: 0, width: 200, height: 110, right: 200, bottom: 110, x: 0, y: 0, toJSON: () => ({}) });
    fireEvent.pointerDown(surface, { pointerId: 4, clientX: 20, clientY: 22 });
    fireEvent.pointerMove(surface, { pointerId: 4, clientX: 100, clientY: 55 });
    fireEvent.pointerUp(surface, { pointerId: 4, clientX: 180, clientY: 88 });
    expect(onSubmit).toHaveBeenCalledOnce();
    expect(onSubmit.mock.calls[0][0].track).toMatchObject([{ x: 1000, y: 2000, type: "down" }, { x: 5000, y: 5000, type: "move" }, { x: 9000, y: 8000, type: "up" }]);
    expect(context.lineWidth).toBe(36);
    expect(context.lineCap).toBe("round");
    expect(context.lineJoin).toBe("round");
    expect(context.stroke).toHaveBeenCalledTimes(2);
    expect(context.moveTo).toHaveBeenNthCalledWith(1, 40, 44);
    expect(context.lineTo).toHaveBeenNthCalledWith(1, 200, 110);
    expect(context.moveTo).toHaveBeenNthCalledWith(2, 200, 110);
    expect(context.lineTo).toHaveBeenNthCalledWith(2, 360, 176);
    expect(surface.textContent).toBe("");
  });

  it("does not submit cancelled or repeated pointer completion", async () => {
    const onSubmit = vi.fn();
    render(<ScratchChallenge imageSrc="data:image/png;base64,AA==" maskSrc="data:image/png;base64,BB==" label="Scratch" startedAt={{ current: performance.now() }} onInteractionStart={vi.fn()} onSubmit={onSubmit}/>);
    const surface = await screen.findByTestId("scratch-challenge");
    await vi.waitFor(() => expect(surface.getAttribute("aria-disabled")).toBe("false"));
    fireEvent.pointerDown(surface, { pointerId: 7, clientX: 1, clientY: 1 });
    fireEvent.pointerCancel(surface, { pointerId: 7 });
    fireEvent.pointerUp(surface, { pointerId: 7, clientX: 2, clientY: 2 });
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("supports keyboard scratch trajectories", async () => {
    const onSubmit = vi.fn();
    render(<ScratchChallenge imageSrc="data:image/png;base64,AA==" maskSrc="data:image/png;base64,BB==" label="Scratch" startedAt={{ current: performance.now() - 300 }} onInteractionStart={vi.fn()} onSubmit={onSubmit}/>);
    const surface = await screen.findByTestId("scratch-challenge");
    await vi.waitFor(() => expect(surface.getAttribute("aria-disabled")).toBe("false"));
    fireEvent.keyDown(surface, { key: " " });
    fireEvent.keyDown(surface, { key: "ArrowRight", shiftKey: true });
    fireEvent.keyDown(surface, { key: "ArrowDown", shiftKey: true });
    fireEvent.keyDown(surface, { key: "Enter" });
    expect(onSubmit).toHaveBeenCalledOnce();
    expect(onSubmit.mock.calls[0][0].track.at(-1)).toMatchObject({ x: 6000, y: 6000, type: "up" });
    expect(context.lineWidth).toBe(36);
    expect(context.stroke).toHaveBeenCalledTimes(3);
  });
});
