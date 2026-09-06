import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

afterEach(() => vi.restoreAllMocks());

describe("App", () => {
  it("shows the API version when health succeeds", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ status: "ok", version: "0.1.0" }), {
          status: 200,
        }),
      ),
    );
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <App />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    expect(
      screen.getByRole("heading", { name: "RIFT operator console" }),
    ).toBeInTheDocument();
    expect(
      await screen.findByText(/API 0.1.0 is available/),
    ).toBeInTheDocument();
  });
});
