export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return Response.json({ status: "ok", service: "nuvemshop-tracking" });
    }

    return new Response("Not found", { status: 404 });
  },
};
