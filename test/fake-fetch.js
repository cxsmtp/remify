export function fakeFetch(routes) {
  const calls = [];
  const fetchImpl = async (target, init = {}) => {
    const url = new URL(target);
    const method = init.method ?? 'GET';
    calls.push({ method, url, init });
    const route = routes.find(([m, pattern]) => m === method && (pattern instanceof RegExp ? pattern.test(url.pathname) : url.pathname === pattern));
    if (!route) return new Response(JSON.stringify({ error: `no route for ${method} ${url.pathname}` }), { status: 404, statusText: 'Not Found' });
    let answer = route[2];
    if (typeof answer === 'function') answer = await answer(url, init);
    if (answer && typeof answer === 'object' && 'status' in answer && 'body' in answer) {
      return new Response(JSON.stringify(answer.body), { status: answer.status, statusText: answer.statusText ?? '' });
    }
    return new Response(JSON.stringify(answer), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  return { fetchImpl, calls };
}

/** All of an async iterable, as an array. */
export async function collect(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}
