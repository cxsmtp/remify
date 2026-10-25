/** fn over every item, at most `limit` at a time; answers results in item order. */
export async function mapPool(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, worker));
  return results;
}

/**
 * Every page of a collection whose pages are numbered and whose end is only
 * known from a short page: the first page alone, then `ahead` pages at once,
 * read in order; what was asked for past the first short page is dropped.
 *
 * @param {(page: number) => Promise<any[]>} readPage  page number → rows
 * @param {{pageSize: number, ahead?: number, first?: number}} options
 */
export async function* numberedPages(readPage, { pageSize, ahead = 4, first = 0 }) {
  let page = first;
  // The first page alone: most collections fit in one, and pages asked for past the end are wasted requests.
  let size = 1;
  for (;;) {
    const batch = Array.from({ length: size }, (_, i) => {
      const pending = readPage(page + i);
      // Pages past the end may fail or be dropped; their errors must not go unhandled.
      pending.catch(() => {});
      return pending;
    });
    for (const pending of batch) {
      const rows = await pending;
      yield* rows;
      if (rows.length < pageSize) return;
    }
    page += size;
    size = ahead;
  }
}

/**
 * Every page of a collection whose total is known from its first page: the
 * first page, then all the others `limit` at a time.
 *
 * @param {(offset: number) => Promise<{rows: any[], total: number}>} readAt  row offset → rows and total
 */
export async function* countedPages(readAt, { pageSize, limit = 4 }) {
  const first = await readAt(0);
  yield* first.rows;
  const total = Number(first.total);
  if (!Number.isFinite(total) || first.rows.length < pageSize) {
    // No total to plan with: carry on one page at a time.
    if (first.rows.length < pageSize) return;
    for (let offset = pageSize; ; offset += pageSize) {
      const { rows } = await readAt(offset);
      yield* rows;
      if (rows.length < pageSize) return;
    }
  }
  const offsets = [];
  for (let offset = pageSize; offset < total; offset += pageSize) offsets.push(offset);
  for (let i = 0; i < offsets.length; i += limit) {
    const pages = await Promise.all(offsets.slice(i, i + limit).map((offset) => readAt(offset)));
    for (const page of pages) yield* page.rows;
  }
}
