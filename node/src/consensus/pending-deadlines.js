/**
 * @file @tip-protocol/node/src/consensus/pending-deadlines.js
 * @description Min-heap of pending verdict deadlines, keyed by deadline
 * (integer epoch ms). Used by `verdict-trigger` to find the next dispute
 * whose reveal-window has crossed the round's BFT-Time clock without
 * scanning the DAG every round.
 *
 * In-memory only. The DAG is the persistent source of truth; the heap
 * is rehydrated from committed JURY_SUMMONS at consensus init.
 *
 * © 2026 The AI Lab Intelligence Unobscured, Inc.
 * License: TIPCL-1.0
 */

"use strict";

/**
 * @typedef {{ deadline: number, ctid: string, stage: "jury"|"appeal" }} Entry
 */

function createPendingDeadlines() {
  /** @type {Entry[]} */
  const heap = [];

  // ─── internal helpers ────────────────────────────────────────────────────

  function _lessThan(i, j) {
    return heap[i].deadline < heap[j].deadline;
  }

  function _swap(i, j) {
    const tmp = heap[i];
    heap[i] = heap[j];
    heap[j] = tmp;
  }

  function _siftUp(i) {
    while (i > 0) {
      const parent = (i - 1) >> 1;
      if (!_lessThan(i, parent)) break;
      _swap(i, parent);
      i = parent;
    }
  }

  function _siftDown(i) {
    const n = heap.length;
    while (true) {
      const left = 2 * i + 1;
      const right = left + 1;
      let smallest = i;
      if (left < n && _lessThan(left, smallest)) smallest = left;
      if (right < n && _lessThan(right, smallest)) smallest = right;
      if (smallest === i) return;
      _swap(i, smallest);
      i = smallest;
    }
  }

  function _isValid(e) {
    return e
      && Number.isInteger(e.deadline) && e.deadline > 0
      && typeof e.ctid === "string" && e.ctid.length > 0
      && (e.stage === "jury" || e.stage === "appeal");
  }

  // ─── public methods ──────────────────────────────────────────────────────

  /** Push an entry. Throws on malformed input. O(log N). */
  function push(entry) {
    if (!_isValid(entry)) {
      throw new Error(`pending-deadlines.push: invalid entry ${JSON.stringify(entry)}`);
    }
    heap.push(entry);
    _siftUp(heap.length - 1);
  }

  /** Smallest-deadline entry, or undefined if empty. O(1). Does not mutate. */
  function peek() {
    return heap[0];
  }

  /** Remove and return the smallest-deadline entry, or undefined if empty. O(log N). */
  function pop() {
    if (heap.length === 0) return undefined;
    const top = heap[0];
    const last = heap.pop();
    if (heap.length > 0) {
      heap[0] = last;
      _siftDown(0);
    }
    return top;
  }

  /** Number of entries. O(1). */
  function size() {
    return heap.length;
  }

  /**
   * Remove the first entry matching (ctid, stage). O(N).
   * Returns true if an entry was removed, false if not found.
   */
  function removeByCtid(ctid, stage) {
    const idx = heap.findIndex(e => e.ctid === ctid && e.stage === stage);
    if (idx === -1) return false;
    const last = heap.pop();
    if (idx < heap.length) {
      heap[idx] = last;
      // Restored value may belong above or below — try both directions.
      _siftDown(idx);
      _siftUp(idx);
    }
    return true;
  }

  /** Shallow copy of entries (heap order — only index 0 guaranteed top). */
  function snapshot() {
    return heap.map(e => ({ ...e }));
  }

  return { push, peek, pop, size, removeByCtid, snapshot };
}

module.exports = { createPendingDeadlines };
