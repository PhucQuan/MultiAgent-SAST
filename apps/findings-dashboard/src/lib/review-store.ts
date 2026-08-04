import type {
  ReviewerDisposition,
  ReviewerFeedback,
  ReviewerFeedbackStore,
} from "@/lib/report-types";

const STORAGE_KEY = "aegis-findings-dashboard/review-store/v1";

const VALID_DISPOSITIONS = new Set<ReviewerDisposition>([
  "confirmed",
  "needs-review",
  "false-positive",
  "suppressed",
]);

function isBrowser(): boolean {
  return typeof window !== "undefined";
}

function normalizeEntry(value: unknown): ReviewerFeedback | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return null;
  }

  const record = value as Record<string, unknown>;
  const disposition =
    typeof record.disposition === "string" &&
    VALID_DISPOSITIONS.has(record.disposition as ReviewerDisposition)
      ? (record.disposition as ReviewerDisposition)
      : undefined;
  const note = typeof record.note === "string" ? record.note : undefined;
  const muted = typeof record.muted === "boolean" ? record.muted : undefined;
  const updatedAt =
    typeof record.updatedAt === "string" && record.updatedAt.trim()
      ? record.updatedAt
      : new Date().toISOString();

  if (!disposition && !note?.trim() && muted !== true) {
    return null;
  }

  return {
    ...(disposition ? { disposition } : {}),
    ...(note?.trim() ? { note: note.trim() } : {}),
    ...(muted !== undefined ? { muted } : {}),
    updatedAt,
  };
}

export function readReviewStore(): ReviewerFeedbackStore {
  if (!isBrowser()) {
    return {};
  }

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return {};
    }

    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return {};
    }

    const entries = Object.entries(parsed as Record<string, unknown>);
    const store: ReviewerFeedbackStore = {};

    for (const [key, value] of entries) {
      const normalized = normalizeEntry(value);
      if (normalized) {
        store[key] = normalized;
      }
    }

    return store;
  } catch {
    return {};
  }
}

export function writeReviewStore(store: ReviewerFeedbackStore): void {
  if (!isBrowser()) {
    return;
  }

  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
}

export function updateReviewStore(
  store: ReviewerFeedbackStore,
  findingKey: string,
  patch: {
    disposition?: ReviewerDisposition | null;
    note?: string;
    muted?: boolean;
  },
): ReviewerFeedbackStore {
  const previous = store[findingKey];
  const nextEntry = normalizeEntry({
    ...previous,
    ...patch,
    updatedAt: new Date().toISOString(),
  });

  if (!nextEntry) {
    const rest = { ...store };
    delete rest[findingKey];
    return rest;
  }

  return {
    ...store,
    [findingKey]: nextEntry,
  };
}

export function clearReviewEntry(
  store: ReviewerFeedbackStore,
  findingKey: string,
): ReviewerFeedbackStore {
  const rest = { ...store };
  delete rest[findingKey];
  return rest;
}

export function serializeReviewStore(store: ReviewerFeedbackStore): string {
  return JSON.stringify(
    {
      exportedAt: new Date().toISOString(),
      feedback: store,
    },
    null,
    2,
  );
}
