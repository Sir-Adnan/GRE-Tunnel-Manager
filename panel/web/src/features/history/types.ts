export type HistoryChange = {
  id: string;
  name: string;
  engine: string;
  kind: "added" | "removed" | "changed";
  fields?: string[];
};

export type HistoryEntry = {
  point: string;
  time: string;
  count: number;
  changes: HistoryChange[];
  invalid?: boolean;
};

export type HistoryView = {
  revision: string;
  total: number;
  entries: HistoryEntry[];
};

export type HistoryReview = {
  point: string;
  time: string;
  revision: string;
  count: number;
  changes: HistoryChange[];
};
