import type { AnalyzeResponse } from "../api/types";

export type ChatMessage =
  | { id: string; role: "system"; text: string; ts: number }
  | { id: string; role: "user"; text: string; ts: number }
  | { id: string; role: "thinking"; ts: number; step: number }
  | { id: string; role: "gateway"; text: string; ts: number; incidentId: number; decision: string }
  | { id: string; role: "sentinel"; original: string; response: AnalyzeResponse; ts: number };

export type ChatSession = {
  id: string;
  title: string;
  createdAt: number;
  updatedAt: number;
  messages: ChatMessage[];
};
