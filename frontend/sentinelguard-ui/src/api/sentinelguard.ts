import { apiClient } from "./client";
import type { AnalyzeRequest, AnalyzeResponse, Incident, PolicyConfig } from "./types";

export async function analyze(req: AnalyzeRequest): Promise<AnalyzeResponse> {
  const res = await apiClient.post<AnalyzeResponse>("/analyze", req);
  return res.data;
}

export async function getIncidents(params: { source?: string; risk_level?: string } = {}): Promise<Incident[]> {
  const res = await apiClient.get<Incident[]>("/incidents", { params });
  return res.data;
}

export async function getIncident(id: number): Promise<Incident> {
  const res = await apiClient.get<Incident>(`/incidents/${id}`);
  return res.data;
}

export async function getPolicy(): Promise<PolicyConfig> {
  const res = await apiClient.get<PolicyConfig>("/policy");
  return res.data;
}

export async function updatePolicy(policy: PolicyConfig): Promise<PolicyConfig> {
  const res = await apiClient.put<PolicyConfig>("/policy", policy);
  return res.data;
}
