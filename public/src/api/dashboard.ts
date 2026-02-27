import { apiClient } from './client';

export type TrafficVerdict = 'benign' | 'malicious';

export interface SummaryStats {
  totalRequests: number;
  benignRequests: number;
  maliciousRequests: number;
  accuracy: number;
}

export interface LiveTrafficEntry {
  id: string;
  timestamp: string;
  method: string;
  path: string;
  ip: string;
  verdict: TrafficVerdict;
  statusCode: number;
  attackType?: string;
  ruleId?: string;
  aiConfidence?: number;
}

export interface AttackDistributionPoint {
  type: string;
  count: number;
}

export interface AttacksByHourPoint {
  hour: string;
  count: number;
}

export interface TopAttacker {
  ip: string;
  attempts: number;
}

export interface AiModelStatus {
  architecture: string;
  version: string;
  parameters: string;
  trainingProgress: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  lastUpdated: string;
}

export async function fetchSummaryStats(): Promise<SummaryStats> {
  const { data } = await apiClient.get<SummaryStats>('/dashboard/summary');
  return data;
}

export async function fetchLiveTraffic(): Promise<LiveTrafficEntry[]> {
  const { data } = await apiClient.get<LiveTrafficEntry[]>('/dashboard/live-traffic');
  return data;
}

export async function fetchAttackDistribution(): Promise<AttackDistributionPoint[]> {
  const { data } = await apiClient.get<AttackDistributionPoint[]>('/dashboard/attack-distribution');
  return data;
}

export async function fetchAttacksByHour(): Promise<AttacksByHourPoint[]> {
  const { data } = await apiClient.get<AttacksByHourPoint[]>('/dashboard/attacks-by-hour');
  return data;
}

export async function fetchTopAttackers(): Promise<TopAttacker[]> {
  const { data } = await apiClient.get<TopAttacker[]>('/dashboard/top-attackers');
  return data;
}

export async function fetchAiModelStatus(): Promise<AiModelStatus> {
  const { data } = await apiClient.get<AiModelStatus>('/dashboard/ai-status');
  return data;
}

