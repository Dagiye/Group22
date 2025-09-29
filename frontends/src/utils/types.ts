// src/utils/types.ts
// Shared type definitions for the frontend

export type User = {
  id: string;
  username: string;
  email?: string;
};

export type Scan = {
  id: string;
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  created_at?: string;
  results_count?: number;
};
