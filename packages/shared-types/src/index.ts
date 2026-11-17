export type ApiResponse<T> = { data: T; error: null } | { data: null; error: { code: string; message: string } };

export interface SessionUser {
  id: string;
  githubLogin: string;
  name: string | null;
  avatarUrl: string | null;
}

export interface HealthStatus {
  status: "ok" | "degraded";
  dependencies: { postgres: "ok" | "error"; redis: "ok" | "error" };
}
