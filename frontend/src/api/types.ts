export interface ComponentStatus {
  name: string;
  installed: boolean;
  version: string | null;
  path: string | null;
  note: string | null;
}

export interface HealthResponse {
  status: string;
  app: string;
  database: string;
  version: string;
}

export interface SystemStatusResponse {
  status: string;
  components: ComponentStatus[];
}
