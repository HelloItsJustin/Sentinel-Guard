import axios from "axios";

const API_BASE_URL = import.meta.env.VITE_SENTINELGUARD_API_URL ?? "http://localhost:8000";

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 15_000
});
