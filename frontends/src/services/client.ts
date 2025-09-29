// app/services/client.ts
import axios, { AxiosInstance, AxiosHeaders, InternalAxiosRequestConfig } from "axios";

const apiClient: AxiosInstance = axios.create({
  baseURL: "http://localhost:8001",
  headers: new AxiosHeaders({ "Content-Type": "application/json" }),
});

apiClient.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    if (typeof window !== "undefined") {
      const token = localStorage.getItem("access_token");
      if (token) {
        if (!config.headers) config.headers = new AxiosHeaders();
        (config.headers as AxiosHeaders).set("Authorization", `Bearer ${token}`);
      }
    }
    return config;
  },
  (error) => Promise.reject(error)
);

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status;
    const data = error?.response?.data;
    if (data) console.error("API Error (server):", status, data);
    else if (status) console.error("API Error (server):", status, "No response data");
    else console.error("API Error:", error?.message ?? error);
    return Promise.reject(error);
  }
);

export default apiClient;
