import axios from "axios";

const api = axios.create({
  baseURL:         "/api",
  withCredentials: true,
  headers: {
    "Content-Type": "application/json",
  },
});

api.interceptors.request.use((config) => config);

api.interceptors.response.use(
  (response) => response.data,   // retourne data directement
  (error) => {
    if (error.response) {
      return Promise.reject(error.response.data);
    }
    return Promise.reject({ detail: "Network error" });
  }
);

export { api };