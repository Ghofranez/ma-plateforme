// Transporteur — appelle les routes du backend
import { api } from "../api/api";

// ─────────────────────────────
// AUTH
// ─────────────────────────────
export const registerUser = (data: any) => api.post("/register", data);
export const loginUser    = (data: any) => api.post("/login", data);

// ─────────────────────────────
// EMAIL VERIFICATION (2FA login)
// ─────────────────────────────
export const sendEmailCode = (email: string) =>
  api.post("/send-email-code", { email });

export const verifyLoginCode = (data: {
  email: string;
  code: string;
}) => api.post("/verify-login-code", data);

// ─────────────────────────────
// RESET PASSWORD
// ─────────────────────────────
export const requestPasswordReset = (data: { email: string }) =>
  api.post("/forgot-password", data);

export const verifyResetCode = (data: {
  email: string;
  code: string;
}) => api.post("/verify-reset-code", data);

export const resetPassword = (data: {
  email: string;
  code: string;
  new_password: string;
}) => api.post("/reset-password", data);

// ─────────────────────────────
// PROFILE
// ─────────────────────────────
export const getMe          = () => api.get("/me");
export const updateProfile  = (data: any) => api.put("/profil", data);
export const changePassword = (data: any) => api.put("/change-password", data);

// ─────────────────────────────
// ANALYSE & HISTORIQUE
// ─────────────────────────────

export const getHistory = () => api.get("/history");

// Lancer une analyse
export const analyzeUrl = (url: string) =>
  api.post("/analyze", { url });

// Vérifier le statut de la tâche
export const getTaskStatus = (taskId: string) =>
  api.get(`/analyze/status/${taskId}`);

export const getReportById = (id: string) =>
  api.get(`/analyze/report/${id}`)

export const deleteHistoryItem = (id: string) =>
  api.delete(`/history/${id}`);

export const logout = () => api.post("/logout");