// Transporteur — appelle les routes du backend
import { api } from "../api/api";

// ─────────────────────────────
// AUTH
// ─────────────────────────────
export const loginUser = (data: any) => {
  localStorage.removeItem("surveillees");
  localStorage.removeItem("scansRestants");
  return api.post("/login", data);
};
export const registerUser = (data: any) => {
  localStorage.removeItem("surveillees");
  localStorage.removeItem("scansRestants");
  return api.post("/register", data);
};

// ─────────────────────────────
// ADMIN
// ─────────────────────────────
export const getAdminUsers = () => api.get("/admin/users");

// ─────────────────────────────
// EMAIL VERIFICATION
// ─────────────────────────────
export const sendEmailCode  = (email: string) => api.post("/send-email-code", { email });
export const verifyLoginCode = (data: { email: string; code: string }) =>
  api.post("/verify-login-code", data);

// ─────────────────────────────
// RESET PASSWORD
// ─────────────────────────────
export const requestPasswordReset = (data: { email: string }) =>
  api.post("/forgot-password", data);
export const verifyResetCode = (data: { email: string; code: string }) =>
  api.post("/verify-reset-code", data);
export const resetPassword = (data: {
  email: string; code: string; new_password: string;
}) => api.post("/reset-password", data);

// ─────────────────────────────
// PROFILE
// ─────────────────────────────
export const getMe          = () => api.get("/me");
export const updateProfile  = (data: any) => api.put("/profil", data);
export const changePassword = (data: any) => api.put("/change-password", data);
//  changement email en 2 étapes
export const requestEmailChange = (data: { new_email: string; password: string }) =>
  api.put("/change-email/request", data);                    // envoie l'email de confirmation

export const confirmEmailChange = (token: string) =>
  api.get(`/change-email/confirm?token=${token}`);           // confirme via le lien

// ─────────────────────────────
// ANALYSE & HISTORIQUE
// ─────────────────────────────
export const getHistory        = () => api.get("/history");
export const analyzeUrl        = (url: string) => api.post("/analyze", { url });
export const getTaskStatus     = (taskId: string) => api.get(`/analyze/status/${taskId}`);
export const getReportById     = (id: string) => api.get(`/analyze/report/${id}`);
export const deleteHistoryItem = (id: string) => api.delete(`/history/${id}`);
export const deleteReport      = (id: string) => api.delete(`/history/${id}`);

// ─────────────────────────────
// SURVEILLANCE
// ─────────────────────────────
export const getMesSurveillances    = () => api.get("/surveillance/mes-surveillances");
export const activerSurveillance    = (url: string) => api.post("/surveillance/activer",    { url });
export const desactiverSurveillance = (url: string) => api.post("/surveillance/desactiver", { url });
export const getSurveillanceReports = () => api.get("/history");


export const logout = () => {
  localStorage.removeItem("surveillees");
  localStorage.removeItem("scansRestants");
  return api.post("/logout");
};

export const changeEmail = (data: { new_email: string; password: string }) =>
  api.put("/change-email", data);