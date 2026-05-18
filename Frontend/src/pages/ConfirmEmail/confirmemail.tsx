import { useEffect, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { confirmEmailChange } from "../../services/auth.service";
import { CheckCircle, XCircle, Loader } from "lucide-react";

export default function ConfirmEmail() {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const [status, setStatus] = useState<"loading" | "success" | "error">("loading");
    const [message, setMessage] = useState("");

    useEffect(() => {
        const token = searchParams.get("token");
        if (!token) {
            setStatus("error");
            setMessage("Token manquant.");
            return;
        }
        confirmEmailChange(token)
            .then(() => {
                setStatus("success");
                setMessage("Email modifié ! Redirection vers la connexion...");
                setTimeout(() => navigate("/login"), 3000);
            })
            .catch((err: any) => {
                setStatus("error");
                setMessage(err?.response?.data?.detail || "Token invalide ou expiré.");
            });
    }, []);

    return (
        <div className="flex items-center justify-center min-h-screen bg-slate-50">
            <div className="bg-white rounded-2xl shadow-sm border border-gray-100 p-8 text-center max-w-sm w-full mx-4">
                {status === "loading" && (
                    <>
                        <Loader size={40} className="text-indigo-500 animate-spin mx-auto mb-4" />
                        <p className="text-gray-500 text-sm">Confirmation en cours...</p>
                    </>
                )}
                {status === "success" && (
                    <>
                        <CheckCircle size={40} className="text-green-500 mx-auto mb-4" />
                        <p className="font-bold text-gray-800 mb-1">Succès !</p>
                        <p className="text-gray-500 text-sm">{message}</p>
                    </>
                )}
                {status === "error" && (
                    <>
                        <XCircle size={40} className="text-red-500 mx-auto mb-4" />
                        <p className="font-bold text-gray-800 mb-1">Erreur</p>
                        <p className="text-gray-500 text-sm">{message}</p>
                        <button
                            onClick={() => navigate("/profil")}
                            className="mt-4 px-4 py-2 rounded-xl text-sm font-bold text-white"
                            style={{ background: "linear-gradient(135deg, #6366f1, #8b5cf6)" }}
                        >
                            Retour au profil
                        </button>
                    </>
                )}
            </div>
        </div>
    );
}