import { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import toast from "react-hot-toast";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "../../components/ui/card";

import { Mail, Lock, Eye, EyeOff, CheckCircle2 } from "lucide-react";
import { resetPassword } from "../../services/auth.service";

export default function ResetPassword() {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const navigate = useNavigate();
  const location = useLocation();

  const email = location.state?.email;
  const code = location.state?.code;

  const validatePassword = (pwd: string) => {
    const errors: string[] = [];
    if (pwd.length < 8) errors.push("8 caractères minimum");
    if (!/[A-Z]/.test(pwd)) errors.push("Majuscule requise");
    if (!/[a-z]/.test(pwd)) errors.push("Minuscule requise");
    if (!/[0-9]/.test(pwd)) errors.push("Chiffre requis");
    if (!/[!@#$%^&*]/.test(pwd)) errors.push("Caractère spécial requis");
    return errors;
  };

  const errors = validatePassword(password);

  const isValid =
    errors.length === 0 &&
    password.length > 0 &&
    password === confirmPassword;

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    if (!code) {
      toast.error("Code invalide ou expiré");
      return;
    }

    if (!isValid) return;

    setIsLoading(true);

    try {
      await resetPassword({
        email,
        code,
        new_password: password,
      });

      toast.success("Mot de passe réinitialisé !");
      navigate("/login");
    } catch (err: any) {
      toast.error(err?.detail || "Erreur serveur");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-blue-50 to-purple-50 px-4">

      <Card className="w-full max-w-md bg-white/80 backdrop-blur-xl shadow-xl rounded-2xl border-0">

        {/* HEADER */}
        <CardHeader className="text-center space-y-3">
          <div className="mx-auto w-14 h-14 flex items-center justify-center rounded-full bg-blue-100">
            <Mail className="text-blue-600" />
          </div>

          <CardTitle className="text-2xl font-bold text-slate-800">
            Nouveau mot de passe
          </CardTitle>

          <CardDescription className="text-slate-500">
            Créez un mot de passe sécurisé
          </CardDescription>
        </CardHeader>

        {/* FORM */}
        <form onSubmit={handleSubmit}>
          <CardContent className="space-y-5">

            {/* PASSWORD */}
            <div className="space-y-2">
              <Label>Nouveau mot de passe</Label>

              <div className="relative">
                <Lock className="absolute left-3 top-3.5 h-4 w-4 text-slate-400" />

                <Input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete="new-password"
                  className="pl-10 pr-10 h-11 rounded-xl"
                />

                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3 text-slate-500 hover:text-slate-700"
                >
                  {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>
            </div>

            {/* EXIGENCES ANIMÉES */}
            {password && (
              <div className="mt-2 bg-slate-50 p-3 rounded-xl text-sm space-y-1 animate-fade-in">
               

                {[
                  { label: "8 caractères minimum", ok: password.length >= 8 },
                  { label: "Majuscule", ok: /[A-Z]/.test(password) },
                  { label: "Minuscule", ok: /[a-z]/.test(password) },
                  { label: "Chiffre", ok: /[0-9]/.test(password) },
                  { label: "Caractère spécial", ok: /[!@#$%^&*]/.test(password) },
                ].map((r, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 animate-slide-up"
                    style={{ animationDelay: `${i * 80}ms` }}
                  >
                    <CheckCircle2
                      size={14}
                      className={r.ok ? "text-green-600" : "text-red-400"}
                    />

                    <span
                      className={`transition-colors duration-300 ${
                        r.ok ? "text-green-600" : "text-slate-500"
                      }`}
                    >
                      {r.label}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {/* CONFIRM PASSWORD */}
            <div className="space-y-2">
              <Label>Confirmer mot de passe</Label>

              <div className="relative">
                <Lock className="absolute left-3 top-3.5 h-4 w-4 text-slate-400" />

                <Input
                  type={showConfirmPassword ? "text" : "password"}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="••••••••"
                  className="pl-10 pr-10 h-11 rounded-xl"
                />

                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-3 text-slate-500 hover:text-slate-700"
                >
                  {showConfirmPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                </button>
              </div>

              {confirmPassword && password !== confirmPassword && (
                <p className="text-red-500 text-sm">
                  Les mots de passe ne correspondent pas
                </p>
              )}
            </div>

          </CardContent>

          {/* BUTTON */}
          <CardFooter>
            <button
              type="submit"
              disabled={!isValid || isLoading}
              className="w-full h-11 rounded-xl bg-gradient-to-r from-blue-600 to-purple-600 text-white font-medium hover:opacity-90 transition disabled:opacity-50"
            >
              {isLoading ? "Réinitialisation..." : "Réinitialiser"}
            </button>
          </CardFooter>

        </form>
      </Card>
    </div>
  );
}