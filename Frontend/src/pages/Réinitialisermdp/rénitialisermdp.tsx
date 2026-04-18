import { useState } from "react";
import { useNavigate, useLocation } from "react-router";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import toast from "react-hot-toast";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle
} from "../../components/ui/card";
import { Mail, Lock, Eye, EyeOff, CheckCircle2 } from "lucide-react";
import "../../pages/Réinitialisermdp/réinitialiser.css";
import { resetPassword } from "../../services/auth.service";

export default function ResetPassword() {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState<string[]>([]);

  const navigate = useNavigate();
  const location = useLocation();

  const email = location.state?.email;
  const code = location.state?.code;

  // ───── VALIDATION ─────
  const validatePassword = (pwd: string) => {
    const validationErrors: string[] = [];

    if (pwd.length < 8) validationErrors.push("8 caractères minimum");
    if (!/[A-Z]/.test(pwd)) validationErrors.push("Majuscule requise");
    if (!/[a-z]/.test(pwd)) validationErrors.push("Minuscule requise");
    if (!/[0-9]/.test(pwd)) validationErrors.push("Chiffre requis");
    if (!/[!@#$%^&*]/.test(pwd)) validationErrors.push("Caractère spécial requis");

    return validationErrors;
  };

  const handlePasswordChange = (value: string) => {
    setPassword(value);
    setErrors(validatePassword(value));
  };

  const isValid =
    errors.length === 0 &&
    password.length > 0 &&
    password === confirmPassword;

  // ───── SUBMIT ─────
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!code) {
      alert("code invalide ou expiré");
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

      toast.success("Mot de passe réinitialisé avec succès !");
      navigate("/login");

    } catch (err: any) {
      toast.error(typeof err?.detail === "string" ? err.detail : err?.detail?.[0]?.msg || "Erreur serveur");
    } finally {
      setIsLoading(false);
    }
  };

  const passwordRequirements = [
    { label: "Au moins 8 caractères", met: password.length >= 8 },
    { label: "Une majuscule", met: /[A-Z]/.test(password) },
    { label: "Une minuscule", met: /[a-z]/.test(password) },
    { label: "Un chiffre", met: /[0-9]/.test(password) },
    { label: "Un caractère spécial", met: /[!@#$%^&*]/.test(password) },
  ];

  return (
    <div className="reset-password-container">
      <Card className="reset-password-card">

        <CardHeader className="card-header-center">
          <div className="icon-wrapper">
            <Mail className="size-9 text-white" />
          </div>
          <CardTitle>Nouveau mot de passe</CardTitle>
          <CardDescription>
            Créez un mot de passe sécurisé
          </CardDescription>
        </CardHeader>

        <form onSubmit={handleSubmit}>
          <CardContent>

            <Label>Nouveau mot de passe</Label>
            <div className="relative">
              <Lock className="input-icon" />

              <Input
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => handlePasswordChange(e.target.value)}
                placeholder="••••••••"
                className="pl-10 pr-10"
                autoComplete="new-password"
              />

              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="show-hide-btn"
              >
                {showPassword ? <EyeOff /> : <Eye />}
              </button>
            </div>

            {password && (
              <div className="password-requirements">
                <p>Exigences :</p>

                {passwordRequirements.map((req, i) => (
                  <div key={i} className="flex items-center gap-2 text-sm">
                    <CheckCircle2 />
                    <span style={{ color: req.met ? "green" : "red" }}>
                      {req.label}
                    </span>
                  </div>
                ))}
              </div>
            )}

            <Label>Confirmer mot de passe</Label>
            <div className="relative">
              <Lock className="input-icon" />

              <Input
                type={showConfirmPassword ? "text" : "password"}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••"
                className="pl-10 pr-10"
              />

              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                className="show-hide-btn"
              >
                {showConfirmPassword ? <EyeOff /> : <Eye />}
              </button>
            </div>

            {confirmPassword && password !== confirmPassword && (
              <p className="text-red-600 text-sm">
                Les mots de passe ne correspondent pas
              </p>
            )}

          </CardContent>

          <CardFooter>
            <button
              type="submit"
              className="submit-button"
              disabled={!isValid || isLoading}
            >
              {isLoading ? "Réinitialisation..." : "Réinitialiser"}
            </button>
          </CardFooter>

        </form>
      </Card>
    </div>
  );
}