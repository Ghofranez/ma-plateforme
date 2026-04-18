import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle
} from "../../components/ui/card";

import {
  Mail,
  Lock,
  Eye,
  EyeOff,
  ShieldCheck,
  Fingerprint,
  Loader2
} from "lucide-react";

import { loginUser } from "../../services/auth.service"; 
import "../../pages/Loginpage/loginpage.css";

export default function Login() {
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
 try {
  const res = await loginUser({ email, password });

  if (res.requires2FA) {
    navigate("/vérificationemail",
    {
    state: { email }
  });
    return;
  }

} catch (err: any) {
  setError(
    err?.response?.data?.detail ||
    "Email ou mot de passe incorrect"
  );
} finally {
  setLoading(false);
}}

  return (
    <div className="login-container">
      <Card className="login-card">
        <CardHeader className="login-header">
          <div className="login-icon-wrapper">
            <div className="login-icon-box">
              <Fingerprint className="login-icon" />
            </div>
          </div>
          <CardTitle className="login-title">Bienvenue</CardTitle>
          <CardDescription className="login-description">
            Connectez-vous à notre plateforme
          </CardDescription>
        </CardHeader>

        <form onSubmit={handleSubmit}>
          <CardContent className="login-content">
            {error && <div className="login-error">{error}</div>}

            <div className="login-field">
              <Label htmlFor="email">Adresse email</Label>
              <div className="login-input-wrapper">
                <Mail className="login-input-icon" />
                <Input
                  id="email"
                  type="email"
                  placeholder="exemple@email.com"
                  className="login-input"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
            </div>

            <div className="login-field">
              <div className="login-password-header">
                <Label htmlFor="password">Mot de passe</Label>
                <Button type="button" variant="link" className="login-forgot">
                  <Link to="/Motdepasseoublie">Mot de passe oublié?</Link>
                </Button>
              </div>
              <div className="login-input-wrapper">
                <Lock className="login-input-icon" />
                <Input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="••••••••"
                  autoComplete="new-password"
                  className="login-input login-input-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="login-eye-btn"
                >
                  {showPassword ? <EyeOff className="login-eye-icon" /> : <Eye className="login-eye-icon" />}
                </button>
              </div>
            </div>

            <div className="login-2fa-badge">
              <ShieldCheck size={14} />
              <span>Vérification par email</span>
            </div>
          </CardContent>

          <CardFooter className="login-footer">
            <Button type="submit" className="login-btn" disabled={loading}>
              {loading ? (
                <>
                  <Loader2 className="animate-spin mr-2" size={16} />
                  Connexion...
                </>
              ) : (
                "Se connecter"
              )}
            </Button>
            <div className="login-register-link">
              Pas encore de compte?{" "}
              <Link to="/register" className="login-link">S'inscrire</Link>
            </div>
          </CardFooter>
        </form>
      </Card>
    </div>
  );
}