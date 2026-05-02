import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "../../components/ui/card";

import { Mail, Lock, Eye, EyeOff, ShieldCheck, Fingerprint, Loader2 } from "lucide-react";
import { loginUser } from "../../services/auth.service";

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
      const res = await loginUser({ email, password }) as any;
      if (res.requires2FA) {
        navigate("/vérificationemail", { state: { email } });
        return;
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Email ou mot de passe incorrect");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-blue-50 to-purple-50 p-4">

      <Card className="w-full max-w-md shadow-2xl border border-slate-200 rounded-2xl bg-white">

        {/* HEADER */}
        <CardHeader className="text-center space-y-3">
          <div className="flex justify-center">
            <div className="w-14 h-14 rounded-xl bg-gradient-to-r from-blue-600 to-purple-600 flex items-center justify-center shadow-lg">
              <Fingerprint className="text-white" />
            </div>
          </div>

          <CardTitle className="text-2xl font-bold text-slate-900">
            Bienvenue
          </CardTitle>

          <CardDescription className="text-slate-500">
            Connectez-vous à notre plateforme
          </CardDescription>
        </CardHeader>

        {/* FORM */}
        <form onSubmit={handleSubmit}>
          <CardContent className="space-y-4">

            {error && (
              <div className="bg-red-50 text-red-600 text-sm p-3 rounded-lg border border-red-200">
                {error}
              </div>
            )}

            {/* EMAIL */}
            <div className="space-y-2">
              <Label>Email</Label>
              <div className="relative">
                <Mail className="absolute left-3 top-3 text-slate-400 w-4 h-4" />
                <Input
                  type="email"
                  placeholder="exemple@email.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="pl-10"
                  required
                />
              </div>
            </div>

            {/* PASSWORD */}
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <Label>Mot de passe</Label>
                <Link
                  to="/Motdepasseoublie"
                  className="text-xs text-blue-600 hover:underline"
                >
                  Mot de passe oublié ?
                </Link>
              </div>

              <div className="relative">
                <Lock className="absolute left-3 top-3 text-slate-400 w-4 h-4" />

                <Input
                  type={showPassword ? "text" : "password"}
                  placeholder="••••••••"
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="pl-10 pr-10"
                  required
                />

                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3 text-slate-400 hover:text-slate-700"
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* BADGE */}
            <div className="flex items-center gap-2 text-xs text-blue-600 bg-blue-50 p-2 rounded-lg">
              <ShieldCheck size={14} />
              Vérification par email activée
            </div>
          </CardContent>

          {/* BUTTON */}
          <CardFooter className="flex flex-col gap-3">
            <Button
              type="submit"
              disabled={loading}
              className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white hover:opacity-90 transition"
            >
              {loading ? (
                <div className="flex items-center gap-2">
                  <Loader2 className="animate-spin w-4 h-4" />
                  Connexion...
                </div>
              ) : (
                "Se connecter"
              )}
            </Button>

            <p className="text-sm text-slate-500">
              Pas encore de compte ?{" "}
              <Link to="/register" className="text-blue-600 hover:underline">
                S'inscrire
              </Link>
            </p>
          </CardFooter>
        </form>
      </Card>
    </div>
  );
}