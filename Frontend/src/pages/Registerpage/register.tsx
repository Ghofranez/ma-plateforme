import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import {
  Card, CardContent, CardDescription,
  CardFooter, CardHeader, CardTitle
} from "../../components/ui/card";

import {
  User, CreditCard, Mail, Lock,
  Eye, EyeOff, Check, X,
  UserPlus, ShieldCheck
} from "lucide-react";

import toast from "react-hot-toast";
import { registerUser } from "../../services/auth.service";

type FormData = {
  nom: string;
  prenom: string;
  cin: string;
  email: string;
  password: string;
  confirmPassword: string;
};

const passwordRules = [
  { id: "length", label: "Au moins 8 caractères", test: (p: string) => p.length >= 8 },
  { id: "upper", label: "Majuscule requise", test: (p: string) => /[A-Z]/.test(p) },
  { id: "lower", label: "Minuscule requise", test: (p: string) => /[a-z]/.test(p) },
  { id: "number", label: "Chiffre requis", test: (p: string) => /[0-9]/.test(p) },
  { id: "special", label: "Caractère spécial requis", test: (p: string) => /[!@#$%^&*(),.?\":{}|<>]/.test(p) },
];

export default function Register() {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [passwordFocused, setPasswordFocused] = useState(false);

  const [cinError, setCinError] = useState("");
  const navigate = useNavigate();

  const [formData, setFormData] = useState<FormData>({
    nom: "",
    prenom: "",
    cin: "",
    email: "",
    password: "",
    confirmPassword: "",
  });

  const isPasswordValid = passwordRules.every(rule => rule.test(formData.password));

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;

    if (name === "cin") {
      if (!/^\d*$/.test(value)) return;

      setCinError(
        value.length > 0 && value.length !== 8
          ? "Le CIN doit contenir exactement 8 chiffres"
          : ""
      );
    }

    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (cinError) return toast.error("CIN invalide");

    if (!formData.nom || !formData.prenom || !formData.cin || !formData.email || !formData.password || !formData.confirmPassword) {
      return toast.error("Veuillez remplir tous les champs");
    }

    if (!isPasswordValid) return toast.error("Mot de passe non valide");

    if (formData.password !== formData.confirmPassword) {
      return toast.error("Les mots de passe ne correspondent pas");
    }

    try {
      await registerUser({
        nom: formData.nom,
        prenom: formData.prenom,
        cin: formData.cin,
        email: formData.email,
        password: formData.password,
        confirm_password: formData.confirmPassword,
      });

      toast.success("Inscription réussie");
      navigate("/login");
    } catch (err: any) {
      toast.error(err?.detail || "Erreur serveur");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-blue-50 to-purple-50 p-4">

      <Card className="w-full max-w-lg shadow-2xl rounded-2xl border border-slate-200 bg-white">

        {/* HEADER */}
        <CardHeader className="text-center space-y-2">
          <div className="flex justify-center">
            <div className="w-14 h-14 rounded-xl bg-gradient-to-r from-blue-600 to-purple-600 flex items-center justify-center shadow-lg">
              <UserPlus className="text-white" />
            </div>
          </div>

          <CardTitle className="text-2xl font-bold text-slate-900">
            Créer un compte
          </CardTitle>

          <CardDescription className="text-slate-500">
            Rejoignez notre plateforme
          </CardDescription>
        </CardHeader>

        <form onSubmit={handleSubmit}>
          <CardContent className="space-y-4">

            {/* NOM / PRENOM */}
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <Label>Nom</Label>
                <div className="relative">
                  <User className="absolute left-3 top-3 text-slate-400 w-4 h-4" />
                  <Input className="pl-10"
                    name="nom"
                    value={formData.nom}
                    onChange={handleChange}
                    placeholder="Nom"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <Label>Prénom</Label>
                <div className="relative">
                  <User className="absolute left-3 top-3 text-slate-400 w-4 h-4" />
                  <Input className="pl-10"
                    name="prenom"
                    value={formData.prenom}
                    onChange={handleChange}
                    placeholder="Prénom"
                  />
                </div>
              </div>
            </div>

            {/* CIN */}
            <div className="space-y-1">
              <Label>CIN</Label>
              <div className="relative">
                <CreditCard className="absolute left-3 top-3 text-slate-400 w-4 h-4" />
                <Input
                  className="pl-10"
                  name="cin"
                  value={formData.cin}
                  onChange={handleChange}
                  placeholder="8 chiffres"
                  maxLength={8}
                />
              </div>
              {cinError && <p className="text-red-500 text-xs">{cinError}</p>}
            </div>

            {/* EMAIL */}
            <div className="space-y-1">
              <Label>Email</Label>
              <div className="relative">
                <Mail className="absolute left-3 top-3 text-slate-400 w-4 h-4" />
                <Input
                  className="pl-10"
                  name="email"
                  type="email"
                  value={formData.email}
                  onChange={handleChange}
                  placeholder="exemple@gmail.com"
                />
              </div>
            </div>

            {/* PASSWORD */}
            <div className="space-y-1">
              <Label>Mot de passe</Label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 text-slate-400 w-4 h-4" />
                <Input
                  className="pl-10 pr-10"
                  name="password"
                  autoComplete="new-password"
                  placeholder="********"
                  type={showPassword ? "text" : "password"}
                  value={formData.password}
                  onChange={handleChange}
                  onFocus={() => setPasswordFocused(true)}
                  onBlur={() => setPasswordFocused(false)}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3 text-slate-400"
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>

              {/* RULES */}
              {(passwordFocused || formData.password) && (
                <ul className="text-xs mt-2 space-y-1">
                  {passwordRules.map(rule => {
                    const ok = rule.test(formData.password);
                    return (
                      <li key={rule.id} className={`flex items-center gap-1 ${ok ? "text-green-600" : "text-red-500"}`}>
                        {ok ? <Check size={12} /> : <X size={12} />}
                        {rule.label}
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>

            {/* CONFIRM */}
            <div className="space-y-1">
              <Label>Confirmer mot de passe</Label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 text-slate-400 w-4 h-4" />
                <Input
                  className="pl-10 pr-10"
                  placeholder="********"
                  name="confirmPassword"
                  type={showConfirmPassword ? "text" : "password"}
                  value={formData.confirmPassword}
                  onChange={handleChange}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-3 text-slate-400"
                >
                  {showConfirmPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {/* SECURITY */}
            <div className="flex items-center gap-2 text-xs text-blue-600 bg-blue-50 p-2 rounded-lg">
              <ShieldCheck size={14} />
              Données sécurisées et chiffrées
            </div>
          </CardContent>

          {/* FOOTER */}
          <CardFooter className="flex flex-col gap-3">
            <Button className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white">
              S'inscrire
            </Button>

            <p className="text-sm text-slate-500">
              Déjà un compte ?{" "}
              <Link className="text-blue-600 hover:underline" to="/login">
                Connexion
              </Link>
            </p>
          </CardFooter>
        </form>
      </Card>
    </div>
  );
}