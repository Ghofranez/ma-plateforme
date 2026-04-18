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
  User,
  CreditCard,
  Mail,
  Lock,
  Eye,
  EyeOff,
  Check,
  X,
  UserPlus,
  ShieldCheck
} from "lucide-react";
import toast from "react-hot-toast";
import { registerUser } from "../../services/auth.service";

import "../../pages/Registerpage/register.css";

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

  const [formData, setFormData] = useState<FormData>({
    nom: "",
    prenom: "",
    cin: "",
    email: "",
    password: "",
    confirmPassword: "",
  });

  const [cinError, setCinError] = useState("");//gérer erreur CIN

  const navigate = useNavigate();

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

    setFormData(prev => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    if (cinError) return toast.error("CIN invalide");

    if (
      !formData.nom ||
      !formData.prenom ||
      !formData.cin ||
      !formData.email ||
      !formData.password ||
      !formData.confirmPassword
    ) {
      return toast.error("Veuillez remplir tous les champs");
    }

    if (!isPasswordValid) {
      return toast.error("Mot de passe non valide");
    }

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
    <div className="register-container">
      <Card className="register-card">

        {/* HEADER */}
        <CardHeader className="register-header">
          <div className="register-icon-wrapper">
            <div className="register-icon-box">
              <UserPlus className="register-icon" />
            </div>
          </div>

          <CardTitle className="register-title">
            Créer un compte
          </CardTitle>

          <CardDescription className="register-description">
            Rejoignez la plateforme
          </CardDescription>
        </CardHeader>

        <form onSubmit={handleSubmit}>
          <CardContent className="register-content">

            {/* NOM */}
            <div className="register-field">
              <Label>Nom</Label>
              <div className="register-input-wrapper">
                <User className="register-input-icon" />
                <Input name="nom" value={formData.nom}
                placeholder="nom de la famille"
                onChange={handleChange} />
              </div>
            </div>

            {/* PRÉNOM */}
            <div className="register-field">
              <Label>Prénom</Label>
              <div className="register-input-wrapper">
                <User className="register-input-icon" />
                <Input name="prenom" value={formData.prenom}
                 placeholder="prénom"
                onChange={handleChange} />
              </div>
            </div>

            {/* CIN */}
            <div className="register-field">
              <Label>CIN</Label>
              <div className="register-input-wrapper">
                <CreditCard className="register-input-icon" />
                <Input
                  name="cin"
                  placeholder="8 chiffres"
                  value={formData.cin}
                  onChange={handleChange}
                  maxLength={8}
                />
              </div>
              {cinError && <p className="cin-error">{cinError}</p>}
            </div>

            {/* EMAIL */}
            <div className="register-field">
              <Label>Email</Label>
              <div className="register-input-wrapper">
                <Mail className="register-input-icon" />
                <Input
                  name="email"
                  type="email"
                  placeholder="exemple@gmail.com"
                  value={formData.email}
                  onChange={handleChange}
                />
              </div>
            </div>

            {/* PASSWORD */}
            <div className="register-field">
              <Label>Mot de passe</Label>
              <div className="register-input-wrapper">
                <Lock className="register-input-icon" />
                <Input
                  name="password"
                  type={showPassword ? "text" : "password"}
                  placeholder="********"
                  autoComplete="new-password"
                  value={formData.password}
                  onChange={handleChange}
                  onFocus={() => setPasswordFocused(true)}
                  onBlur={() => setPasswordFocused(false)}
                />
                <button type="button" onClick={() => setShowPassword(!showPassword)}>
                  {showPassword ? <EyeOff /> : <Eye />}
                </button>
              </div>

              {(passwordFocused || formData.password) && (
                <ul className="password-rules">
  {passwordRules.map(rule => {
    const isValid = rule.test(formData.password);

    return (
      <li
        key={rule.id}
        className={
          isValid
            ? "rule valid"
            : formData.password
            ? "rule invalid"
            : "rule pending"
        }
      >
        {isValid ? <Check /> : <X />}
        {rule.label}
      </li>
    );
  })}
</ul>
              )}
            </div>

            {/* CONFIRM PASSWORD */}
            <div className="register-field">
              <Label>Confirmer mot de passe</Label>
              <div className="register-input-wrapper">
                <Lock className="register-input-icon" />
                <Input
                  name="confirmPassword"
                  type={showConfirmPassword ? "text" : "password"}
                  placeholder="********"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                />
                <button type="button" onClick={() => setShowConfirmPassword(!showConfirmPassword)}>
                  {showConfirmPassword ? <EyeOff /> : <Eye />}
                </button>
              </div>
            </div>

            {/* SECURITY */}
            <div className="register-security-badge">
              <ShieldCheck size={14} />
              <span>Vos données sont sécurisées</span>
            </div>

          </CardContent>

          <CardFooter className="register-footer">
            <Button type="submit">S'inscrire</Button>

            <div className="register-login-link">
              Déjà un compte ? <Link to="/login">Connexion</Link>
            </div>
          </CardFooter>

        </form>
      </Card>
    </div>
  );
}