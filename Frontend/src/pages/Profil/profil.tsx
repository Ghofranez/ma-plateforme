import { useState, useEffect } from "react";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Card } from "../../components/ui/card";
import { Label } from "../../components/ui/label";
import { ArrowLeft, Save, Lock, Eye, EyeOff, CheckCircle, Check, X } from "lucide-react";
import { Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { toast } from "react-hot-toast";
import { Sidebar, MenuButton } from "../Sidebar/sidebar";
import {
  updateProfile,
  changePassword,
  getMe,
} from "../../services/auth.service";
import "./profil.css";

const passwordRules = [
  { id: "length", label: "Au moins 8 caractères", test: (p: string) => p.length >= 8 },
  { id: "upper", label: "Majuscule requise", test: (p: string) => /[A-Z]/.test(p) },
  { id: "lower", label: "Minuscule requise", test: (p: string) => /[a-z]/.test(p) },
  { id: "number", label: "Chiffre requis", test: (p: string) => /[0-9]/.test(p) },
  { id: "special", label: "Caractère spécial requis", test: (p: string) => /[!@#$%^&*(),.?\":{}|<>]/.test(p) },
];

export default function Profile() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [updateSuccess, setUpdateSuccess] = useState(false);

  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [passwordFocused, setPasswordFocused] = useState(false);//afficher régles mot de passe

  const [original, setOriginal] = useState({ firstName: "", lastName: "" });//valeurs initiales (pour détecter modification)
  const [isDirty, setIsDirty] = useState(false);//indique changement de nom ou prénom

  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  });

  const isNewPasswordValid = passwordRules.every(rule => rule.test(formData.newPassword));

  useEffect(() => {
    const load = async () => {
      try {
        const data = await getMe();
        const loaded = {
          firstName: data.nom || "",
          lastName: data.prenom || "",
          email: data.email || "",
          currentPassword: "",
          newPassword: "",
          confirmPassword: "",
        };
        setFormData(loaded);
        setOriginal({ firstName: loaded.firstName, lastName: loaded.lastName });
      } catch (err) {
        toast.error("Erreur de chargement du profil");
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => {
      const updated = { ...prev, [name]: value };
      if (name === "firstName" || name === "lastName") {
        setIsDirty(
          updated.firstName !== original.firstName ||
          updated.lastName !== original.lastName
        );
      }
      return updated;
    });
  };

  const cancelProfile = () => {
    setFormData((prev) => ({
      ...prev,
      firstName: original.firstName,
      lastName: original.lastName,
    }));
    setIsDirty(false);
  };

  const saveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await updateProfile({
        nom: formData.firstName,
        prenom: formData.lastName,
      });
      setOriginal({ firstName: formData.firstName, lastName: formData.lastName });
      setIsDirty(false);
      setUpdateSuccess(true);
      toast.success("Profil mis à jour !");
      setTimeout(() => setUpdateSuccess(false), 3000);
    } catch (err) {
      toast.error("Erreur lors de la mise à jour");
    }
  };

  const changePasswordHandler = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isNewPasswordValid) {
      toast.error("Le mot de passe ne respecte pas les critères");
      return;
    }
    if (formData.newPassword !== formData.confirmPassword) {
      toast.error("Les mots de passe ne correspondent pas");
      return;
    }
    try {
      await changePassword({
        current_password: formData.currentPassword,
        new_password: formData.newPassword,
      });
      toast.success("Mot de passe modifié !");
      setFormData((prev) => ({
        ...prev,
        currentPassword: "",
        newPassword: "",
        confirmPassword: "",
      }));
    } catch (err) {
      toast.error("Ancien mot de passe incorrect");
    }
  };

  if (loading) return <div className="profile-loading">Chargement...</div>;

  return (
    <div className="profile-container">
      <MenuButton onClick={() => setIsSidebarOpen(true)} />
      <Sidebar isOpen={isSidebarOpen} onClose={() => setIsSidebarOpen(false)} />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="profile-wrapper"
      >
        <Link to="/accueilpage" className="back-to-home-circle" title="Retour à l'accueil">
           <ArrowLeft size={20} />
        </Link>

        <h1 className="profile-main-title">Paramètres du profil</h1>

        <Card className="profile-card">
          <p className="card-section-label">Informations personnelles</p>
          <AnimatePresence>
            {updateSuccess && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="success-banner"
              >
                <CheckCircle size={16} /> Modification réussie !
              </motion.div>
            )}
          </AnimatePresence>

          <form onSubmit={saveProfile}>
            <div className="profile-name-grid">
              <div className="field-group">
                <Label htmlFor="firstName">Prénom</Label>
                <Input id="firstName" name="firstName" value={formData.firstName} onChange={handleChange} />
              </div>
              <div className="field-group">
                <Label htmlFor="lastName">Nom</Label>
                <Input id="lastName" name="lastName" value={formData.lastName} onChange={handleChange} />
              </div>
            </div>
            <div className="field-group">
              <Label>Email</Label>
              <Input value={formData.email} disabled className="input-disabled" />
            </div>

            {isDirty && (
              <div className="profile-actions">
                <Button type="submit" className="btn-save">
                  <Save size={14} /> Enregistrer
                </Button>
                <Button type="button" className="btn-cancel" onClick={cancelProfile}>
                  Annuler
                </Button>
              </div>
            )}
          </form>
        </Card>

        <Card className="profile-card">
          <p className="card-section-label">Changer Mot de passe</p>
          <form onSubmit={changePasswordHandler}>
            <div className="field-group">
              <Label>Mot de passe actuel</Label>
              <div className="input-wrapper">
                <Input
                  name="currentPassword"
                  type={showCurrentPassword ? "text" : "password"}
                  value={formData.currentPassword}
                  autoComplete="new-password"
                  onChange={handleChange}
                  placeholder="Mot de passe actuel"
                  required
                />
                <button type="button" className="eye-btn" onClick={() => setShowCurrentPassword(!showCurrentPassword)}>
                  {showCurrentPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            <div className="profile-name-grid">
              <div className="field-group">
                <Label>Nouveau mot de passe</Label>
                <div className="input-wrapper">
                  <Input
                    name="newPassword"
                    type={showNewPassword ? "text" : "password"}
                    value={formData.newPassword}
                    onChange={handleChange}
                    onFocus={() => setPasswordFocused(true)}
                    onBlur={() => setPasswordFocused(false)}
                    placeholder="Nouveau mot de passe"
                    required
                  />
                  <button type="button" className="eye-btn" onClick={() => setShowNewPassword(!showNewPassword)}>
                    {showNewPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>

                {/* LES RÈGLES VISUELLES */}
                {(passwordFocused || formData.newPassword) && (
                  <motion.ul
                    initial={{ opacity: 0, y: -10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="password-rules-profile"
                  >
                    {passwordRules.map(rule => {
                      const isValid = rule.test(formData.newPassword);
                      return (
                        <li key={rule.id} className={`rule ${isValid ? "valid" : formData.newPassword ? "invalid" : "pending"}`}>
                          {isValid ? <Check size={12} strokeWidth={3} /> : <X size={12} strokeWidth={3} />}
                          {rule.label}
                        </li>
                      );
                    })}
                  </motion.ul>
                )}
              </div>

              <div className="field-group">
                <Label>Confirmer</Label>
                <div className="input-wrapper">
                  <Input
                    name="confirmPassword"
                    type={showConfirmPassword ? "text" : "password"}
                    value={formData.confirmPassword}
                    onChange={handleChange}
                    placeholder="Confirmez"
                    required
                  />
                  <button type="button" className="eye-btn" onClick={() => setShowConfirmPassword(!showConfirmPassword)}>
                    {showConfirmPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>
            </div>

            <Button type="submit" className="btn-pwd" disabled={!isNewPasswordValid}>
              <Lock size={14} /> Mettre à jour le mot de passe
            </Button>
          </form>
        </Card>
      </motion.div>
    </div>
  );
}