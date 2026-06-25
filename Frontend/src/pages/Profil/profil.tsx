import { useState, useEffect } from "react";
import { ArrowLeft, Save, Lock, Eye, EyeOff, CheckCircle, Check, X, Mail } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { toast } from "react-hot-toast";
import { updateProfile, changePassword, getMe,requestEmailChange } from "../../services/auth.service";


const passwordRules = [
  { id: "length",  label: "Au moins 8 caractères",   test: (p: string) => p.length >= 8 },
  { id: "upper",   label: "Majuscule requise",        test: (p: string) => /[A-Z]/.test(p) },
  { id: "lower",   label: "Minuscule requise",        test: (p: string) => /[a-z]/.test(p) },
  { id: "number",  label: "Chiffre requis",           test: (p: string) => /[0-9]/.test(p) },
  { id: "special", label: "Caractère spécial requis", test: (p: string) => /[!@#$%^&*(),.?\":{}|<>]/.test(p) },
];

export default function Profile() {
  const navigate = useNavigate();
  const [loading,             setLoading]             = useState(true);
  const [updateSuccess,       setUpdateSuccess]       = useState(false);
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword,     setShowNewPassword]     = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [passwordFocused,     setPasswordFocused]     = useState(false);
  const [original,            setOriginal]            = useState({ firstName: "", lastName: "",phone:"" });
  const [isDirty,             setIsDirty]             = useState(false);

  // ── État changement email ──
  const [showEmailForm,    setShowEmailForm]    = useState(false);
  const [emailData,        setEmailData]        = useState({ new_email: "", password: "" });
  const [showEmailPassword,setShowEmailPassword]= useState(false);
  const [emailLoading,     setEmailLoading]     = useState(false);

  const [formData, setFormData] = useState({
    firstName: "", lastName: "", email: "",
    phone:"",
    currentPassword: "", newPassword: "", confirmPassword: "",
  });

  const isNewPasswordValid = passwordRules.every(rule => rule.test(formData.newPassword));

  useEffect(() => {
    (async () => {
      try {
        const data = await getMe() as any;
        const loaded = {
          firstName: data.nom || "", lastName: data.prenom || "",
          email: data.email || "", phone: data.phone || "",currentPassword: "", newPassword: "", confirmPassword: "",
        };
        setFormData(loaded);
        setOriginal({ firstName: loaded.firstName, lastName: loaded.lastName , phone: loaded.phone});
      } catch { toast.error("Erreur de chargement du profil"); }
      finally { setLoading(false); }
    })();
  }, []);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => {
      const updated = { ...prev, [name]: value };
     if (name === "firstName" || name === "lastName" || name === "phone") {
        setIsDirty(
          updated.firstName !== original.firstName ||
          updated.lastName  !== original.lastName  ||
          updated.phone       !== original.phone
     );
    }
      return updated;
    });
  };

  const cancelProfile = () => {
    setFormData(prev => ({ ...prev, firstName: original.firstName, lastName: original.lastName }));
    setIsDirty(false);
  };

  const saveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await updateProfile({ nom: formData.firstName, prenom: formData.lastName, phone: formData.phone });
      setOriginal({ firstName: formData.firstName, lastName: formData.lastName ,phone: formData.phone });
      setIsDirty(false);
      setUpdateSuccess(true);
      toast.success("Profil mis à jour !");
      setTimeout(() => setUpdateSuccess(false), 3000);
    } catch { toast.error("Erreur lors de la mise à jour"); }
  };

  const changePasswordHandler = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isNewPasswordValid) { toast.error("Le mot de passe ne respecte pas les critères"); return; }
    if (formData.newPassword !== formData.confirmPassword) { toast.error("Les mots de passe ne correspondent pas"); return; }
    try {
      await changePassword({ current_password: formData.currentPassword, new_password: formData.newPassword });
      toast.success("Mot de passe modifié !");
      setFormData(prev => ({ ...prev, currentPassword: "", newPassword: "", confirmPassword: "" }));
    } catch { toast.error("Ancien mot de passe incorrect"); }
  };

  // ── Handler changement email ──
  const changeEmailHandler = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailData.new_email || !emailData.password) {
        toast.error("Remplissez tous les champs");
        return;
    }
    setEmailLoading(true);
    try {
        await requestEmailChange(emailData);
        toast.success("Un email de confirmation a été envoyé à votre adresse actuelle !");
        setShowEmailForm(false);
        setEmailData({ new_email: "", password: "" });
    } catch (err: any) {
        toast.error(err?.response?.data?.detail || "Erreur lors de la demande");
    } finally {
        setEmailLoading(false);
    }
};

  if (loading) return (
    <div className="flex items-center justify-center min-h-screen bg-slate-50">
      <div className="text-sm text-gray-400">Chargement...</div>
    </div>
  );

  return (
    <div className="min-h-screen bg-slate-50 pb-12">

      {/* Header sticky */}
      <div className="sticky top-0 z-10 bg-white/90 backdrop-blur border-b border-gray-100 px-4 py-3 flex items-center gap-3">
        <button
          onClick={() => navigate("/accueilpage")}
          className="flex items-center justify-center w-8 h-8 rounded-xl hover:bg-gray-100 transition-colors text-gray-500 shrink-0"
        >
          <ArrowLeft size={18} />
        </button>
        <div className="flex-1 text-center">
          <h1 className="font-black text-gray-900 text-base leading-tight">Paramètres du profil</h1>
        </div>
        <div className="w-8 h-8" />
      </div>

      <div className="mx-4 mt-5 flex flex-col gap-4">

        {/* ── Carte infos personnelles ── */}
        <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-50">
            <p className="text-xs font-black uppercase tracking-widest text-gray-400">Informations personnelles</p>
          </div>

          <AnimatePresence>
            {updateSuccess && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="flex items-center gap-2 px-5 py-3 bg-green-50 border-b border-green-100 text-green-700 text-sm font-semibold"
              >
                <CheckCircle size={15} /> Modification réussie !
              </motion.div>
            )}
          </AnimatePresence>

          <form onSubmit={saveProfile} className="px-5 py-4 flex flex-col gap-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-gray-500">Prénom</label>
                <input
                  name="firstName" value={formData.firstName} onChange={handleChange}
                  className="w-full px-3 py-2.5 text-sm bg-slate-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-300 focus:bg-white transition"
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-gray-500">Nom</label>
                <input
                  name="lastName" value={formData.lastName} onChange={handleChange}
                  className="w-full px-3 py-2.5 text-sm bg-slate-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-300 focus:bg-white transition"
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-gray-500">Numéro de téléphone</label>
                <input
                   name="phone"
                   value={formData.phone}
                   onChange={handleChange}
                   placeholder="Ex: 12345678"
                   maxLength={8}
                   className="w-full px-3 py-2.5 text-sm bg-slate-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-300 focus:bg-white transition"
                 />
              </div>
            </div>

            {/* Email affiché + bouton changer */}
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-semibold text-gray-500">Email</label>
              <div className="flex gap-2 items-center">
                <input
                  value={formData.email} disabled
                  className="flex-1 px-3 py-2.5 text-sm bg-gray-100 border border-gray-200 rounded-xl text-gray-400 cursor-not-allowed"
                />
                <button
                  type="button"
                  onClick={() => setShowEmailForm(!showEmailForm)}
                  className="px-3 py-2.5 rounded-xl text-xs font-bold text-indigo-600 border border-indigo-200 bg-indigo-50 hover:bg-indigo-100 transition whitespace-nowrap"
                >
                  {showEmailForm ? "Annuler" : "Changer"}
                </button>
              </div>
            </div>

            {isDirty && (
              <div className="flex gap-2">
                <button
                  type="submit"
                  className="flex-1 flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-bold text-white transition-all"
                  style={{ background: "linear-gradient(135deg, #6366f1, #8b5cf6)" }}
                >
                  <Save size={14} /> Enregistrer
                </button>
                <button
                  type="button" onClick={cancelProfile}
                  className="flex-1 py-2.5 rounded-xl text-sm font-bold text-gray-500 bg-gray-100 hover:bg-gray-200 transition-all"
                >
                  Annuler
                </button>
              </div>
            )}
          </form>
        </div>

        {/* ── Carte changement email ── */}
        <AnimatePresence>
          {showEmailForm && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="bg-white rounded-2xl border border-indigo-100 shadow-sm overflow-hidden"
            >
              <div className="px-5 py-4 border-b border-gray-50">
                <p className="text-xs font-black uppercase tracking-widest text-gray-400">Changer l'email</p>
              </div>

              {/* Avertissement */}
              <div className="mx-5 mt-4 flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-xl p-3">
                <Mail size={14} className="text-amber-500 mt-0.5 shrink-0" />
                <p className="text-xs text-amber-700 font-medium">
                  Après le changement, vous serez déconnecté et devrez vous reconnecter avec votre nouvel email. Vos données sont conservées.
                </p>
              </div>

              <form onSubmit={changeEmailHandler} className="px-5 py-4 flex flex-col gap-4">
                <div className="flex flex-col gap-1.5">
                  <label className="text-xs font-semibold text-gray-500">Nouvel email</label>
                  <input
                    type="email"
                    value={emailData.new_email}
                    onChange={e => setEmailData(prev => ({ ...prev, new_email: e.target.value }))}
                    placeholder="nouveau@email.com"
                    className="w-full px-3 py-2.5 text-sm bg-slate-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-300 focus:bg-white transition"
                  />
                </div>

                <div className="flex flex-col gap-1.5">
                  <label className="text-xs font-semibold text-gray-500">Confirmez avec votre mot de passe</label>
                  <div className="relative">
                    <input
                      type={showEmailPassword ? "text" : "password"}
                      value={emailData.password}
                      onChange={e => setEmailData(prev => ({ ...prev, password: e.target.value }))}
                      placeholder="Mot de passe actuel"
                      className="w-full px-3 pr-10 py-2.5 text-sm bg-slate-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-300 focus:bg-white transition"
                    />
                    <button type="button" onClick={() => setShowEmailPassword(!showEmailPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                      {showEmailPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={emailLoading || !emailData.new_email || !emailData.password}
                  className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-bold text-white transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  style={{ background: "linear-gradient(135deg, #6366f1, #8b5cf6)" }}
                >
                  <Mail size={14} />
                  {emailLoading ? "Modification..." : "Confirmer le changement"}
                </button>
              </form>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── Carte mot de passe ── */}
        <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-50">
            <p className="text-xs font-black uppercase tracking-widest text-gray-400">Changer le mot de passe</p>
          </div>

          <form onSubmit={changePasswordHandler} className="px-5 py-4 flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <label className="text-xs font-semibold text-gray-500">Mot de passe actuel</label>
              <div className="relative">
                <input
                  name="currentPassword" type={showCurrentPassword ? "text" : "password"}
                  value={formData.currentPassword} onChange={handleChange}
                  autoComplete="new-password" placeholder="Mot de passe actuel" required
                  className="w-full px-3 pr-10 py-2.5 text-sm bg-slate-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-300 focus:bg-white transition"
                />
                <button type="button" onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                  {showCurrentPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-gray-500">Nouveau mot de passe</label>
                <div className="relative">
                  <input
                    name="newPassword" type={showNewPassword ? "text" : "password"}
                    value={formData.newPassword} onChange={handleChange}
                    onFocus={() => setPasswordFocused(true)}
                    onBlur={() => setPasswordFocused(false)}
                    placeholder="Nouveau mot de passe" required
                    className="w-full px-3 pr-10 py-2.5 text-sm bg-slate-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-300 focus:bg-white transition"
                  />
                  <button type="button" onClick={() => setShowNewPassword(!showNewPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                    {showNewPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-xs font-semibold text-gray-500">Confirmer</label>
                <div className="relative">
                  <input
                    name="confirmPassword" type={showConfirmPassword ? "text" : "password"}
                    value={formData.confirmPassword} onChange={handleChange}
                    placeholder="Confirmez" required
                    className="w-full px-3 pr-10 py-2.5 text-sm bg-slate-50 border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-300 focus:bg-white transition"
                  />
                  <button type="button" onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                    {showConfirmPassword ? <EyeOff size={15} /> : <Eye size={15} />}
                  </button>
                </div>
              </div>
            </div>

            {(passwordFocused || formData.newPassword) && (
              <motion.ul
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                className="flex flex-col gap-1.5 bg-slate-50 rounded-xl p-3 border border-gray-100"
              >
                {passwordRules.map(rule => {
                  const isValid = rule.test(formData.newPassword);
                  return (
                    <li key={rule.id} className={`flex items-center gap-2 text-xs font-medium ${
                      isValid ? "text-green-600" : formData.newPassword ? "text-red-500" : "text-gray-400"
                    }`}>
                      {isValid
                        ? <Check size={12} strokeWidth={3} className="text-green-500" />
                        : <X size={12} strokeWidth={3} className="text-red-400" />
                      }
                      {rule.label}
                    </li>
                  );
                })}
              </motion.ul>
            )}

            <button
              type="submit" disabled={!isNewPasswordValid}
              className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-sm font-bold text-white transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              style={{ background: "linear-gradient(135deg, #6366f1, #8b5cf6)" }}
            >
              <Lock size={14} /> Mettre à jour le mot de passe
            </button>
          </form>
        </div>

      </div>
    </div>
  );
}