import { useState } from "react";
import { useNavigate} from "react-router";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import { Card,CardContent, CardDescription, CardFooter, CardHeader, CardTitle} from "../../components/ui/card";
import { Mail, ArrowLeft, BellRing, LockKeyhole } from "lucide-react";
import toast from "react-hot-toast";
import "../../pages/Motdepasseoublie/motdepasseoublie.css";
import { requestPasswordReset } from "../../services/auth.service";


export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
  e.preventDefault();
  setIsLoading(true);

  try {
    await requestPasswordReset({email});

    navigate("/verificationmdp", {
      state: { email },
    });

  } catch (err: any) {
    toast.error(err?.detail || "Erreur lors de l'envoi du code");
  } finally {
    setIsLoading(false);
  }
};
  return (
    <div className="forgot-container">
      <Card className="forgot-card">

        <CardHeader className="forgot-header">
          <div className="forgot-icon-wrapper">
            <div className="forgot-icon-box">
              <LockKeyhole className="forgot-icon" />
            </div>
          </div>
          <CardTitle className="forgot-title">Mot de passe oublié?</CardTitle>
          <CardDescription className="forgot-description">
            Pas de souci, nous vous enverrons un code de réinitialisation
          </CardDescription>
        </CardHeader>

        <form onSubmit={handleSubmit}>
          <CardContent className="forgot-content">

            <div className="forgot-field">
              <Label htmlFor="email">Adresse email</Label>
              <div className="forgot-input-wrapper">
                <Mail className="forgot-input-icon" />
                <Input
                  id="email"
                  type="email"
                  placeholder="exemple@email.com"
                  className="forgot-input"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </div>
            </div>

            <div className="forgot-info-box">
              <p className="forgot-info-text">
                <strong> <BellRing className="forgot-bellring"/> Information:</strong> Un code de vérification à 6 chiffres sera envoyé à votre adresse email.
              </p>
            </div>

          </CardContent>

          <CardFooter className="forgot-footer">

            <Button
              type="submit"
              disabled={isLoading}
              className="forgot-btn-submit"
            >
             {isLoading ? "Envoi en cours..." : "Envoyer le code"}

            </Button>

            <Button
              type="button"
              variant="ghost"
              onClick={() => navigate("/login")}
              className="forgot-btn-back"
            >
              <ArrowLeft className="forgot-btn-back-icon" />
              Retour à la connexion
            </Button>
          </CardFooter>
        </form>

      </Card>
    </div>
  );
}