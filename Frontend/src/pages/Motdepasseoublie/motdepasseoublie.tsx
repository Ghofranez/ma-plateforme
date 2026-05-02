import { useState } from "react";
import { useNavigate } from "react-router";
import { Button } from "../../components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "../../components/ui/card";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import { Mail, ArrowLeft, BellRing, LockKeyhole } from "lucide-react";
import toast from "react-hot-toast";
import { requestPasswordReset } from "../../services/auth.service";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      await requestPasswordReset({ email });

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
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-blue-50 to-purple-50 px-4">

      <Card className="w-full max-w-md shadow-xl border-0 rounded-2xl bg-white/80 backdrop-blur-lg">

        {/* HEADER */}
        <CardHeader className="text-center space-y-3">
          <div className="mx-auto w-14 h-14 flex items-center justify-center rounded-full bg-blue-100">
            <LockKeyhole className="text-blue-600" />
          </div>

          <CardTitle className="text-2xl font-bold text-slate-800">
            Mot de passe oublié ?
          </CardTitle>

          <CardDescription className="text-slate-500">
            Pas de souci, nous vous enverrons un code de réinitialisation
          </CardDescription>
        </CardHeader>

        {/* FORM */}
        <form onSubmit={handleSubmit}>
          <CardContent className="space-y-5">

            {/* EMAIL */}
            <div className="space-y-2">
              <Label>Email</Label>

              <div className="relative">
                <Mail className="absolute left-3 top-3.5 h-4 w-4 text-slate-400" />

                <Input
                  type="email"
                  placeholder="exemple@email.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                  className="pl-10 h-11 rounded-xl border-slate-200 focus:border-blue-500 focus:ring-blue-500"
                />
              </div>
            </div>

            {/* INFO BOX */}
            <div className="flex items-start gap-2 p-3 rounded-xl bg-blue-50 text-blue-700 text-sm">
              <BellRing className="h-4 w-4 mt-0.5" />
              <p>
                <strong>Information :</strong> Un code à 6 chiffres sera envoyé à votre email.
              </p>
            </div>

          </CardContent>

          {/* FOOTER */}
          <CardFooter className="flex flex-col gap-3">

            <Button
              type="submit"
              disabled={isLoading}
              className="w-full h-11 rounded-xl bg-gradient-to-r from-blue-600 to-purple-600 text-white font-medium hover:opacity-90 transition"
            >
              {isLoading ? "Envoi en cours..." : "Envoyer le code"}
            </Button>

            <Button
              type="button"
              variant="ghost"
              onClick={() => navigate("/login")}
              className="w-full flex items-center justify-center gap-2 text-slate-600 hover:text-slate-900"
            >
              <ArrowLeft size={16} />
              Retour à la connexion
            </Button>

          </CardFooter>
        </form>

      </Card>
    </div>
  );
}