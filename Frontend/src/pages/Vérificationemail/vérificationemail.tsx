import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Button } from "../../components/ui/button";
import {
  Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle
} from "../../components/ui/card";
import { Mail, ArrowLeft } from "lucide-react";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot
} from "../../components/ui/input-otp";
import { verifyLoginCode, sendEmailCode } from "../../services/auth.service";
import toast from "react-hot-toast";

export default function VerifyEmail() {
  const [otp, setOtp] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [cooldown, setCooldown] = useState(0);
  const [error, setError] = useState("");

  const navigate = useNavigate();
  const location = useLocation();
  const email = location.state?.email || "";

  useEffect(() => {
    if (!email) navigate("/login");
  }, [email]);

  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setInterval(() => setCooldown(c => c - 1), 1000);
    return () => clearInterval(t);
  }, [cooldown]);

  const handleVerify = async () => {
    if (otp.length !== 6) {
      setError("Code invalide");
      return;
    }

    setIsLoading(true);
    setError("");

    try {
      await verifyLoginCode({ email, code: otp });
      navigate("/accueilpage");
    } catch (err: any) {
      setError(err?.detail || "Code incorrect");
    } finally {
      setIsLoading(false);
    }
  };

  const handleResend = async () => {
    if (cooldown > 0) return;

    try {
      await sendEmailCode(email);
      setOtp("");
      setCooldown(30);
      toast.success("Code renvoyé");
    } catch {
      toast.error("Erreur envoi code");
    }
  };

  const isValid = otp.length === 6;

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-white to-purple-50 px-4">

      <Card className="w-full max-w-md rounded-2xl shadow-xl border border-blue-200">

        {/* HEADER */}
        <CardHeader className="text-center space-y-4">

          {/* ICON */}
          <div className="mx-auto w-16 h-16 rounded-full bg-blue-100 flex items-center justify-center">
            <Mail className="text-blue-600 w-7 h-7" />
          </div>

          <CardTitle className="text-2xl font-semibold text-slate-900">
            Vérification email
          </CardTitle>

          <CardDescription className="text-slate-600">
            Code envoyé à
          </CardDescription>

          <p className="text-blue-600 font-medium text-sm break-all">
            {email}
          </p>
        </CardHeader>

        {/* CONTENT */}
        <CardContent className="space-y-6">

          {/* OTP INPUT */}
          <div className="flex justify-center">
            <InputOTP value={otp} onChange={setOtp} maxLength={6}>
              <InputOTPGroup className="flex gap-3">
                {[0,1,2,3,4,5].map(i => (
                  <InputOTPSlot
                    key={i}
                    index={i}
                    className="w-12 h-12 border rounded-lg text-lg text-center
                               focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                  />
                ))}
              </InputOTPGroup>
            </InputOTP>
          </div>

          {/* ERROR */}
          {error && (
            <p className="text-red-500 text-sm text-center">
              {error}
            </p>
          )}

          {/* RESEND */}
          <div className="text-center">
            <button
              onClick={handleResend}
              disabled={cooldown > 0}
              className="text-blue-600 text-sm hover:underline disabled:text-gray-400"
            >
              {cooldown > 0
                ? `Renvoyer dans ${cooldown}s`
                : "Renvoyer le code"}
            </button>
          </div>

        </CardContent>

        {/* FOOTER */}
        <CardFooter className="flex flex-col gap-3">

          {/* VERIFY BUTTON */}
          <Button
            onClick={handleVerify}
            disabled={!isValid || isLoading}
            className="w-full bg-blue-600 hover:bg-blue-700 text-white rounded-xl py-2"
          >
            {isLoading ? "Vérification..." : "Vérifier"}
          </Button>

          {/* BACK */}
          <Button
            variant="ghost"
            onClick={() => navigate(-1)}
            className="flex items-center gap-2 text-slate-700"
          >
            <ArrowLeft size={16} />
            Retour
          </Button>

        </CardFooter>

      </Card>
    </div>
  );
}