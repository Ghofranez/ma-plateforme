import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Button } from "../../components/ui/button";
import {
  Card, CardContent, CardDescription,
  CardFooter, CardHeader, CardTitle
} from "../../components/ui/card";
import { Mail, ArrowLeft, Clock } from "lucide-react";
import {
  InputOTP,
  InputOTPGroup,
  InputOTPSlot
} from "../../components/ui/input-otp";

import {
  verifyResetCode,
  requestPasswordReset
} from "../../services/auth.service";

export default function VerifyPasswordReset() {
  const [otp, setOtp] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [timeLeft, setTimeLeft] = useState(600);
  const [cooldown, setCooldown] = useState(0);

  const navigate = useNavigate();
  const location = useLocation();
  const email = location.state?.email || "";

  useEffect(() => {
    if (!email) navigate("/login");
  }, [email]);

  useEffect(() => {
    if (timeLeft <= 0) return;
    const timer = setInterval(() => setTimeLeft(p => p - 1), 1000);
    return () => clearInterval(timer);
  }, [timeLeft]);

  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setInterval(() => setCooldown(c => c - 1), 1000);
    return () => clearInterval(t);
  }, [cooldown]);

  const formatTime = (s: number) => {
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return `${m}:${sec.toString().padStart(2, "0")}`;
  };

  const handleVerify = async () => {
    if (otp.length !== 6) return setError("Code invalide");
    if (timeLeft <= 0) return setError("Code expiré");

    setIsLoading(true);
    setError("");

    try {
      await verifyResetCode({ email, code: otp });
      navigate("/réinitialisermdp", { state: { email, code: otp } });
    } catch (err: any) {
      setError(err?.detail || "Code incorrect");
    } finally {
      setIsLoading(false);
    }
  };

  const handleResend = async () => {
    if (cooldown > 0) return;

    try {
      await requestPasswordReset({ email });
      setOtp("");
      setError("");
      setTimeLeft(600);
      setCooldown(30);
    } catch {
      setError("Erreur lors de l'envoi");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-blue-50/30 to-purple-50/20 px-4">

      <Card className="w-full max-w-md shadow-xl border border-slate-200 bg-white/80 backdrop-blur-md rounded-2xl">

        {/* HEADER */}
        <CardHeader className="text-center space-y-3">

          {/* ICON */}
          <div className="mx-auto w-14 h-14 flex items-center justify-center rounded-full bg-gradient-to-r from-blue-600 to-purple-600 shadow-md">
            <Mail className="text-white w-6 h-6" />
          </div>

          <CardTitle className="text-2xl font-semibold text-slate-900">
            Vérification du code
          </CardTitle>

          <CardDescription className="text-slate-600">
            Entrez le code envoyé à
          </CardDescription>

          <p className="text-sm text-blue-600 font-medium break-all">
            {email}
          </p>
        </CardHeader>

        {/* CONTENT */}
        <CardContent className="space-y-5">

          {/* OTP */}
          <div className="flex justify-center">
            <InputOTP
              maxLength={6}
              value={otp}
              onChange={(v) => {
                setOtp(v);
                setError("");
              }}
              disabled={timeLeft <= 0}
            >
              <InputOTPGroup className="flex gap-3">
                {[0,1,2,3,4,5].map(i => (
                  <InputOTPSlot
                    key={i}
                    index={i}
                    className="w-11 h-12 text-lg text-center border rounded-md
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

          {/* TIMER */}
          <div className="flex items-center justify-center gap-2 text-sm text-slate-600">
            <Clock className="w-4 h-4" />
            {timeLeft > 0 ? (
              <span>
                Code valide pendant{" "}
                <strong className="text-blue-600">{formatTime(timeLeft)}</strong>
              </span>
            ) : (
              <span className="text-red-500">Code expiré</span>
            )}
          </div>

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

          <Button
            onClick={handleVerify}
            disabled={isLoading || otp.length !== 6 || timeLeft <= 0}
            className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white rounded-xl hover:opacity-90"
          >
            {isLoading ? "Vérification..." : "Vérifier le code"}
          </Button>

          <Button
            variant="ghost"
            onClick={() => navigate("/login")}
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