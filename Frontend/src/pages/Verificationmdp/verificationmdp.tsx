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

import "../../pages/Verificationmdp/vérification.css";

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


  // CHECK EMAIL

  useEffect(() => {
    if (!email) {
      navigate("/login");
    }
  }, [email, navigate]);


  // TIMER (FIXED)

  useEffect(() => {
    if (timeLeft <= 0) return;

    const timer = setInterval(() => {
      setTimeLeft((prev) => prev - 1);
    }, 1000);

    return () => clearInterval(timer);
  }, [timeLeft]);

useEffect(() => {
  if (cooldown <= 0) return;
  const t = setInterval(() => {
    setCooldown((c) => c - 1);
  }, 1000);
  return () => clearInterval(t);
}, [cooldown]);

    const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, "0")}`;
  };

  // ───── VERIFY ─────
  
  const handleVerify = async () => {
    if (otp.length !== 6) {
      setError("Code à 6 chiffres requis");
      return;
    }

    if (timeLeft <= 0) {
      setError("Code expiré");
      return;
    }

    setIsLoading(true);
    setError("");

    try {
       await verifyResetCode({ email, code: otp });

      navigate("/réinitialisermdp", {
        state: {
          email,
          code: otp,
        },
      });

    } catch (err: any) {
      setError(
  typeof err?.detail === "string"
    ? err.detail
    : err?.detail?.[0]?.msg || "Code invalide");
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

  } catch (err: any) {
    setError(
      typeof err?.detail === "string"
        ? err.detail
        : "Erreur lors de l'envoi"
    );
  }
};

  return (
    <div className="verify-password-container">
      <Card className="verify-password-card">

        <CardHeader className="card-header-center">
          <div className="icon-wrapper">
            <Mail className="size-9 text-white" />
          </div>

          <CardTitle>Vérification du code</CardTitle>

          <CardDescription>
            Entrez le code envoyé à
          </CardDescription>

          <p className="text-sm text-orange-600">{email}</p>
        </CardHeader>

        <CardContent className="space-y-6">

          <div className="flex flex-col items-center space-y-4">
            <InputOTP
              maxLength={6}
              value={otp}
              onChange={(value) => {
                setOtp(value);
                setError("");
              }}
              disabled={timeLeft <= 0}
            >
              <InputOTPGroup className="input-otp-container">
                {[...Array(6)].map((_, i) => (
                  <InputOTPSlot key={i} index={i} />
                ))}
              </InputOTPGroup>
            </InputOTP>

            {error && <p className="input-error">{error}</p>}
          </div>

          <div className="timer">
            <Clock className="size-4" />
            {timeLeft > 0 ? (
              <>Code valide pendant <strong>{formatTime(timeLeft)}</strong></>
            ) : (
              <span className="timer-expired">Code expiré</span>
            )}
          </div>

          <div className="security-message">
            <p>
              <strong>Sécurité:</strong> Si ce n'est pas vous, ignorez cet email.
            </p>
          </div>

          <div className="text-center text-sm text-gray-600">
            Code non reçu ?{" "}
           <button
               type="button"
                onClick={handleResend}
                disabled={cooldown > 0}
               className="resend-button"
                    >
                {cooldown > 0 ? `Renvoyer dans ${cooldown}s` : "Renvoyer"}
           </button>
          </div>

        </CardContent>

        <CardFooter className="flex flex-col space-y-3">

          <button
            onClick={handleVerify}
            disabled={isLoading || otp.length !== 6 || timeLeft <= 0}
            className="submit-button"
          >
            {isLoading ? "Vérification..." : "Vérifier le code"}
          </button>

          <Button
            variant="ghost"
            onClick={() => navigate("/login")}
            className="back-button"
          >
            <ArrowLeft className="size-4" />
            Retour
          </Button>

        </CardFooter>

      </Card>
    </div>
  );
}