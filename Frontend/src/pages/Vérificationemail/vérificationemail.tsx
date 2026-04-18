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
import "./vérificationemail.css";

export default function VerifyEmail() {
  const [otp, setOtp] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isResending, setIsResending] = useState(false);
  const [error, setError] = useState("");
  const [timeLeft, setTimeLeft] = useState(600);
  const [cooldown, setCooldown] = useState(0);

  const navigate = useNavigate();
  const location = useLocation();

  const email = location.state?.email || "";

 useEffect(() => {
  if (!email) {
    navigate("/login");
  }
}, [email, navigate]);


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
      await verifyLoginCode({ email, code: otp }) as any;

      navigate("/accueilpage");

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
    await sendEmailCode(email);
    setOtp("");
    toast.success("Nouveau code envoyé");
    setError("");
    setTimeLeft(600);
    setCooldown(30);
  } catch (err: any) {
  setError(
    err?.response?.data?.detail ||
    "Erreur lors de l'envoi"
   );
  }
   finally {
    setIsResending(false);

 }
};

  const isOtpValid = /^\d{6}$/.test(otp);

  return (
    <div className="verify-container">
      <Card className="verify-card">

        <CardHeader className="verify-header">
          <div className="verify-icon-wrapper">
            <div className="verify-icon-box">
              <Mail className="verify-icon" />
            </div>
          </div>

          <CardTitle className="verify-title">
            Vérification email
          </CardTitle>

          <CardDescription className="verify-description">
            Code envoyé à
          </CardDescription>

          <p className="verify-email-label">{email}</p>
        </CardHeader>

        <CardContent className="verify-content">

          <InputOTP
            maxLength={6}
            value={otp}
            onChange={(value) => {
              setOtp(value);
              setError("");
            }}
          >
            <InputOTPGroup>
              {[0,1,2,3,4,5].map((i) => (
                <InputOTPSlot key={i} index={i} />
              ))}
            </InputOTPGroup>
          </InputOTP>

          {error && <p className="verify-error">{error}</p>}


          <div style={{ marginTop: 15, textAlign: "center" }}>
            <button
              onClick={handleResend}
              disabled={isResending || cooldown > 0}
              className="verify-resend-btn"
            >
              {cooldown > 0
                ? `Renvoyer dans ${cooldown}s`
                : isResending
                ? "Envoi..."
                : "Renvoyer le code"}
            </button>
          </div>

        </CardContent>

        <CardFooter className="verify-footer">

          <Button
            onClick={handleVerify}
            disabled={isLoading || !isOtpValid}
            className="verify-btn-submit"
          >
            {isLoading ? "Vérification..." : "Vérifier"}
          </Button>

          <Button variant="ghost" onClick={() => navigate(-1)}>
            <ArrowLeft />
            Retour
          </Button>

        </CardFooter>

      </Card>
    </div>
  );
}