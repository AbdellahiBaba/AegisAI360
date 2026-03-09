import { useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Loader2, ShieldCheck } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { AegisLogoLarge } from "@/components/logo";
import { LanguageSwitcher } from "@/components/language-switcher";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

export default function AuthPage() {
  useDocumentTitle("Sign In");
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [isVerifying2FA, setIsVerifying2FA] = useState(false);
  const { loginMutation, registerMutation, twoFactorChallenge, verifyTwoFactor, clearTwoFactorChallenge } = useAuth();
  const { toast } = useToast();
  const { t } = useTranslation();

  const mutation = isLogin ? loginMutation : registerMutation;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    mutation.mutate(
      { username, password },
      {
        onError: (error: Error) => {
          toast({
            title: isLogin ? t("auth.loginFailed") : t("auth.registrationFailed"),
            description: error.message,
            variant: "destructive",
          });
        },
      },
    );
  };

  const handleTwoFactorSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsVerifying2FA(true);
    try {
      await verifyTwoFactor(totpCode);
    } catch (error: any) {
      toast({
        title: "Verification Failed",
        description: error.message || "Invalid authentication code",
        variant: "destructive",
      });
    } finally {
      setIsVerifying2FA(false);
      setTotpCode("");
    }
  };

  const handleCancelTwoFactor = () => {
    clearTwoFactorChallenge();
    setTotpCode("");
  };

  if (twoFactorChallenge) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background grid-pattern p-4">
        <div className="absolute top-0 start-0 end-0 h-8 bg-primary/10 border-b border-primary/20 flex items-center justify-center px-2">
          <span className="text-[10px] font-mono text-primary/60 tracking-[0.2em] sm:tracking-[0.4em] uppercase truncate">
            {t("auth.authorizedOnly")}
          </span>
        </div>

        <div className="w-full max-w-md space-y-8">
          <AegisLogoLarge />

          <Card className="border-primary/10">
            <CardHeader className="pb-4">
              <div className="flex justify-center mb-3">
                <ShieldCheck className="w-10 h-10 text-primary" />
              </div>
              <CardTitle className="text-center text-xs uppercase tracking-[0.3em] text-muted-foreground">
                Two-Factor Authentication
              </CardTitle>
              <p className="text-center text-xs text-muted-foreground mt-2">
                Enter the 6-digit code from your authenticator app
              </p>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleTwoFactorSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="totp-code" className="text-[10px] uppercase tracking-wider">Authentication Code</Label>
                  <Input
                    id="totp-code"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                    placeholder="000000"
                    required
                    maxLength={6}
                    pattern="[0-9]{6}"
                    className="font-mono text-center text-2xl tracking-[0.5em] h-14"
                    autoFocus
                    autoComplete="one-time-code"
                    data-testid="input-totp-code"
                  />
                </div>
                <Button
                  type="submit"
                  className="w-full tracking-wider uppercase text-xs"
                  disabled={isVerifying2FA || totpCode.length !== 6}
                  data-testid="button-verify-totp"
                >
                  {isVerifying2FA ? (
                    <Loader2 className="w-4 h-4 animate-spin me-2" />
                  ) : null}
                  Verify
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  className="w-full text-xs text-muted-foreground min-h-[44px]"
                  onClick={handleCancelTwoFactor}
                  data-testid="button-cancel-totp"
                >
                  Cancel
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background grid-pattern p-4">
      <div className="absolute top-0 start-0 end-0 h-8 bg-primary/10 border-b border-primary/20 flex items-center justify-center px-2">
        <span className="text-[10px] font-mono text-primary/60 tracking-[0.2em] sm:tracking-[0.4em] uppercase truncate">
          {t("auth.authorizedOnly")}
        </span>
      </div>

      <div className="absolute top-10 end-2 sm:end-4">
        <LanguageSwitcher />
      </div>

      <div className="w-full max-w-md space-y-8">
        <AegisLogoLarge />

        <Card className="border-primary/10">
          <CardHeader className="pb-4">
            <CardTitle className="text-center text-xs uppercase tracking-[0.3em] text-muted-foreground">
              {isLogin ? t("auth.operatorAuth") : t("auth.registerOperator")}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username" className="text-[10px] uppercase tracking-wider">{t("auth.callsign")}</Label>
                <Input
                  id="username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder={t("auth.enterCallsign")}
                  required
                  className="font-mono"
                  data-testid="input-username"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password" className="text-[10px] uppercase tracking-wider">{t("auth.passphrase")}</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder={t("auth.enterPassphrase")}
                  required
                  minLength={8}
                  className="font-mono"
                  data-testid="input-password"
                />
              </div>
              <Button
                type="submit"
                className="w-full tracking-wider uppercase text-xs"
                disabled={mutation.isPending}
                data-testid="button-auth-submit"
              >
                {mutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin me-2" />
                ) : null}
                {isLogin ? t("auth.authenticate") : t("auth.register")}
              </Button>
            </form>
            <div className="mt-4 text-center">
              <button
                type="button"
                onClick={() => setIsLogin(!isLogin)}
                className="text-[10px] text-primary hover:underline tracking-wider uppercase min-h-[44px] px-4 py-2 inline-flex items-center justify-center"
                data-testid="button-toggle-auth-mode"
              >
                {isLogin
                  ? t("auth.requestAccess")
                  : t("auth.existingOperator")}
              </button>
            </div>
          </CardContent>
        </Card>

        <div className="text-center">
          <p className="text-[9px] text-muted-foreground/50 font-mono tracking-wider">
            {t("auth.platformVersion")}
          </p>
        </div>
      </div>
    </div>
  );
}
