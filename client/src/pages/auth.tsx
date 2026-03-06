import { useState } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useTranslation } from "react-i18next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Loader2 } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { AegisLogoLarge } from "@/components/logo";
import { LanguageSwitcher } from "@/components/language-switcher";

export default function AuthPage() {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const { loginMutation, registerMutation } = useAuth();
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

  return (
    <div className="min-h-screen flex items-center justify-center bg-background tactical-grid p-4">
      <div className="absolute top-0 start-0 end-0 h-8 bg-primary/10 border-b border-primary/20 flex items-center justify-center">
        <span className="text-[10px] font-mono text-primary/60 tracking-[0.4em] uppercase">
          {t("auth.authorizedOnly")}
        </span>
      </div>

      <div className="absolute top-10 end-4">
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
                  minLength={6}
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
                className="text-[10px] text-primary hover:underline tracking-wider uppercase"
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
