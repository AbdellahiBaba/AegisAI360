import { useState } from "react";
import { Link } from "wouter";
import { useTranslation } from "react-i18next";
import { AegisLogo } from "@/components/logo";
import { LanguageSwitcher } from "@/components/language-switcher";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet";
import { Menu } from "lucide-react";

export function PublicLayout({ children }: { children: React.ReactNode }) {
  const { t } = useTranslation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className="min-h-screen flex flex-col bg-background text-foreground">
      <header className="sticky top-0 z-50 border-b border-primary/10 bg-background/95 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-4 px-4 sm:px-6 py-3">
          <Link href="/" data-testid="link-home">
            <AegisLogo size={32} />
          </Link>
          <nav className="hidden md:flex items-center gap-6 flex-wrap">
            <Link href="/features" className="text-sm text-muted-foreground hover:text-primary transition-colors" data-testid="link-features">
              {t("landing.navFeatures")}
            </Link>
            <Link href="/pricing" className="text-sm text-muted-foreground hover:text-primary transition-colors" data-testid="link-pricing">
              {t("landing.navPricing")}
            </Link>
            <Link href="/about" className="text-sm text-muted-foreground hover:text-primary transition-colors" data-testid="link-about">
              {t("landing.navAbout")}
            </Link>
            <Link href="/security" className="text-sm text-muted-foreground hover:text-primary transition-colors" data-testid="link-security">
              {t("public.navSecurity")}
            </Link>
            <Link href="/faq" className="text-sm text-muted-foreground hover:text-primary transition-colors" data-testid="link-faq">
              {t("public.navFaq")}
            </Link>
            <Link href="/contact" className="text-sm text-muted-foreground hover:text-primary transition-colors" data-testid="link-contact">
              {t("public.navContact")}
            </Link>
            <Link href="/guide" className="text-sm text-muted-foreground hover:text-primary transition-colors" data-testid="link-guide">
              {t("public.navGuide")}
            </Link>
          </nav>
          <div className="flex items-center gap-2">
            <LanguageSwitcher />
            <Link href="/auth" className="hidden sm:inline-flex">
              <Button variant="default" size="sm" data-testid="button-login">
                {t("landing.login")}
              </Button>
            </Link>
            <Button
              variant="ghost"
              size="icon"
              className="md:hidden h-9 w-9"
              onClick={() => setMobileMenuOpen(true)}
              data-testid="button-mobile-menu-public"
            >
              <Menu className="h-5 w-5" />
            </Button>
          </div>
        </div>
      </header>

      <Sheet open={mobileMenuOpen} onOpenChange={setMobileMenuOpen}>
        <SheetContent side="right" className="w-[280px] bg-background border-border/50 p-0">
          <SheetHeader className="sr-only">
            <SheetTitle>Navigation</SheetTitle>
            <SheetDescription>Mobile navigation menu</SheetDescription>
          </SheetHeader>
          <div className="flex flex-col h-full">
            <div className="flex items-center justify-between p-4 border-b border-border/30">
              <AegisLogo size={28} />
            </div>
            <nav className="flex flex-col gap-1 p-4 flex-1">
              <Link href="/features" onClick={() => setMobileMenuOpen(false)} className="flex items-center px-3 py-3 text-sm text-muted-foreground hover:text-primary hover:bg-primary/5 rounded-md transition-colors" data-testid="mobile-link-features">
                {t("landing.navFeatures")}
              </Link>
              <Link href="/pricing" onClick={() => setMobileMenuOpen(false)} className="flex items-center px-3 py-3 text-sm text-muted-foreground hover:text-primary hover:bg-primary/5 rounded-md transition-colors" data-testid="mobile-link-pricing">
                {t("landing.navPricing")}
              </Link>
              <Link href="/about" onClick={() => setMobileMenuOpen(false)} className="flex items-center px-3 py-3 text-sm text-muted-foreground hover:text-primary hover:bg-primary/5 rounded-md transition-colors" data-testid="mobile-link-about">
                {t("landing.navAbout")}
              </Link>
              <Link href="/security" onClick={() => setMobileMenuOpen(false)} className="flex items-center px-3 py-3 text-sm text-muted-foreground hover:text-primary hover:bg-primary/5 rounded-md transition-colors" data-testid="mobile-link-security">
                {t("public.navSecurity")}
              </Link>
              <Link href="/faq" onClick={() => setMobileMenuOpen(false)} className="flex items-center px-3 py-3 text-sm text-muted-foreground hover:text-primary hover:bg-primary/5 rounded-md transition-colors" data-testid="mobile-link-faq">
                {t("public.navFaq")}
              </Link>
              <Link href="/contact" onClick={() => setMobileMenuOpen(false)} className="flex items-center px-3 py-3 text-sm text-muted-foreground hover:text-primary hover:bg-primary/5 rounded-md transition-colors" data-testid="mobile-link-contact">
                {t("public.navContact")}
              </Link>
              <Link href="/guide" onClick={() => setMobileMenuOpen(false)} className="flex items-center px-3 py-3 text-sm text-muted-foreground hover:text-primary hover:bg-primary/5 rounded-md transition-colors" data-testid="mobile-link-guide">
                {t("public.navGuide")}
              </Link>
            </nav>
            <div className="p-4 border-t border-border/30">
              <Link href="/auth" onClick={() => setMobileMenuOpen(false)}>
                <Button className="w-full text-sm" data-testid="mobile-button-login">
                  {t("landing.login")}
                </Button>
              </Link>
            </div>
          </div>
        </SheetContent>
      </Sheet>

      <main className="flex-1">
        {children}
      </main>

      <footer className="border-t border-primary/10 bg-background">
        <div className="max-w-7xl mx-auto px-6 py-10">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6">
            <div className="flex flex-col gap-3">
              <AegisLogo size={28} />
              <p className="text-xs text-muted-foreground">
                {t("landing.copyright")}
              </p>
            </div>
            <nav className="flex items-center gap-6 flex-wrap">
              <Link href="/privacy" className="text-xs text-muted-foreground hover:text-primary transition-colors" data-testid="link-privacy">
                {t("landing.privacyPolicy")}
              </Link>
              <Link href="/terms" className="text-xs text-muted-foreground hover:text-primary transition-colors" data-testid="link-terms">
                {t("landing.termsOfService")}
              </Link>
              <Link href="/refund" className="text-xs text-muted-foreground hover:text-primary transition-colors" data-testid="link-refund">
                {t("landing.refundPolicy")}
              </Link>
              <Link href="/contact" className="text-xs text-muted-foreground hover:text-primary transition-colors" data-testid="link-footer-contact">
                {t("public.navContact")}
              </Link>
              <Link href="/faq" className="text-xs text-muted-foreground hover:text-primary transition-colors" data-testid="link-footer-faq">
                {t("public.navFaq")}
              </Link>
              <Link href="/security" className="text-xs text-muted-foreground hover:text-primary transition-colors" data-testid="link-footer-security">
                {t("public.navSecurity")}
              </Link>
            </nav>
          </div>
        </div>
      </footer>
    </div>
  );
}
