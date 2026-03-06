import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Languages } from "lucide-react";

export function LanguageSwitcher() {
  const { i18n, t } = useTranslation();

  const switchTo = (lng: string) => {
    i18n.changeLanguage(lng);
  };

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="ghost" size="icon" className="relative" data-testid="button-language-switcher">
          <Languages className="w-4 h-4" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[140px] p-1" align="end">
        <button
          className={`w-full text-start px-3 py-1.5 text-xs rounded-sm hover:bg-accent ${i18n.language === "en" ? "bg-accent font-semibold" : ""}`}
          onClick={() => switchTo("en")}
          data-testid="button-lang-en"
        >
          {t("language.en")}
        </button>
        <button
          className={`w-full text-start px-3 py-1.5 text-xs rounded-sm hover:bg-accent ${i18n.language === "ar" ? "bg-accent font-semibold" : ""}`}
          onClick={() => switchTo("ar")}
          data-testid="button-lang-ar"
        >
          {t("language.ar")}
        </button>
      </PopoverContent>
    </Popover>
  );
}
