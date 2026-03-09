import { useLocation } from "wouter";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { XCircle } from "lucide-react";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

export default function BillingError() {
  useDocumentTitle("Billing Error");
  const [, navigate] = useLocation();

  return (
    <div className="flex items-center justify-center min-h-[80vh] p-6">
      <Card className="max-w-md w-full" data-testid="card-billing-error">
        <CardContent className="pt-6 text-center">
          <XCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-2xl font-bold mb-2" data-testid="text-error-title">Payment Canceled</h2>
          <p className="text-muted-foreground mb-6">Your checkout was canceled. No charges were made.</p>
          <div className="space-y-2">
            <Button onClick={() => navigate("/choose-plan")} className="w-full" data-testid="button-try-again">
              Try Again
            </Button>
            <Button onClick={() => navigate("/")} variant="outline" className="w-full" data-testid="button-back-dashboard">
              Back to Dashboard
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
