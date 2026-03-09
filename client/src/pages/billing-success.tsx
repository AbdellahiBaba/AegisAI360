import { useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useLocation } from "wouter";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { CheckCircle, Loader2 } from "lucide-react";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

export default function BillingSuccess() {
  useDocumentTitle("Billing Success");
  const [, navigate] = useLocation();

  const sessionId = new URLSearchParams(window.location.search).get("session_id") || "";

  const confirmMutation = useMutation({
    mutationFn: async () => {
      const res = await apiRequest("POST", "/api/billing/confirm", { sessionId });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/user"] });
      queryClient.invalidateQueries({ queryKey: ["/api/billing/status"] });
    },
  });

  useEffect(() => {
    if (sessionId) {
      confirmMutation.mutate();
    }
  }, []);

  return (
    <div className="flex items-center justify-center min-h-[80vh] p-6">
      <Card className="max-w-md w-full" data-testid="card-billing-success">
        <CardContent className="pt-6 text-center">
          {confirmMutation.isPending ? (
            <Loader2 className="w-12 h-12 animate-spin text-primary mx-auto mb-4" />
          ) : (
            <CheckCircle className="w-16 h-16 text-green-500 mx-auto mb-4" />
          )}
          <h2 className="text-2xl font-bold mb-2" data-testid="text-success-title">Subscription Activated</h2>
          <p className="text-muted-foreground mb-6">Your plan is now active. You have full access to AegisAI360.</p>
          <Button onClick={() => navigate("/")} className="w-full" data-testid="button-go-dashboard">
            Go to Dashboard
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
