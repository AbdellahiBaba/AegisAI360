import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { Shield, Download, Bell, ScanLine, CheckCircle2, ArrowRight, ArrowLeft } from "lucide-react";

const steps = [
  {
    icon: Shield,
    title: "Welcome to AegisAI360",
    description: "Your autonomous AI-powered cyber defense platform is ready. This quick tour will help you get started with the essential setup steps.",
    action: null,
    actionLabel: null,
    actionPath: null,
  },
  {
    icon: Download,
    title: "Connect Your First Agent",
    description: "Deploy the AegisAI360 endpoint agent on your devices to start monitoring for threats in real time. Download and install the agent to begin collecting telemetry.",
    action: "navigate",
    actionLabel: "Go to Agent Download",
    actionPath: "/download-agent",
  },
  {
    icon: Bell,
    title: "Configure Alert Rules",
    description: "Set up custom alert rules to get notified about the threats that matter most to your organization. Define conditions, severity thresholds, and notification channels.",
    action: "navigate",
    actionLabel: "Set Up Alert Rules",
    actionPath: "/alert-rules",
  },
  {
    icon: ScanLine,
    title: "Run Your First Scan",
    description: "Launch a vulnerability scan to discover potential weaknesses in your infrastructure. Identify open ports, outdated software, and misconfigurations before attackers do.",
    action: "navigate",
    actionLabel: "Open Scanner",
    actionPath: "/scanner",
  },
  {
    icon: CheckCircle2,
    title: "You're All Set!",
    description: "Your AegisAI360 platform is configured and ready to protect your infrastructure. You can always revisit these steps from the sidebar navigation.",
    action: null,
    actionLabel: null,
    actionPath: null,
  },
];

interface OnboardingWizardProps {
  open: boolean;
  onComplete: () => void;
}

export function OnboardingWizard({ open, onComplete }: OnboardingWizardProps) {
  const [currentStep, setCurrentStep] = useState(0);
  const [, navigate] = useLocation();

  const completeMutation = useMutation({
    mutationFn: async () => {
      await apiRequest("PATCH", "/api/user/onboarding");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/user"] });
      onComplete();
    },
  });

  const step = steps[currentStep];
  const StepIcon = step.icon;
  const isLastStep = currentStep === steps.length - 1;
  const isFirstStep = currentStep === 0;

  function handleNext() {
    if (isLastStep) {
      completeMutation.mutate();
    } else {
      setCurrentStep((s) => s + 1);
    }
  }

  function handleBack() {
    if (!isFirstStep) {
      setCurrentStep((s) => s - 1);
    }
  }

  function handleSkip() {
    completeMutation.mutate();
  }

  function handleActionClick() {
    if (step.actionPath) {
      completeMutation.mutate();
      navigate(step.actionPath);
    }
  }

  return (
    <Dialog open={open} onOpenChange={() => {}}>
      <DialogContent className="sm:max-w-md" onPointerDownOutside={(e) => e.preventDefault()} onEscapeKeyDown={(e) => e.preventDefault()}>
        <DialogHeader>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 rounded-md bg-primary/10">
              <StepIcon className="w-5 h-5 text-primary" />
            </div>
            <Badge variant="secondary" className="text-[10px] font-mono" data-testid="badge-onboarding-step">
              Step {currentStep + 1} of {steps.length}
            </Badge>
          </div>
          <DialogTitle data-testid="text-onboarding-title">{step.title}</DialogTitle>
          <DialogDescription data-testid="text-onboarding-description">{step.description}</DialogDescription>
        </DialogHeader>

        <div className="flex items-center justify-center gap-1.5 py-3">
          {steps.map((_, i) => (
            <div
              key={i}
              className={`h-1.5 rounded-full transition-all ${
                i === currentStep ? "w-6 bg-primary" : i < currentStep ? "w-3 bg-primary/50" : "w-3 bg-muted"
              }`}
              data-testid={`indicator-step-${i}`}
            />
          ))}
        </div>

        {step.action === "navigate" && step.actionLabel && (
          <Button
            variant="outline"
            className="w-full"
            onClick={handleActionClick}
            data-testid="button-onboarding-action"
          >
            {step.actionLabel}
            <ArrowRight className="w-4 h-4 ms-2" />
          </Button>
        )}

        <DialogFooter className="flex-row justify-between gap-2 sm:justify-between">
          <div className="flex gap-2">
            {!isFirstStep && (
              <Button variant="ghost" onClick={handleBack} data-testid="button-onboarding-back">
                <ArrowLeft className="w-4 h-4 me-1" />
                Back
              </Button>
            )}
          </div>
          <div className="flex gap-2">
            {!isLastStep && (
              <Button variant="ghost" onClick={handleSkip} disabled={completeMutation.isPending} data-testid="button-onboarding-skip">
                Skip Tour
              </Button>
            )}
            <Button onClick={handleNext} disabled={completeMutation.isPending} data-testid="button-onboarding-next">
              {completeMutation.isPending ? "Saving..." : isLastStep ? "Get Started" : "Next"}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
