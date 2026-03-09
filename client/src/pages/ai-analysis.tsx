import { useState, useRef, useEffect } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { useTranslation } from "react-i18next";
import { Brain, Send, Loader2, Trash2, Plus } from "lucide-react";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

interface Message {
  role: "user" | "assistant";
  content: string;
}

interface Conversation {
  id: number;
  title: string;
}

export default function AiAnalysis() {
  useDocumentTitle("AI Analysis");
  const { t } = useTranslation();
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeConversation, setActiveConversation] = useState<number | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/api/ai-conversations")
      .then((r) => r.json())
      .then((data) => setConversations(data))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (activeConversation) {
      fetch(`/api/ai-conversations/${activeConversation}`)
        .then((r) => r.json())
        .then((data) => {
          if (data.messages) {
            setMessages(data.messages.map((m: any) => ({ role: m.role, content: m.content })));
          }
        })
        .catch(() => {});
    }
  }, [activeConversation]);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const createConversation = async () => {
    const res = await fetch("/api/ai-conversations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: t("aiAnalysis.newAnalysis") }),
    });
    const conv = await res.json();
    setConversations((prev) => [conv, ...prev]);
    setActiveConversation(conv.id);
    setMessages([]);
  };

  const deleteConversation = async (id: number) => {
    await fetch(`/api/ai-conversations/${id}`, { method: "DELETE" });
    setConversations((prev) => prev.filter((c) => c.id !== id));
    if (activeConversation === id) {
      setActiveConversation(null);
      setMessages([]);
    }
  };

  const sendMessage = async () => {
    if (!input.trim() || isStreaming) return;
    let convId = activeConversation;
    if (!convId) {
      const res = await fetch("/api/ai-conversations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ title: input.slice(0, 50) }),
      });
      const conv = await res.json();
      setConversations((prev) => [conv, ...prev]);
      convId = conv.id;
      setActiveConversation(conv.id);
    }

    const userMessage = input.trim();
    setInput("");
    setMessages((prev) => [...prev, { role: "user", content: userMessage }]);
    setIsStreaming(true);

    try {
      const response = await fetch(`/api/ai-conversations/${convId}/messages`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: userMessage }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({ error: "AI service unavailable" }));
        throw new Error(errData.error || `Server error: ${response.status}`);
      }

      if (!response.body) throw new Error("No response body");

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let assistantContent = "";
      let buffer = "";
      setMessages((prev) => [...prev, { role: "assistant", content: "" }]);

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed.startsWith("data: ")) continue;
          try {
            const parsed = JSON.parse(trimmed.slice(6));
            if (parsed.content) {
              assistantContent += parsed.content;
              setMessages((prev) => {
                const updated = [...prev];
                updated[updated.length - 1] = { role: "assistant", content: assistantContent };
                return updated;
              });
            }
          } catch {}
        }
      }
    } catch (error: any) {
      const errorText = error?.message || t("aiAnalysis.errorMessage");
      setMessages((prev) => {
        const last = prev[prev.length - 1];
        if (last?.role === "assistant" && last.content === "") {
          return [...prev.slice(0, -1), { role: "assistant", content: errorText }];
        }
        return [...prev, { role: "assistant", content: errorText }];
      });
    } finally {
      setIsStreaming(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  return (
    <div className="flex h-[calc(100vh-48px)]">
      <div className="w-56 border-e flex flex-col flex-shrink-0">
        <div className="p-3 border-b">
          <Button size="sm" className="w-full" onClick={createConversation} data-testid="button-new-analysis">
            <Plus className="w-4 h-4 me-1" />
            {t("aiAnalysis.newAnalysis")}
          </Button>
        </div>
        <ScrollArea className="flex-1">
          <div className="p-2 space-y-1">
            {conversations.map((conv) => (
              <div
                key={conv.id}
                className={`flex items-center justify-between gap-1 px-2 py-1.5 rounded-md cursor-pointer text-xs group ${
                  activeConversation === conv.id ? "bg-accent" : ""
                }`}
                onClick={() => setActiveConversation(conv.id)}
                data-testid={`conversation-${conv.id}`}
              >
                <span className="truncate">{conv.title}</span>
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-5 w-5 opacity-0 group-hover:opacity-100 flex-shrink-0"
                  onClick={(e) => {
                    e.stopPropagation();
                    deleteConversation(conv.id);
                  }}
                  data-testid={`button-delete-conversation-${conv.id}`}
                >
                  <Trash2 className="w-3 h-3" />
                </Button>
              </div>
            ))}
          </div>
        </ScrollArea>
      </div>

      <div className="flex-1 flex flex-col min-w-0">
        <div className="flex-1 overflow-auto">
          {messages.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-center p-8">
              <div className="p-4 rounded-full bg-primary/10 mb-4">
                <Brain className="w-8 h-8 text-primary" />
              </div>
              <h2 className="text-lg font-semibold mb-2">{t("aiAnalysis.title")}</h2>
              <p className="text-sm text-muted-foreground max-w-md mb-6">
                {t("aiAnalysis.subtitle")}
              </p>
              <div className="flex flex-wrap gap-2 justify-center max-w-lg">
                {[
                  "Analyze suspicious SSH login attempts from 185.220.101.x",
                  "What are common indicators of ransomware activity?",
                  "Review MITRE ATT&CK techniques for lateral movement",
                  "Help me investigate a potential data exfiltration",
                ].map((prompt) => (
                  <Badge
                    key={prompt}
                    variant="secondary"
                    className="cursor-pointer text-[11px] py-1.5"
                    onClick={() => {
                      setInput(prompt);
                    }}
                    data-testid={`suggestion-${prompt.slice(0, 20)}`}
                  >
                    {prompt}
                  </Badge>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-4 space-y-4">
              {messages.map((msg, idx) => (
                <div
                  key={idx}
                  className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
                  data-testid={`message-${idx}`}
                >
                  {msg.role === "assistant" && (
                    <div className="p-1.5 rounded-md bg-primary/10 h-fit flex-shrink-0 mt-0.5">
                      <Brain className="w-4 h-4 text-primary" />
                    </div>
                  )}
                  <div
                    className={`max-w-[75%] rounded-md px-3 py-2 text-sm whitespace-pre-wrap ${
                      msg.role === "user"
                        ? "bg-primary text-primary-foreground"
                        : "bg-card"
                    }`}
                  >
                    {msg.content}
                    {msg.role === "assistant" && msg.content === "" && isStreaming && (
                      <Loader2 className="w-4 h-4 animate-spin text-primary" />
                    )}
                  </div>
                </div>
              ))}
              <div ref={scrollRef} />
            </div>
          )}
        </div>

        <div className="p-3 border-t">
          <div className="flex gap-2">
            <Textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={t("aiAnalysis.inputPlaceholder")}
              className="resize-none min-h-[44px] max-h-[120px]"
              rows={1}
              data-testid="input-ai-message"
            />
            <Button
              size="icon"
              onClick={sendMessage}
              disabled={!input.trim() || isStreaming}
              data-testid="button-send-message"
            >
              {isStreaming ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
