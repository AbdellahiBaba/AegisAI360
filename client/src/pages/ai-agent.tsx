import { useState, useRef, useEffect, useCallback } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import {
  Zap, Send, Loader2, Trash2, Plus, Copy, Download, Check,
  Shield, Code, Bug, Microscope, AlertTriangle, Building,
  ChevronRight, MessageSquare, Sparkles,
} from "lucide-react";

interface CodeBlock {
  language: string;
  code: string;
  filename?: string;
}

interface Message {
  role: "user" | "assistant";
  content: string;
  codeBlocks?: CodeBlock[];
}

interface Conversation {
  id: number;
  title: string;
  mode: string;
  createdAt: string;
}

interface Capability {
  id: string;
  name: string;
  description: string;
  icon: string;
}

interface QuickPrompt {
  id: string;
  label: string;
  prompt: string;
}

const ICON_MAP: Record<string, React.ElementType> = {
  shield: Shield, code: Code, bug: Bug, microscope: Microscope,
  alert: AlertTriangle, building: Building,
};

function CodeBlockRenderer({ block, index }: { block: CodeBlock; index: number }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(block.code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = async () => {
    try {
      const res = await fetch("/api/aegis-agent/package-download", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: block.code, filename: block.filename || `code.${block.language}` }),
      });
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = block.filename || `code.${block.language}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {}
  };

  return (
    <div className="my-3 rounded-lg border border-border/60 overflow-hidden bg-[hsl(var(--card))]" data-testid={`code-block-${index}`}>
      <div className="flex items-center justify-between px-3 py-1.5 bg-muted/50 border-b border-border/40">
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-[10px] font-mono">{block.language}</Badge>
          {block.filename && <span className="text-[11px] text-muted-foreground font-mono">{block.filename}</span>}
        </div>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon" className="h-6 w-6" onClick={handleCopy} data-testid={`button-copy-code-${index}`}>
            {copied ? <Check className="w-3 h-3 text-green-500" /> : <Copy className="w-3 h-3" />}
          </Button>
          <Button variant="ghost" size="icon" className="h-6 w-6" onClick={handleDownload} data-testid={`button-download-code-${index}`}>
            <Download className="w-3 h-3" />
          </Button>
        </div>
      </div>
      <pre className="p-3 overflow-x-auto text-xs leading-relaxed font-mono text-foreground/90">
        <code>{block.code}</code>
      </pre>
    </div>
  );
}

function renderMessageContent(content: string, codeBlocks?: CodeBlock[]) {
  if (!content) return null;

  const parts: { type: "text" | "code"; content: string; block?: CodeBlock; index?: number }[] = [];
  const regex = /```(\w+)?\n([\s\S]*?)```/g;
  let lastIndex = 0;
  let match;
  let codeIdx = 0;

  while ((match = regex.exec(content)) !== null) {
    if (match.index > lastIndex) {
      parts.push({ type: "text", content: content.substring(lastIndex, match.index) });
    }
    const block = codeBlocks?.[codeIdx] || { language: match[1] || "text", code: match[2].trim() };
    parts.push({ type: "code", content: "", block, index: codeIdx });
    codeIdx++;
    lastIndex = match.index + match[0].length;
  }
  if (lastIndex < content.length) {
    parts.push({ type: "text", content: content.substring(lastIndex) });
  }

  return (
    <>
      {parts.map((part, i) =>
        part.type === "code" && part.block ? (
          <CodeBlockRenderer key={i} block={part.block} index={part.index || 0} />
        ) : (
          <span key={i} className="whitespace-pre-wrap">{part.content}</span>
        )
      )}
    </>
  );
}

export default function AiAgent() {
  useDocumentTitle("AegisAI360 Agent");
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [activeConversation, setActiveConversation] = useState<number | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [isStreaming, setIsStreaming] = useState(false);
  const [capabilities, setCapabilities] = useState<{ capabilities: Capability[]; quickPrompts: QuickPrompt[] } | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/api/aegis-agent/capabilities")
      .then((r) => r.json())
      .then((data) => setCapabilities(data))
      .catch(() => {});
    fetch("/api/aegis-agent/conversations")
      .then((r) => r.json())
      .then((data) => setConversations(data))
      .catch(() => {});
  }, []);

  useEffect(() => {
    if (activeConversation) {
      fetch(`/api/aegis-agent/conversations/${activeConversation}/messages`)
        .then((r) => r.json())
        .then((data) => {
          setMessages(data.map((m: any) => ({
            role: m.role,
            content: m.content,
            codeBlocks: m.codeBlocks || undefined,
          })));
        })
        .catch(() => {});
    }
  }, [activeConversation]);

  useEffect(() => {
    scrollRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const deleteConversation = async (id: number) => {
    await fetch(`/api/aegis-agent/conversations/${id}`, { method: "DELETE" });
    setConversations((prev) => prev.filter((c) => c.id !== id));
    if (activeConversation === id) {
      setActiveConversation(null);
      setMessages([]);
    }
  };

  const sendMessage = useCallback(async (overrideInput?: string) => {
    const text = overrideInput || input;
    if (!text.trim() || isStreaming) return;
    setInput("");

    const userMessage = text.trim();
    setMessages((prev) => [...prev, { role: "user", content: userMessage }]);
    setIsStreaming(true);

    try {
      const response = await fetch("/api/aegis-agent/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: userMessage,
          conversationId: activeConversation || undefined,
        }),
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({ error: "AI agent unavailable" }));
        throw new Error(errData.error || `Server error: ${response.status}`);
      }
      if (!response.body) throw new Error("No response body");

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let assistantContent = "";
      let buffer = "";
      let finalCodeBlocks: CodeBlock[] = [];
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
            if (parsed.type === "chunk" && parsed.text) {
              assistantContent += parsed.text;
              setMessages((prev) => {
                const updated = [...prev];
                updated[updated.length - 1] = { role: "assistant", content: assistantContent };
                return updated;
              });
            } else if (parsed.type === "done") {
              if (parsed.conversationId && !activeConversation) {
                setActiveConversation(parsed.conversationId);
                setConversations((prev) => {
                  if (prev.find((c) => c.id === parsed.conversationId)) return prev;
                  return [{ id: parsed.conversationId, title: userMessage.substring(0, 80), mode: "chat", createdAt: new Date().toISOString() }, ...prev];
                });
              }
              if (parsed.codeBlocks?.length) {
                finalCodeBlocks = parsed.codeBlocks;
                setMessages((prev) => {
                  const updated = [...prev];
                  updated[updated.length - 1] = { ...updated[updated.length - 1], codeBlocks: parsed.codeBlocks };
                  return updated;
                });
              }
            }
          } catch {}
        }
      }
    } catch (error: any) {
      const errorText = error?.message || "An error occurred. Please try again.";
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
  }, [input, isStreaming, activeConversation]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const handleQuickPrompt = (prompt: string) => {
    setInput(prompt + " ");
  };

  const startNewChat = () => {
    setActiveConversation(null);
    setMessages([]);
    setInput("");
  };

  return (
    <div className="flex h-[calc(100vh-48px)]">
      <div className="w-56 border-e flex flex-col flex-shrink-0 bg-card/30">
        <div className="p-3 border-b">
          <Button size="sm" className="w-full" onClick={startNewChat} data-testid="button-new-agent-chat">
            <Plus className="w-4 h-4 me-1" />
            New Session
          </Button>
        </div>
        <ScrollArea className="flex-1">
          <div className="p-2 space-y-1">
            {conversations.map((conv) => (
              <div
                key={conv.id}
                className={`flex items-center justify-between gap-1 px-2 py-1.5 rounded-md cursor-pointer text-xs group ${
                  activeConversation === conv.id ? "bg-primary/10 text-primary font-medium" : "hover:bg-muted/50"
                }`}
                onClick={() => setActiveConversation(conv.id)}
                data-testid={`agent-conversation-${conv.id}`}
              >
                <div className="flex items-center gap-1.5 truncate">
                  <MessageSquare className="w-3 h-3 flex-shrink-0 opacity-50" />
                  <span className="truncate">{conv.title}</span>
                </div>
                <Button
                  size="icon"
                  variant="ghost"
                  className="h-5 w-5 opacity-0 group-hover:opacity-100 flex-shrink-0"
                  onClick={(e) => { e.stopPropagation(); deleteConversation(conv.id); }}
                  data-testid={`button-delete-agent-conv-${conv.id}`}
                >
                  <Trash2 className="w-3 h-3" />
                </Button>
              </div>
            ))}
            {conversations.length === 0 && (
              <p className="text-[11px] text-muted-foreground text-center py-4">No conversations yet</p>
            )}
          </div>
        </ScrollArea>
      </div>

      <div className="flex-1 flex flex-col min-w-0">
        <div className="flex-1 overflow-auto">
          {messages.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-center p-8 max-w-3xl mx-auto">
              <div className="p-4 rounded-full bg-gradient-to-br from-amber-500/20 to-primary/10 mb-4">
                <Zap className="w-10 h-10 text-amber-500" />
              </div>
              <h2 className="text-xl font-bold mb-1" data-testid="text-agent-title">AegisAI360</h2>
              <p className="text-sm text-muted-foreground mb-6">
                Elite cybersecurity AI agent — threat analysis, secure code generation, incident response, and more.
              </p>

              {capabilities && (
                <>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3 w-full mb-6">
                    {capabilities.capabilities.map((cap) => {
                      const Icon = ICON_MAP[cap.icon] || Shield;
                      return (
                        <Card key={cap.id} className="bg-card/50 hover:bg-card/80 transition-colors cursor-default" data-testid={`capability-${cap.id}`}>
                          <CardContent className="p-3">
                            <div className="flex items-center gap-2 mb-1">
                              <Icon className="w-4 h-4 text-amber-500" />
                              <span className="text-xs font-semibold">{cap.name}</span>
                            </div>
                            <p className="text-[10px] text-muted-foreground leading-relaxed">{cap.description}</p>
                          </CardContent>
                        </Card>
                      );
                    })}
                  </div>

                  <div className="w-full">
                    <p className="text-[11px] text-muted-foreground mb-2 flex items-center gap-1 justify-center">
                      <Sparkles className="w-3 h-3" /> Quick Actions
                    </p>
                    <div className="flex flex-wrap gap-2 justify-center">
                      {capabilities.quickPrompts.map((qp) => (
                        <Badge
                          key={qp.id}
                          variant="secondary"
                          className="cursor-pointer text-[11px] py-1.5 hover:bg-primary/10 hover:text-primary transition-colors"
                          onClick={() => handleQuickPrompt(qp.prompt)}
                          data-testid={`quick-prompt-${qp.id}`}
                        >
                          <ChevronRight className="w-3 h-3 me-1" />
                          {qp.label}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </div>
          ) : (
            <div className="p-4 space-y-4 max-w-4xl mx-auto">
              {messages.map((msg, idx) => (
                <div
                  key={idx}
                  className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
                  data-testid={`agent-message-${idx}`}
                >
                  {msg.role === "assistant" && (
                    <div className="p-1.5 rounded-md bg-gradient-to-br from-amber-500/20 to-primary/10 h-fit flex-shrink-0 mt-0.5">
                      <Zap className="w-4 h-4 text-amber-500" />
                    </div>
                  )}
                  <div
                    className={`max-w-[80%] rounded-lg px-4 py-2.5 text-sm ${
                      msg.role === "user"
                        ? "bg-primary text-primary-foreground"
                        : "bg-card border border-border/40"
                    }`}
                  >
                    {msg.role === "assistant" ? (
                      <>
                        {renderMessageContent(msg.content, msg.codeBlocks)}
                        {msg.content === "" && isStreaming && (
                          <div className="flex items-center gap-2 text-muted-foreground">
                            <Loader2 className="w-4 h-4 animate-spin text-amber-500" />
                            <span className="text-xs">Analyzing...</span>
                          </div>
                        )}
                      </>
                    ) : (
                      <span className="whitespace-pre-wrap">{msg.content}</span>
                    )}
                  </div>
                </div>
              ))}
              <div ref={scrollRef} />
            </div>
          )}
        </div>

        <div className="p-3 border-t bg-card/30">
          <div className="flex gap-2 max-w-4xl mx-auto">
            <Textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask AegisAI360 about threats, generate secure code, analyze vulnerabilities..."
              className="resize-none min-h-[44px] max-h-[120px]"
              rows={1}
              data-testid="input-agent-message"
            />
            <Button
              size="icon"
              onClick={() => sendMessage()}
              disabled={!input.trim() || isStreaming}
              className="bg-amber-600 hover:bg-amber-700 text-white"
              data-testid="button-send-agent-message"
            >
              {isStreaming ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
