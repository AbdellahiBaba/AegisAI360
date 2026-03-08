import { useState, useEffect, useCallback } from "react";
import { useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandSeparator,
} from "@/components/ui/command";
import { Badge } from "@/components/ui/badge";
import {
  ShieldAlert, Bug, Network, FileSearch, LayoutDashboard,
  Search, ArrowRight,
} from "lucide-react";

function useDebounce(value: string, delay: number) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [, navigate] = useLocation();
  const debouncedQuery = useDebounce(query, 250);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  const { data, isFetching } = useQuery<{
    events: any[];
    incidents: any[];
    devices: any[];
    pages: { title: string; url: string }[];
    cves: any[];
  }>({
    queryKey: ["/api/search", debouncedQuery],
    queryFn: async () => {
      if (!debouncedQuery || debouncedQuery.length < 2) {
        return { events: [], incidents: [], devices: [], pages: [], cves: [] };
      }
      const res = await fetch(`/api/search?q=${encodeURIComponent(debouncedQuery)}`, { credentials: "include" });
      if (!res.ok) throw new Error("Search failed");
      return res.json();
    },
    enabled: open && debouncedQuery.length >= 2,
    staleTime: 30000,
  });

  const go = useCallback(
    (url: string) => {
      setOpen(false);
      setQuery("");
      navigate(url);
    },
    [navigate]
  );

  const hasResults =
    data &&
    (data.pages?.length > 0 ||
      data.events?.length > 0 ||
      data.incidents?.length > 0 ||
      data.devices?.length > 0 ||
      data.cves?.length > 0);

  return (
    <CommandDialog open={open} onOpenChange={(v) => { setOpen(v); if (!v) setQuery(""); }}>
      <CommandInput
        placeholder="Search events, incidents, devices, CVEs, or pages..."
        value={query}
        onValueChange={setQuery}
        data-testid="input-command-search"
      />
      <CommandList>
        {debouncedQuery.length >= 2 && !isFetching && !hasResults && (
          <CommandEmpty data-testid="text-no-results">No results found.</CommandEmpty>
        )}

        {data?.pages && data.pages.length > 0 && (
          <CommandGroup heading="Pages">
            {data.pages.map((page) => (
              <CommandItem
                key={page.url}
                value={`page-${page.title}`}
                onSelect={() => go(page.url)}
                data-testid={`search-result-page-${page.url.replace(/\//g, "-")}`}
              >
                <LayoutDashboard className="w-4 h-4 text-muted-foreground" />
                <span>{page.title}</span>
                <ArrowRight className="ml-auto w-3 h-3 text-muted-foreground" />
              </CommandItem>
            ))}
          </CommandGroup>
        )}

        {data?.events && data.events.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Security Events">
              {data.events.map((evt: any) => (
                <CommandItem
                  key={`event-${evt.id}`}
                  value={`event-${evt.id}-${evt.description}`}
                  onSelect={() => go("/alerts")}
                  data-testid={`search-result-event-${evt.id}`}
                >
                  <ShieldAlert className="w-4 h-4 text-muted-foreground" />
                  <div className="flex flex-col min-w-0 flex-1">
                    <span className="text-sm truncate">{evt.description}</span>
                    <span className="text-xs text-muted-foreground">{evt.sourceIp} · {evt.eventType}</span>
                  </div>
                  <Badge variant="secondary" className="text-[10px] ml-auto flex-shrink-0">
                    {evt.severity}
                  </Badge>
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}

        {data?.incidents && data.incidents.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Incidents">
              {data.incidents.map((inc: any) => (
                <CommandItem
                  key={`incident-${inc.id}`}
                  value={`incident-${inc.id}-${inc.title}`}
                  onSelect={() => go("/incidents")}
                  data-testid={`search-result-incident-${inc.id}`}
                >
                  <Bug className="w-4 h-4 text-muted-foreground" />
                  <div className="flex flex-col min-w-0 flex-1">
                    <span className="text-sm truncate">{inc.title}</span>
                    <span className="text-xs text-muted-foreground">{inc.status} · {inc.severity}</span>
                  </div>
                  <Badge variant="secondary" className="text-[10px] ml-auto flex-shrink-0">
                    {inc.severity}
                  </Badge>
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}

        {data?.devices && data.devices.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Network Devices">
              {data.devices.map((dev: any) => (
                <CommandItem
                  key={`device-${dev.id}`}
                  value={`device-${dev.id}-${dev.hostname}-${dev.ipAddress}`}
                  onSelect={() => go("/network-monitor")}
                  data-testid={`search-result-device-${dev.id}`}
                >
                  <Network className="w-4 h-4 text-muted-foreground" />
                  <div className="flex flex-col min-w-0 flex-1">
                    <span className="text-sm truncate">{dev.hostname || dev.macAddress}</span>
                    <span className="text-xs text-muted-foreground">{dev.ipAddress}</span>
                  </div>
                  <Badge variant="secondary" className="text-[10px] ml-auto flex-shrink-0">
                    {dev.status}
                  </Badge>
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}

        {data?.cves && data.cves.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="CVEs">
              {data.cves.map((cve: any, i: number) => (
                <CommandItem
                  key={`cve-${cve.id || i}`}
                  value={`cve-${cve.id}`}
                  onSelect={() => go("/cve-database")}
                  data-testid={`search-result-cve-${cve.id || i}`}
                >
                  <FileSearch className="w-4 h-4 text-muted-foreground" />
                  <div className="flex flex-col min-w-0 flex-1">
                    <span className="text-sm truncate">{cve.id}</span>
                    <span className="text-xs text-muted-foreground truncate">{cve.description?.slice(0, 80)}</span>
                  </div>
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}

        {debouncedQuery.length < 2 && (
          <CommandGroup heading="Quick Actions">
            <CommandItem value="go-dashboard" onSelect={() => go("/")} data-testid="search-quick-dashboard">
              <LayoutDashboard className="w-4 h-4 text-muted-foreground" />
              <span>Go to Dashboard</span>
            </CommandItem>
            <CommandItem value="go-alerts" onSelect={() => go("/alerts")} data-testid="search-quick-alerts">
              <ShieldAlert className="w-4 h-4 text-muted-foreground" />
              <span>Go to Security Events</span>
            </CommandItem>
            <CommandItem value="go-incidents" onSelect={() => go("/incidents")} data-testid="search-quick-incidents">
              <Bug className="w-4 h-4 text-muted-foreground" />
              <span>Go to Incidents</span>
            </CommandItem>
            <CommandItem value="go-network" onSelect={() => go("/network-monitor")} data-testid="search-quick-network">
              <Network className="w-4 h-4 text-muted-foreground" />
              <span>Go to Network Monitor</span>
            </CommandItem>
          </CommandGroup>
        )}
      </CommandList>
    </CommandDialog>
  );
}

export function SearchTrigger({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-2 px-2 py-1 text-xs text-muted-foreground border rounded-md hover-elevate"
      data-testid="button-search-trigger"
    >
      <Search className="w-3.5 h-3.5" />
      <span className="hidden sm:inline">Search...</span>
      <kbd className="hidden sm:inline-flex items-center gap-0.5 rounded border px-1 py-0.5 text-[10px] font-mono text-muted-foreground">
        <span className="text-[10px]">&#8984;</span>K
      </kbd>
    </button>
  );
}
