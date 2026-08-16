import { getTranslations } from "next-intl/server";
import { fetchAgents, fetchOverview } from "@/lib/api";

export const dynamic = "force-dynamic";
import { PageShell } from "@/components/layout/PageShell";
import { AgentCard } from "@/components/agents/AgentCard";
import { fmtNumber } from "@/lib/format";

export default async function HomePage() {
  const t = await getTranslations("home");
  const [agentsResult, overviewResult] = await Promise.all([
    fetchAgents(),
    fetchOverview(),
  ]);

  const agents = agentsResult.ok ? agentsResult.data : [];
  const overview = overviewResult.ok
    ? overviewResult.data
    : { total_agents: 0, active_agents: 0, calls_today: 0, protected_today: 0 };

  return (
    <PageShell title={t("title")}>
      {/* Single status line — no charts, no widgets */}
      <p className="text-sm text-[var(--text-muted)] mb-8">
        {fmtNumber(overview.total_agents)} agents
        {" · "}
        {fmtNumber(overview.calls_today)} calls today
        {" · "}
        {fmtNumber(overview.protected_today)} protected
      </p>

      {agents.length === 0 ? (
        <div className="py-16 text-center">
          <p className="text-sm text-[var(--text-muted)] mb-3">{t("empty")}</p>
          <a
            href="https://github.com/tejoker/SauronID"
            className="text-sm text-[var(--accent-text)] hover:text-[var(--accent-hover)] transition-colors duration-150"
          >
            {t("emptyLink")} →
          </a>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {agents.map((agent) => (
            <AgentCard key={agent.id} agent={agent} />
          ))}
        </div>
      )}
    </PageShell>
  );
}
