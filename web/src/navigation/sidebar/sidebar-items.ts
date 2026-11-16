import {
  Activity,
  Ban,
  BellRing,
  Bot,
  Brain,
  Bug,
  Cable,
  ClipboardList,
  FolderOpen,
  FolderSync,
  LayoutDashboard,
  type LucideIcon,
  MessageSquare,
  Network,
  Plug,
  Radar,
  Radio,
  ScrollText,
  Settings2,
  ShieldAlert,
  Sparkles,
  Target,
  Terminal,
  Wrench,
} from "lucide-react";

export type NavBadge = "new" | "soon";

export interface NavSubItem {
  id: string;
  title: string;
  url: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

interface NavItemBase {
  id: string;
  title: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

export interface NavMainLinkItem extends NavItemBase {
  url: string;
  subItems?: never;
}

export interface NavMainParentItem extends NavItemBase {
  subItems: NavSubItem[];
}

export type NavMainItem = NavMainLinkItem | NavMainParentItem;

export interface NavGroup {
  id: number;
  /** nav.group.<key> 메시지 키. 라벨은 렌더 시점에 번역한다. */
  key: string;
  label?: string;
  items: NavMainItem[];
}

// 메뉴는 작업 흐름 순서로 묶는다: 개요 → 진단 → 방어 → 실행 기록 → AI 구성 → 통제 → 시스템.
// 그룹 안은 평면 링크만 둔다(접힌 사이드바에서도 한 번의 클릭으로 도달).
export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    key: "overview",
    label: "概览",
    items: [
      { id: "dashboard", title: "仪表盘", url: "/dashboard", icon: LayoutDashboard },
      { id: "chat", title: "对话", url: "/chat", icon: MessageSquare },
    ],
  },
  {
    id: 2,
    key: "offense",
    label: "渗透",
    items: [
      { id: "tasks", title: "任务", url: "/function/tasks", icon: Target },
      { id: "findings", title: "发现", url: "/function/findings", icon: Bug },
      { id: "assets", title: "资产", url: "/function/assets", icon: Network },
      { id: "sync", title: "资产同步", url: "/function/sync", icon: FolderSync },
      { id: "traffic", title: "流量", url: "/function/traffic", icon: Activity },
    ],
  },
  {
    id: 3,
    key: "defense",
    label: "防御",
    items: [
      { id: "protected-assets", title: "保护资产", url: "/defensive/assets", icon: Network },
      { id: "defensive-hunting", title: "自主狩猎", url: "/defensive/hunting", icon: Radar },
      { id: "security-sources", title: "日志连接", url: "/defensive/sources", icon: Plug },
    ],
  },
  {
    id: 4,
    key: "activity",
    label: "执行记录",
    items: [
      { id: "commands", title: "工具执行", url: "/function/commands", icon: Terminal },
      { id: "llm-records", title: "LLM 录制", url: "/function/llm-records", icon: Radio },
      { id: "workspace", title: "工作空间", url: "/function/workspace", icon: FolderOpen },
      { id: "logs", title: "日志", url: "/system/logs", icon: ScrollText },
    ],
  },
  {
    id: 5,
    key: "ai",
    label: "AI 配置",
    items: [
      { id: "llm", title: "LLM", url: "/system/llm", icon: Brain },
      { id: "agents", title: "Agent", url: "/system/agents", icon: Bot },
      { id: "skills", title: "Skill", url: "/system/skills", icon: Sparkles },
      { id: "tools", title: "工具", url: "/system/tools", icon: Wrench },
      { id: "mcp", title: "MCP", url: "/system/mcp", icon: Cable },
    ],
  },
  {
    id: 6,
    key: "guardrails",
    label: "管控",
    items: [
      { id: "intercept", title: "拦截规则", url: "/system/intercept", icon: ShieldAlert },
      { id: "asset-intercept", title: "资产拦截", url: "/system/intercept/assets", icon: Ban },
      { id: "approvals", title: "审批记录", url: "/system/intercept/approvals", icon: ClipboardList },
    ],
  },
  {
    id: 7,
    key: "system",
    label: "系统",
    items: [
      { id: "notify", title: "通知推送", url: "/system/notify", icon: BellRing },
      { id: "settings", title: "系统配置", url: "/system/settings", icon: Settings2 },
    ],
  },
];
