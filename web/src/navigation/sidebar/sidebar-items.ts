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

// 사이드바는 제목 없는 한 묶음, 여섯 줄이다. 매일 여는 화면(대시보드·자산·대화)만
// 바로 보이고, 나머지는 분석·활동 기록·설정 세 개의 접이식 메뉴 안에 둔다.
export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    key: "main",
    items: [
      { id: "dashboard", title: "仪表盘", url: "/dashboard", icon: LayoutDashboard },
      // 자산: Wazuh 장비(인프라 맵·사건 후보)와 진단이 찾아낸 자산을 한 화면의 탭으로 본다.
      { id: "assets", title: "资产", url: "/defensive/assets", icon: Network },
      { id: "chat", title: "对话", url: "/chat", icon: MessageSquare },
      {
        id: "analysis",
        title: "分析",
        icon: Target,
        subItems: [
          { id: "tasks", title: "任务", url: "/function/tasks", icon: Target },
          { id: "findings", title: "发现", url: "/function/findings", icon: Bug },
          { id: "traffic", title: "流量", url: "/function/traffic", icon: Activity },
          { id: "defensive-hunting", title: "自主狩猎", url: "/defensive/hunting", icon: Radar },
        ],
      },
      {
        id: "activity",
        title: "执行记录",
        icon: ScrollText,
        subItems: [
          { id: "commands", title: "工具执行", url: "/function/commands", icon: Terminal },
          { id: "llm-records", title: "LLM 录制", url: "/function/llm-records", icon: Radio },
          { id: "workspace", title: "工作空间", url: "/function/workspace", icon: FolderOpen },
          { id: "logs", title: "日志", url: "/system/logs", icon: ScrollText },
        ],
      },
      {
        // 승인 대기 건수 배지는 이 항목에 붙는다(nav-main).
        id: "config",
        title: "设置",
        icon: Settings2,
        subItems: [
          { id: "connections", title: "连接", url: "/system/connections", icon: Plug },
          { id: "llm", title: "LLM", url: "/system/llm", icon: Brain },
          { id: "agents", title: "Agent", url: "/system/agents", icon: Bot },
          { id: "skills", title: "Skill", url: "/system/skills", icon: Sparkles },
          { id: "tools", title: "工具", url: "/system/tools", icon: Wrench },
          { id: "mcp", title: "MCP", url: "/system/mcp", icon: Cable },
          { id: "intercept", title: "拦截规则", url: "/system/intercept", icon: ShieldAlert },
          { id: "asset-intercept", title: "资产拦截", url: "/system/intercept/assets", icon: Ban },
          { id: "approvals", title: "审批记录", url: "/system/intercept/approvals", icon: ClipboardList },
          { id: "notify", title: "通知推送", url: "/system/notify", icon: BellRing },
          { id: "settings", title: "系统配置", url: "/system/settings", icon: Settings2 },
        ],
      },
    ],
  },
];
