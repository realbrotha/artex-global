import {
  Activity,
  Ban,
  BellRing,
  Bot,
  Brain,
  Bug,
  Cable,
  CalendarClock,
  ClipboardList,
  FolderOpen,
  History,
  LayoutDashboard,
  type LucideIcon,
  MessageSquare,
  MessageSquareWarning,
  Network,
  Plug,
  Radar,
  Radio,
  ScrollText,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Siren,
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

// 사이드바는 제목 없는 한 묶음, 여덟 줄이다. 매일 여는 화면(대시보드·인프라·탐지·설정 점검·대화)만
// 바로 보이고, 나머지는 진단·활동 기록·설정 세 개의 접이식 메뉴 안에 둔다.
// 인프라·탐지·설정 점검은 내부 관점(Wazuh), 진단은 외부 관점(침투 테스트)이다.
// 자율 헌팅(/defensive/hunting)은 쓰지 않아 메뉴에서 뺐다. 화면과 주소는 남아 있다.
export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    key: "main",
    items: [
      { id: "dashboard", title: "仪表盘", url: "/dashboard", icon: LayoutDashboard },
      // 내부 관점 세 화면: 무엇이 있나(인프라) · 무슨 일이 났나(탐지) · 설정이 안전한가(설정 점검).
      { id: "infra", title: "基础设施", url: "/defensive/assets", icon: Network },
      { id: "detections", title: "检测", url: "/defensive/detections", icon: Siren },
      { id: "posture", title: "配置检查", url: "/defensive/posture", icon: ShieldCheck },
      { id: "chat", title: "对话", url: "/chat", icon: MessageSquare },
      {
        // 외부(블랙박스) 관점의 침투 테스트: 작업 → 공격 표면 → 취약점 → 트래픽.
        id: "pentest",
        title: "渗透",
        icon: Target,
        subItems: [
          { id: "tasks", title: "任务", url: "/function/tasks", icon: Target },
          { id: "attack-surface", title: "攻击面", url: "/function/assets", icon: Radar },
          { id: "findings", title: "发现", url: "/function/findings", icon: Bug },
          { id: "traffic", title: "流量", url: "/function/traffic", icon: Activity },
        ],
      },
      {
        id: "activity",
        title: "执行记录",
        icon: ScrollText,
        subItems: [
          { id: "siem-history", title: "分析记录", url: "/defensive/history", icon: History },
          { id: "siem-feedback", title: "判定反馈", url: "/defensive/feedback", icon: MessageSquareWarning },
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
          { id: "schedule", title: "分析计划", url: "/system/schedule", icon: CalendarClock },
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
