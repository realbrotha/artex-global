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
  Crosshair,
  FolderOpen,
  History,
  House,
  LayoutDashboard,
  type LucideIcon,
  MessageSquare,
  MessageSquareWarning,
  Network,
  Plug,
  Radar,
  Radio,
  ScanEye,
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

// 하위 메뉴 항목: 이름(nav.item.<id>, 화면 표시 이름은 메시지 파일에만 둔다) · 아이콘 · 주소.
export interface NavLink {
  id: string;
  url: string;
  icon?: LucideIcon;
  badge?: NavBadge;
}

// 하위 메뉴의 묶음. 제목은 nav.section.<id>. id 가 영역 id 와 같으면 영역 이름을 쓴다.
export interface NavSection {
  id: string;
  items: NavLink[];
}

// 아이콘 줄의 영역. 모든 영역은 하위 메뉴를 가진다.
export interface NavArea {
  id: string;
  icon: LucideIcon;
  sections: NavSection[];
}

// neocloud 방식 2단 메뉴 (CLAUDE.md 1.4).
// 아이콘 줄은 큰 영역만 둔다. 실제 화면 메뉴는 영역의 하위 메뉴 묶음 안에 있다.
// 모든 영역에 하위 메뉴가 있어 메뉴 폭(48 + 220px)이 화면마다 바뀌지 않는다.
export const navAreas: NavArea[] = [
  {
    // 매일 여는 두 화면. 홈에도 하위 메뉴를 둬서 메뉴 폭이 화면마다 바뀌지 않게 한다.
    id: "home",
    icon: House,
    sections: [
      {
        id: "home",
        items: [
          { id: "dashboard", url: "/dashboard", icon: LayoutDashboard },
          { id: "chat", url: "/chat", icon: MessageSquare },
        ],
      },
    ],
  },
  {
    // 내부 관점(Wazuh): 무엇이 있나 · 무슨 일이 났나 · 설정이 안전한가 · 외부 위협 동향 헌팅.
    id: "monitor",

    icon: ScanEye,
    sections: [
      {
        id: "monitor",
        items: [
          { id: "infra", url: "/defensive/assets", icon: Network },
          { id: "detections", url: "/defensive/detections", icon: Siren },
          { id: "posture", url: "/defensive/posture", icon: ShieldCheck },
          { id: "defensive-hunting", url: "/defensive/hunting", icon: Crosshair },
        ],
      },
    ],
  },
  {
    // 외부(블랙박스) 관점의 침투 테스트: 작업 → 공격 표면 → 취약점 → 트래픽.
    id: "pentest",

    icon: Target,
    sections: [
      {
        id: "pentest",
        items: [
          { id: "tasks", url: "/function/tasks", icon: Target },
          { id: "attack-surface", url: "/function/assets", icon: Radar },
          { id: "findings", url: "/function/findings", icon: Bug },
          { id: "traffic", url: "/function/traffic", icon: Activity },
        ],
      },
    ],
  },
  {
    id: "activity",

    icon: ScrollText,
    sections: [
      {
        id: "activity",
        items: [
          { id: "siem-history", url: "/defensive/history", icon: History },
          { id: "siem-quality", url: "/defensive/quality", icon: MessageSquareWarning },
          { id: "commands", url: "/function/commands", icon: Terminal },
          { id: "llm-records", url: "/function/llm-records", icon: Radio },
          { id: "workspace", url: "/function/workspace", icon: FolderOpen },
          { id: "logs", url: "/system/logs", icon: ScrollText },
        ],
      },
    ],
  },
  {
    // 항목이 8개를 넘어 묶음 제목으로 나눈다. 승인 대기 건수 배지는 이 영역과 승인 기록에 붙는다.
    id: "config",

    icon: Settings2,
    sections: [
      {
        id: "collect",
        items: [
          { id: "connections", url: "/system/connections", icon: Plug },
          { id: "schedule", url: "/system/schedule", icon: CalendarClock },
        ],
      },
      {
        id: "ai",
        items: [
          { id: "llm", url: "/system/llm", icon: Brain },
          { id: "agents", url: "/system/agents", icon: Bot },
          { id: "skills", url: "/system/skills", icon: Sparkles },
          { id: "tools", url: "/system/tools", icon: Wrench },
          { id: "mcp", url: "/system/mcp", icon: Cable },
        ],
      },
      {
        id: "control",
        items: [
          { id: "intercept", url: "/system/intercept", icon: ShieldAlert },
          { id: "asset-intercept", url: "/system/intercept/assets", icon: Ban },
          { id: "approvals", url: "/system/intercept/approvals", icon: ClipboardList },
        ],
      },
      {
        id: "system",
        items: [
          { id: "notify", url: "/system/notify", icon: BellRing },
          { id: "settings", url: "/system/settings", icon: Settings2 },
        ],
      },
    ],
  },
];

// 영역의 모든 하위 메뉴 항목.
export const areaLinks = (area: NavArea): NavLink[] => area.sections.flatMap((section) => section.items);

// 영역을 눌렀을 때 가는 주소: 하위 메뉴의 첫 항목.
export const areaHref = (area: NavArea): string => areaLinks(area)[0]?.url ?? "/";
