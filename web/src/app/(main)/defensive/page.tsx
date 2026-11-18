import { redirect } from "next/navigation";

// 방어 메뉴 첫 화면은 위협 헌팅.
export default function DefensivePage() {
  redirect("/defensive/hunting/");
}
