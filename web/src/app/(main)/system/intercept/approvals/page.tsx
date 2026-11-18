import { ApprovalRecords } from "@/components/approval-records";
import { PageHeader } from "@/components/page";

export default function ApprovalsPage() {
  return (
    <div className="flex min-w-0 flex-col gap-4">
      <PageHeader />
      <ApprovalRecords />
    </div>
  );
}
