"use client";

import { PageHeader } from "@/components/page";

import { FeedbackView } from "./_components/feedback-view";

// Judging feedback on its own; the same view is a tab of Detection quality.
export default function FeedbackPage() {
  return <FeedbackView header={(refresh) => <PageHeader actions={refresh} />} />;
}
