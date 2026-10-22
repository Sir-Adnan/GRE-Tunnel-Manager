import type { ReactNode } from "react";
import type { TemplateProps } from "../../../types";
export default function Page({
  model,
}: TemplateProps<string, { content: ReactNode }>) {
  return <>{model.content}</>;
}
