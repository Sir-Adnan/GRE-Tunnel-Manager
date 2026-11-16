import { useCallback, useState } from "react";
import { toast } from "sonner";
import { operate } from "@/lib/api";
import type { Job } from "@/lib/api";
import { errorMessage } from "@/lib/i18n";

/** A result to show, or a failure (error: true) that the dialog explains. */
export type OperationOutput = { title: string; text: string; error?: boolean };

/** Operations whose result text is worth showing after completion, with the title key to show it under. */
const resultTitles: Record<string, string> = {
  logs: "logs",
  "reverse-create": "completed",
  plan: "previewAll",
  doctor: "review",
};

/**
 * Runs one broker operation at a time through the job API, calls `refresh` (inventory) after success and
 * keeps the last result or error for the output dialog. Rejections are re-thrown so forms stay open.
 */
export function useOperations(t: (key: string) => string) {
  const [job, setJob] = useState<Job>();
  const [output, setOutput] = useState<OperationOutput>();
  const run = useCallback(
    async (request: unknown, refresh: () => Promise<void>): Promise<void> => {
      try {
        const completed = await operate(request, setJob);
        try {
          await refresh();
          toast.success(t("completed"));
        } catch {
          toast.warning(t("savedRefreshFailed"));
        }
        const title = resultTitles[(request as { action: string }).action];
        if (title)
          setOutput({
            title: t(title),
            text:
              typeof completed.result === "string"
                ? completed.result
                : JSON.stringify(completed.result, null, 2),
          });
      } catch (error) {
        setOutput({
          title: t("error"),
          text: errorMessage(error),
          error: true,
        });
        throw error;
      }
    },
    [t],
  );
  return {
    job,
    busy: job?.state === "running",
    output,
    closeOutput: () => setOutput(undefined),
    run,
  };
}
