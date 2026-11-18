"use client";

import * as React from "react";

import {
  DownloadIcon,
  FileIcon,
  FolderIcon,
  FolderPlusIcon,
  HardDriveIcon,
  RefreshCwIcon,
  SaveIcon,
  Trash2Icon,
  UploadIcon,
} from "lucide-react";
import { useTranslations } from "next-intl";
import { toast } from "sonner";

import { DrawerFooter, ListEmpty, PageHeader, TableSkeletonRows, useConfirm } from "@/components/page";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { getDateLocale } from "@/i18n/datetime";
import { api } from "@/lib/api";
import type { WorkspaceEntry, WorkspaceFile } from "@/lib/types";
import { cn } from "@/lib/utils";

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GB`;
}
function fmtTime(ms: number): string {
  return new Date(ms).toLocaleString(getDateLocale(), {
    year: "2-digit",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

type EditState = {
  file: WorkspaceFile;
  content: string;
  dirty: boolean;
  saving: boolean;
};

export default function WorkspacePage() {
  const t = useTranslations("workspace");
  const confirm = useConfirm();
  const [path, setPath] = React.useState("");
  const [entries, setEntries] = React.useState<WorkspaceEntry[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [edit, setEdit] = React.useState<EditState | null>(null);
  const [mkdirOpen, setMkdirOpen] = React.useState(false);
  const [mkdirName, setMkdirName] = React.useState("");
  const uploadRef = React.useRef<HTMLInputElement>(null);

  const load = React.useCallback(
    (p: string) => {
      setLoading(true);
      api
        .workspaceList(p)
        .then((r) => {
          setEntries(r.entries);
          setPath(r.path);
        })
        .catch((e) => toast.error(t("readDirFailed", { msg: (e as Error).message })))
        .finally(() => setLoading(false));
    },
    [t],
  );

  React.useEffect(() => {
    load("");
  }, [load]);

  const crumbs = React.useMemo(() => {
    const parts = path ? path.split("/") : [];
    const acc: { name: string; path: string }[] = [{ name: t("crumbRoot"), path: "" }];
    let cur = "";
    for (const part of parts) {
      cur = cur ? `${cur}/${part}` : part;
      acc.push({ name: part, path: cur });
    }
    return acc;
  }, [path, t]);

  const openFile = (e: WorkspaceEntry) => {
    api
      .workspaceRead(e.path)
      .then((f) => setEdit({ file: f, content: f.content ?? "", dirty: false, saving: false }))
      .catch((err) => toast.error(t("openFileFailed", { msg: (err as Error).message })));
  };

  const saveFile = () => {
    if (!edit) return;
    setEdit({ ...edit, saving: true });
    api
      .workspaceWrite(edit.file.path, edit.content)
      .then(() => {
        toast.success(t("saved"));
        setEdit((cur) => (cur ? { ...cur, dirty: false, saving: false } : cur));
        load(path);
      })
      .catch((err) => {
        toast.error(t("saveFailed", { msg: (err as Error).message }));
        setEdit((cur) => (cur ? { ...cur, saving: false } : cur));
      });
  };

  const del = async (e: WorkspaceEntry) => {
    const ok = await confirm({
      title: t("confirmDelete", { kind: e.dir ? "dir" : "file", name: e.name }),
      confirmLabel: t("delete"),
      destructive: true,
    });
    if (!ok) return;
    api
      .workspaceDelete(e.path)
      .then(() => {
        toast.success(t("deleted"));
        load(path);
      })
      .catch((err) => toast.error(t("deleteFailed", { msg: (err as Error).message })));
  };

  const doUpload = (files: FileList | null) => {
    if (!files || files.length === 0) return;
    api
      .workspaceUpload(path, Array.from(files))
      .then((r) => {
        toast.success(t("uploaded", { n: r.uploaded }));
        load(path);
      })
      .catch((err) => toast.error(t("uploadFailed", { msg: (err as Error).message })))
      .finally(() => {
        if (uploadRef.current) uploadRef.current.value = "";
      });
  };

  const doMkdir = () => {
    const name = mkdirName.trim();
    if (!name) return;
    const target = path ? `${path}/${name}` : name;
    api
      .workspaceMkdir(target)
      .then(() => {
        toast.success(t("folderCreated"));
        setMkdirOpen(false);
        setMkdirName("");
        load(path);
      })
      .catch((err) => toast.error(t("createFailed", { msg: (err as Error).message })));
  };

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        actions={
          <>
            <Button variant="outline" onClick={() => setMkdirOpen(true)}>
              <FolderPlusIcon /> {t("newFolder")}
            </Button>
            <Button onClick={() => uploadRef.current?.click()}>
              <UploadIcon /> {t("upload")}
            </Button>
            <input ref={uploadRef} type="file" multiple className="hidden" onChange={(e) => doUpload(e.target.files)} />
          </>
        }
      />
      {/* 도구 줄: 경로(브레드크럼) + 새로고침 */}
      <div className="flex flex-wrap items-center gap-2">
        {/* 폴더 경로. 루트는 아이콘으로만 두어 제목처럼 보이지 않게 한다. */}
        <div className="flex min-w-0 items-center gap-1 text-sm">
          <button
            type="button"
            onClick={() => load("")}
            aria-label={t("crumbRoot")}
            title={t("crumbRoot")}
            className={cn(
              "rounded p-1 hover:bg-accent [&_svg]:size-4",
              crumbs.length === 1 ? "text-foreground" : "text-muted-foreground",
            )}
          >
            <HardDriveIcon />
          </button>
          {crumbs.slice(1).map((c, i) => (
            <React.Fragment key={c.path}>
              <span className="text-muted-foreground">/</span>
              <button
                type="button"
                onClick={() => load(c.path)}
                className={cn(
                  "max-w-[160px] truncate rounded px-1.5 py-0.5 hover:bg-accent",
                  i === crumbs.length - 2 ? "text-foreground font-medium" : "text-muted-foreground",
                )}
              >
                {c.name}
              </button>
            </React.Fragment>
          ))}
        </div>
        <Button
          variant="ghost"
          size="icon-sm"
          className="ml-auto"
          onClick={() => load(path)}
          aria-label={t("refresh")}
          title={t("refresh")}
        >
          <RefreshCwIcon className={cn(loading && "animate-spin")} />
        </Button>
      </div>

      {!loading && entries.length === 0 ? (
        <ListEmpty title={t("empty")} icon={<FolderIcon />} />
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("colName")}</TableHead>
                  <TableHead className="w-28 text-right">{t("colSize")}</TableHead>
                  <TableHead className="w-40">{t("colMtime")}</TableHead>
                  <TableHead className="w-24 text-right">{t("colActions")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading && entries.length === 0 && <TableSkeletonRows columns={4} />}
                {entries.map((e) => (
                  <TableRow key={e.path}>
                    <TableCell>
                      <button
                        type="button"
                        onClick={() => (e.dir ? load(e.path) : openFile(e))}
                        className="flex items-center gap-2 text-left hover:underline"
                      >
                        {e.dir ? (
                          <FolderIcon className="size-4 shrink-0 text-info" />
                        ) : (
                          <FileIcon className="text-muted-foreground size-4 shrink-0" />
                        )}
                        <span className="truncate font-mono text-sm">{e.name}</span>
                      </button>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-right font-mono text-xs">
                      {e.dir ? "—" : fmtSize(e.size)}
                    </TableCell>
                    <TableCell className="text-muted-foreground text-xs">{fmtTime(e.mtime)}</TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        {!e.dir && (
                          <Button
                            variant="ghost"
                            size="icon-xs"
                            aria-label={t("download")}
                            title={t("download")}
                            onClick={() =>
                              api
                                .workspaceDownload(e.path)
                                .catch((err) => toast.error(t("downloadFailed", { msg: (err as Error).message })))
                            }
                          >
                            <DownloadIcon className="size-3.5" />
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="icon-xs"
                          className="text-danger"
                          aria-label={t("delete")}
                          title={t("delete")}
                          onClick={() => del(e)}
                        >
                          <Trash2Icon className="size-3.5" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* 파일 보기 / 편집 */}
      <Sheet open={edit !== null} onOpenChange={(o) => !o && setEdit(null)}>
        <SheetContent side="right" size="md" className="gap-0">
          {edit && (
            <>
              <SheetHeader className="border-b">
                <SheetTitle className="flex items-center gap-2 truncate font-mono text-sm">
                  <FileIcon className="size-4 shrink-0" />
                  <span className="truncate" title={edit.file.path}>
                    {edit.file.path}
                  </span>
                </SheetTitle>
                <div className="flex items-center gap-2 text-muted-foreground text-xs">
                  <span>{fmtSize(edit.file.size)}</span>
                  {!edit.file.binary && !edit.file.too_large && <span>· {edit.dirty ? t("dirty") : t("synced")}</span>}
                  {!edit.file.binary && !edit.file.too_large && (
                    <Button
                      variant="outline"
                      size="xs"
                      className="ml-auto"
                      onClick={() => api.workspaceDownload(edit.file.path)}
                    >
                      <DownloadIcon /> {t("download")}
                    </Button>
                  )}
                </div>
              </SheetHeader>

              {edit.file.binary || edit.file.too_large ? (
                <div className="flex flex-1 flex-col items-center justify-center gap-3 p-8 text-center">
                  <p className="text-muted-foreground text-sm">{edit.file.too_large ? t("tooLarge") : t("binary")}</p>
                  <Button variant="outline" onClick={() => api.workspaceDownload(edit.file.path)}>
                    <DownloadIcon /> {t("downloadFile")}
                  </Button>
                </div>
              ) : (
                <>
                  <div className="min-h-0 flex-1 px-4 py-3">
                    <Textarea
                      value={edit.content}
                      onChange={(ev) => setEdit({ ...edit, content: ev.target.value, dirty: true })}
                      spellCheck={false}
                      className="h-full resize-none font-mono text-xs leading-relaxed"
                    />
                  </div>
                  <DrawerFooter
                    onCancel={() => setEdit(null)}
                    onConfirm={saveFile}
                    confirmDisabled={!edit.dirty}
                    pending={edit.saving}
                    confirmLabel={
                      <>
                        <SaveIcon /> {edit.saving ? t("saving") : t("save")}
                      </>
                    }
                  />
                </>
              )}
            </>
          )}
        </SheetContent>
      </Sheet>

      {/* 새 폴더 */}
      <Sheet open={mkdirOpen} onOpenChange={setMkdirOpen}>
        <SheetContent side="right" size="sm">
          <SheetHeader>
            <SheetTitle>{t("newFolder")}</SheetTitle>
          </SheetHeader>
          <div className="flex min-h-0 flex-1 flex-col gap-1.5 overflow-y-auto px-4">
            <Label htmlFor="ws-mkdir">{t("folderNamePlaceholder")}</Label>
            <Input
              id="ws-mkdir"
              autoFocus
              value={mkdirName}
              onChange={(e) => setMkdirName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && doMkdir()}
              placeholder={t("folderNamePlaceholder")}
            />
          </div>
          <DrawerFooter
            onCancel={() => setMkdirOpen(false)}
            onConfirm={doMkdir}
            confirmDisabled={!mkdirName.trim()}
            confirmLabel={t("create")}
          />
        </SheetContent>
      </Sheet>
    </div>
  );
}
