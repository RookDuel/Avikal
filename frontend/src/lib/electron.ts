type DragFileWithPath = File & { path?: string }

export function getDroppedPaths(fileList: FileList): string[] {
  return Array.from(fileList).map((file) => {
    const dragFile = file as DragFileWithPath
    return dragFile.path || dragFile.name
  })
}
