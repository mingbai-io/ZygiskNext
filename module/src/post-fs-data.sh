#!/system/bin/sh

MODDIR=${0%/*}
if [ "$ZYGISK_ENABLED" ]; then
  exit 0
fi

cd "$MODDIR"

# TODO: inject in daemon
cp "/system/etc/public.libraries.txt" "$MODDIR/system/etc/public.libraries.txt"
echo "libzygisk_loader.so" >> "$MODDIR/system/etc/public.libraries.txt"
log -p -i -t "zygisksu" "library injected";

if [ "$(which magisk)" ]; then
  for file in ../*; do
    if [ -d "$file" ] && [ -d "$file/zygisk" ] && ! [ -f "$file/disable" ]; then
      if [ -f "$file/post-fs-data.sh" ]; then
        cd "$file"
        log -p i -t "zygisksu" "Manually trigger post-fs-data.sh for $file"
        sh "$(realpath ./post-fs-data.sh)"
        cd "$MODDIR"
      fi
    fi
  done
fi
