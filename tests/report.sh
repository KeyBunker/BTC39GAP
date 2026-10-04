if [ "$#" -lt 3 ]; then
    printf 'Usage: report.sh <build|test|heading|summary> <verbose> <label> [command ...]\n' >&2
    exit 2
fi

mode=$1
verbose=$2
label=$3
shift 3

cyan=
green=
red=
reset=
if [ -t 1 ] && [ "${TERM:-dumb}" != dumb ] && [ -z "${NO_COLOR:-}" ]; then
    cyan=$(printf '\033[1;36m')
    green=$(printf '\033[1;32m')
    red=$(printf '\033[1;31m')
    reset=$(printf '\033[0m')
fi

case "$mode" in
    heading)
        printf '\n%s%s%s\n\n' "$cyan" "$label" "$reset"
        exit 0
        ;;
    summary)
        printf '\n%s%s%s\n\n' "$green" "$label" "$reset"
        exit 0
        ;;
    build|test)
        ;;
    *)
        printf 'Unknown report mode: %s\n' "$mode" >&2
        exit 2
        ;;
esac

if [ "$#" -eq 0 ]; then
    printf 'No command supplied for %s.\n' "$label" >&2
    exit 2
fi

log_dir=$(
    umask 077
    mktemp -d 'tests/.btc39gap-output.XXXXXX'
) || exit 1
trap 'rm -f "$log_dir/output"; rmdir "$log_dir"' 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$verbose" = 1 ]; then
    printf '\n  $ %s\n' "$*"
fi
printf '  %-38s ' "$label"

if "$@" >"$log_dir/output" 2>&1; then
    if [ "$mode" = build ]; then
        printf '%s[BUILT]%s\n' "$green" "$reset"
    else
        printf '%s[PASS]%s\n' "$green" "$reset"
    fi
    if [ "$mode" = build ] || [ "$verbose" = 1 ]; then
        if [ -s "$log_dir/output" ]; then
            cat "$log_dir/output" || exit 1
        fi
    fi
else
    status=$?
    printf '%s[FAIL]%s (exit %s)\n\n' "$red" "$reset" "$status"
    cat "$log_dir/output"
    printf '\n' >&2
    exit "$status"
fi

exit 0
