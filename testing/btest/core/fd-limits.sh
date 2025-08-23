# Check the file descriptor limit behavior Zeek applies at startup.
#
# We need to be able to set soft & hard open-fd limits via ulimit.
# Store the current values while we're at it.
# @TEST-REQUIRES: ulimit -n -S >limit.soft
# @TEST-REQUIRES: ulimit -n -H >limit.hard
#
# @TEST-EXEC: unset ZEEK_NOFILE_MAX; LIM_SOFT=$(cat limit.soft) LIM_HARD=$(cat limit.hard) bash %INPUT
#
# This has tests that skip if intentional limit adjustments fail; in that case a
# "skip" file is present, we don't baseline the results, and the test just
# passes. It'd be nice to be able to signal to btest via exit code that a test
# is to be considered skipped.
# @TEST-EXEC: if [ ! -f skip ]; then TEST_DIFF_CANONIFIER=$SCRIPTS/diff-remove-abspath btest-diff output; fi

# @TEST-START-FILE limits.zeek
event zeek_init()
      {
      # Report resulting limits to stderr:
      system("ulimit -n -S");
      system("ulimit -n -H");
      }
# @TEST-END-FILE

# @TEST-START-FILE limits.sh
setcaps() {
    local soft=$1
    local hard=$2

    ulimit -S -n $soft || {
        echo "Skipping $TEST_NAME, could not set soft fd limit $soft."
        touch skip
        exit 0
    }
    ulimit -H -n $hard || {
        echo "Skipping $TEST_NAME, could not set hard fd limit $hard."
        touch skip
        exit 0
    }
}
# @TEST-END-FILE

# Apply low limits and no ZEEK_NOFILE_MAX variable.
# The limits should stay unchanged with no warning message.

. ./limits.sh
setcaps 100 150
zeek -b limits.zeek 2>output

# @TEST-START-NEXT
# Establish a low limit via ZEEK_NOFILE_MAX.
# Zeek should apply these values, without a warning message.

setcaps 100 100 # Check that one can set the values we want Zeek to cap to.
setcaps 200 200 # Defaults for Zeek to compare against.

export ZEEK_NOFILE_MAX=100
zeek -b limits.zeek 2>output

# @TEST-START-NEXT
# With high limits and no ZEEK_NOFILE_MAX Zeek should cap and produce a
# warning message.

. ./limits.sh
setcaps 1500000 2000000
zeek -b limits.zeek 2>output

# @TEST-START-NEXT
# With high limits and the capping mechanism disabled (via the an empy
# ZEEK_NOFILE_MAX) the values should remain intact.

. ./limits.sh
setcaps 1500000 2000000
export ZEEK_NOFILE_MAX=
zeek -b limits.zeek 2>output

# @TEST-START-NEXT
# With high limits and the capping mechanism disabled (by setting
# ZEEK_NOFILE_MAX to 0) the values should remain intact.

. ./limits.sh
setcaps 1500000 2000000
export ZEEK_NOFILE_MAX=0
zeek -b limits.zeek 2>output
