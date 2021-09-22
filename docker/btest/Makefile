DIAG=diag.log
BTEST=../../auxil/btest/btest

all: cleanup btest-verbose

# Showing all tests.
btest-verbose:
	@$(BTEST) -j -f $(DIAG)

cleanup:
	@rm -f $(DIAG)
