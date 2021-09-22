# @TEST-REQUIRES: docker inspect ${TEST_TAG:-zeek:latest}
# @TEST-EXEC: bash %INPUT >output
# @TEST-EXEC: btest-diff output

docker run --rm ${TEST_TAG} zeek -v | sed "s/[0-9.]\+.\+$/xxx/"
