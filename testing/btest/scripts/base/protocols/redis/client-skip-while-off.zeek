# @TEST-DOC: Test CLIENT REPLY OFF then ON again and a SKIP
# @TEST-REQUIRES: have-spicy
#
# @TEST-EXEC: zeek -b -r $TRACES/redis/client-skip-while-off.pcap %INPUT >output
# @TEST-EXEC: btest-diff redis.log

@load base/protocols/redis
